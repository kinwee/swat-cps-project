#!/usr/bin/env python3
"""
autoencoder_detector.py  —  Reconstruction-based ML Anomaly Detector
Target: Allen-Bradley ControlLogix PLC1 via pylogix

Inference uses pure numpy — no PyTorch required on the HMI.
Training still uses PyTorch (run on your Mac, produces ae_model.npz).

Usage:
  # Train (on Mac — requires PyTorch):
  python3 autoencoder_detector.py train --data assets/19-Feb-2026_0930_1735.csv --save ae_model.npz

  # Monitor (on HMI — numpy only):
  python3 autoencoder_detector.py monitor --plc-ip 192.168.1.10 --model ae_model.npz
"""

import argparse, time, sys
import numpy as np
import pandas as pd
from datetime import datetime
from pylogix import PLC

FEATURES  = ['LIT101.Pv']
PLC_TAGS  = ['HMI_LIT101.Pv']
WINDOW    = 10


# ── Numpy inference (no PyTorch needed) ───────────────────────────────────────

def relu(x):
    return np.maximum(0, x)

def ae_forward_np(x, weights):
    """Pure numpy autoencoder forward pass."""
    h = relu(x @ weights['enc_w0'].T + weights['enc_b0'])
    h = relu(h @ weights['enc_w1'].T + weights['enc_b1'])
    h =      h @ weights['enc_w2'].T + weights['enc_b2']
    h = relu(h @ weights['dec_w0'].T + weights['dec_b0'])
    h = relu(h @ weights['dec_w1'].T + weights['dec_b1'])
    h =      h @ weights['dec_w2'].T + weights['dec_b2']
    return h

def load_np_model(model_path):
    m = np.load(model_path, allow_pickle=True)
    weights = {
        'enc_w0': m['state_encoder.0.weight'], 'enc_b0': m['state_encoder.0.bias'],
        'enc_w1': m['state_encoder.2.weight'], 'enc_b1': m['state_encoder.2.bias'],
        'enc_w2': m['state_encoder.4.weight'], 'enc_b2': m['state_encoder.4.bias'],
        'dec_w0': m['state_decoder.0.weight'], 'dec_b0': m['state_decoder.0.bias'],
        'dec_w1': m['state_decoder.2.weight'], 'dec_b1': m['state_decoder.2.bias'],
        'dec_w2': m['state_decoder.4.weight'], 'dec_b2': m['state_decoder.4.bias'],
    }
    return weights, m['mu'], m['sigma'], float(m['threshold']), int(m['window'])


# ── Training (requires PyTorch — run on Mac) ──────────────────────────────────

def train(data_path, save_path, epochs, window):
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
                nn.Linear(16, latent_dim)
            )
            self.decoder = nn.Sequential(
                nn.Linear(latent_dim, 16), nn.ReLU(),
                nn.Linear(16, 32),         nn.ReLU(),
                nn.Linear(32, input_dim)
            )
        def forward(self, x):
            return self.decoder(self.encoder(x))

    print(f"[*] Loading {data_path}...")
    df = pd.read_csv(data_path, low_memory=False)
    feat_cols = [c for c in FEATURES if c in df.columns]
    if not feat_cols:
        print(f"[!] Features {FEATURES} not found. Columns: {list(df.columns[:15])}")
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
    opt = torch.optim.Adam(ae.parameters(), lr=1e-3)
    mse = nn.MSELoss()

    print(f"[*] Training  epochs={epochs}  input_dim={input_dim}  features={feat_cols}")
    for ep in range(1, epochs+1):
        ae.train(); opt.zero_grad()
        loss = mse(ae(X_t), X_t)
        loss.backward(); opt.step()
        if ep % 20 == 0:
            print(f"    Epoch {ep:4d}/{epochs}  loss={loss.item():.6f}")

    ae.eval()
    with torch.no_grad():
        errors = ((ae(X_t) - X_t)**2).mean(1).numpy()
    threshold = float(np.percentile(errors, 95))
    print(f"[+] Threshold (95th pct): {threshold:.6f}")

    np_data = {'threshold': np.array(threshold), 'mu': mu, 'sigma': sigma,
               'window': np.array(window), 'input_dim': np.array(input_dim)}
    for k, v in ae.state_dict().items():
        np_data[f'state_{k}'] = v.numpy()
    np.savez(save_path, **np_data)
    print(f"[+] Model saved: {save_path}")


# ── Live Monitor (numpy only — runs on HMI) ──────────────────────────────────

def monitor(plc_ip, model_path, flag_file, interval):
    print(f"[*] Loading model: {model_path}")
    weights, mu, sigma, threshold, window = load_np_model(model_path)
    print(f"[*] Monitoring PLC {plc_ip}  threshold={threshold:.6f}")
    history = []
    cycle   = 0

    while True:
        try:
            with PLC() as plc:
                plc.IPAddress = plc_ip
                while True:
                    results = plc.Read(PLC_TAGS)
                    if not isinstance(results, list): results = [results]
                    vals = np.array([r.Value if r.Value is not None else 0.0
                                     for r in results], dtype=np.float32)
                    norm_vals = (vals - mu) / sigma
                    history.append(norm_vals)
                    if len(history) > window: history = history[-window:]

                    ae_flag = 0; mse_val = None
                    if len(history) == window:
                        x = np.array(history).flatten().astype(np.float32).reshape(1, -1)
                        recon = ae_forward_np(x, weights)
                        mse_val = float(((recon - x)**2).mean())
                        ae_flag = 1 if mse_val > threshold else 0

                    with open(flag_file, 'w') as f: f.write(str(ae_flag))

                    cycle += 1
                    ts = datetime.now().strftime('%H:%M:%S')
                    if ae_flag:
                        print(f"[{ts}] cycle={cycle:5d}  *** AE ANOMALY ***  MSE={mse_val:.6f} > {threshold:.6f}")
                    elif cycle % 10 == 0:
                        mse_str = f"{mse_val:.6f}" if mse_val is not None else "warming up"
                        print(f"[{ts}] cycle={cycle:5d}  OK  MSE={mse_str}  LIT101={vals[0]:.1f}  FIT101={vals[1]:.3f}")
                    time.sleep(interval)
        except Exception as e:
            print(f"[!] Error: {e} — reconnecting in 3s...")
            with open(flag_file, 'w') as f: f.write('0')
            time.sleep(3)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='mode', required=True)
    tr = sub.add_parser('train')
    tr.add_argument('--data',   required=True)
    tr.add_argument('--save',   default='ae_model.npz')
    tr.add_argument('--epochs', type=int, default=500)
    tr.add_argument('--window', type=int, default=WINDOW)
    mo = sub.add_parser('monitor')
    mo.add_argument('--plc-ip',   default='192.168.1.10')
    mo.add_argument('--model',    default='ae_model.npz')
    mo.add_argument('--flag',     default='/tmp/ae_flag')
    mo.add_argument('--interval', type=float, default=1.0)
    args = ap.parse_args()
    if args.mode == 'train':
        train(args.data, args.save, args.epochs, args.window)
    else:
        monitor(args.plc_ip, args.model, args.flag, args.interval)

if __name__ == '__main__':
    main()
