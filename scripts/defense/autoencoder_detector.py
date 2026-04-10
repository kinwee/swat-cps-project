#!/usr/bin/env python3
"""
autoencoder_detector.py  —  Reconstruction-based ML Anomaly Detector
Target: Allen-Bradley ControlLogix PLC1 via pylogix

Usage:
  python3 autoencoder_detector.py train   --data assets/19-Feb-2026_0930_1735.csv --save ae_model.pt
  python3 autoencoder_detector.py monitor --plc-ip 192.168.1.10 --model ae_model.pt
"""

import argparse, time, sys
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from datetime import datetime
from pylogix import PLC

# ── Logging setup ─────────────────────────────────────────────────────────────
import os as _os
from datetime import datetime as _logdt
_LOG_DIR = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..', '..', 'logs')
_os.makedirs(_LOG_DIR, exist_ok=True)
LOG_FILE = _os.path.join(_LOG_DIR, f"ae_{_logdt.now().strftime('%Y%m%d_%H%M%S')}.log")
_logfile = open(LOG_FILE, 'w', buffering=1)
_orig_print = print
def print(*args, **kwargs):
    msg = ' '.join(str(a) for a in args)
    ts  = _logdt.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{ts}] {msg}"
    _orig_print(line, **kwargs)
    _logfile.write(line + '\n')


FEATURES  = ['LIT101.Pv', 'FIT101.Pv']   # CSV column names
PLC_TAGS  = ['HMI_LIT101.Pv', 'AI_FIT_101_FLOW']  # corresponding PLC tags
WINDOW    = 10


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


def train(data_path, save_path, epochs, window):
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
        ae.train()
        opt.zero_grad()
        loss = mse(ae(X_t), X_t)
        loss.backward(); opt.step()
        if ep % 20 == 0:
            print(f"    Epoch {ep:4d}/{epochs}  loss={loss.item():.6f}")

    ae.eval()
    with torch.no_grad():
        errors = ((ae(X_t) - X_t)**2).mean(1).numpy()
    threshold = float(np.percentile(errors, 95))
    print(f"[+] Threshold (95th pct): {threshold:.6f}")

    torch.save({'state': ae.state_dict(), 'input_dim': input_dim,
                'mu': mu, 'sigma': sigma, 'window': window,
                'feat_cols': feat_cols, 'threshold': threshold}, save_path)
    print(f"[+] Model saved: {save_path}")


def monitor(plc_ip, model_path, flag_file, interval):
    print(f"[*] Loading model: {model_path}")
    ckpt = torch.load(model_path, map_location='cpu', weights_only=False)
    ae = Autoencoder(ckpt['input_dim']); ae.load_state_dict(ckpt['state']); ae.eval()
    mu, sigma = ckpt['mu'], ckpt['sigma']
    window, threshold = ckpt['window'], ckpt['threshold']

    print(f"[*] Monitoring PLC {plc_ip}  threshold={threshold:.6f}")
    history = []
    cycle   = 0

    while True:
        try:
            with PLC() as plc:
                plc.IPAddress = plc_ip
                while True:
                    results = plc.Read(PLC_TAGS)
                    if not isinstance(results, list):
                        results = [results]
                    vals = np.array([r.Value if r.Value is not None else 0.0
                                     for r in results], dtype=np.float32)
                    norm_vals = (vals - mu) / sigma
                    history.append(norm_vals)
                    if len(history) > window:
                        history = history[-window:]

                    ae_flag = 0
                    mse_val = None
                    if len(history) == window:
                        x = torch.tensor(np.array(history).flatten(), dtype=torch.float32).unsqueeze(0)
                        with torch.no_grad():
                            mse_val = float(((ae(x) - x)**2).mean())
                        ae_flag = 1 if mse_val > threshold else 0

                    with open(flag_file, 'w') as f:
                        f.write(str(ae_flag))

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
            with open(flag_file, 'w') as f:
                f.write('0')
            time.sleep(3)


def main():
    _orig_print(f"[LOG] Writing to {LOG_FILE}")
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='mode', required=True)

    tr = sub.add_parser('train')
    tr.add_argument('--data',   required=True)
    tr.add_argument('--save',   default='ae_model.pt')
    tr.add_argument('--epochs', type=int, default=500)
    tr.add_argument('--window', type=int, default=WINDOW)

    mo = sub.add_parser('monitor')
    mo.add_argument('--plc-ip',   default='192.168.1.10')
    mo.add_argument('--model',    default='ae_model.pt')
    mo.add_argument('--flag',     default='/tmp/ae_flag')
    mo.add_argument('--interval', type=float, default=1.0)

    args = ap.parse_args()
    if args.mode == 'train':
        train(args.data, args.save, args.epochs, args.window)
    else:
        monitor(args.plc_ip, args.model, args.flag, args.interval)

if __name__ == '__main__':
    main()
