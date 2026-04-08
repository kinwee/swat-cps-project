#!/usr/bin/env python3
"""
lstm_twin.py  —  SWaT Data-Driven Digital Twin (LSTM)
Predicts next sensor values across all 6 stages from current window.

Architecture:
    Input:  window of 30 timesteps × N features
    LSTM:   2 layers, hidden_dim=128
    Output: next timestep predictions for all analog sensors

Usage:
    python3 lstm_twin.py train  --data ../assets/19-Feb-2026_0930_1735.csv
    python3 lstm_twin.py predict --data ../assets/20-Feb-2026_0905_1710.csv --model lstm_twin.pt
    python3 lstm_twin.py attack  --data ../assets/19-Feb-2026_0930_1735.csv --model lstm_twin.pt
"""

import argparse, sys, time
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import matplotlib.pyplot as plt

WINDOW     = 30       # Lookback window (seconds)
HIDDEN_DIM = 128
N_LAYERS   = 2
BATCH_SIZE = 256
LR         = 1e-3

# Analog features to predict (exclude status/alarm columns)
ANALOG_FEATURES = [
    'LIT101.Pv', 'FIT101.Pv',
    'FIT201.Pv', 'AIT201.Pv', 'AIT202.Pv', 'AIT203.Pv',
    'AIT301.Pv', 'AIT302.Pv', 'AIT303.Pv', 'LIT301.Pv', 'FIT301.Pv', 'DPIT301.Pv',
    'LIT401.Pv', 'FIT401.Pv', 'AIT402.Pv',
    'FIT501.Pv', 'FIT502.Pv', 'FIT503.Pv', 'AIT501.Pv', 'AIT502.Pv', 'PIT501.Pv',
    'LIT601.Pv', 'LIT602.Pv', 'FIT602.Pv',
]


class LSTMTwin(nn.Module):
    def __init__(self, input_dim, hidden_dim=HIDDEN_DIM, n_layers=N_LAYERS, output_dim=None):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, n_layers, batch_first=True, dropout=0.2)
        self.fc   = nn.Linear(hidden_dim, output_dim or input_dim)

    def forward(self, x):
        out, _ = self.lstm(x)
        return self.fc(out[:, -1, :])   # predict next step from last hidden state


def load_and_prep(csv_path, features=None):
    df = pd.read_csv(csv_path, low_memory=False)
    avail = [f for f in (features or ANALOG_FEATURES) if f in df.columns]
    for c in avail:
        df[c] = pd.to_numeric(df[c], errors='coerce')
    data = df[avail].dropna().values.astype(np.float32)
    mu   = data.mean(0)
    sigma= data.std(0) + 1e-8
    return data, mu, sigma, avail


def make_windows(data, window):
    X, y = [], []
    for i in range(len(data) - window):
        X.append(data[i:i+window])
        y.append(data[i+window])
    return np.array(X), np.array(y)


def train(args):
    print(f"[*] Loading {args.data}...")
    data, mu, sigma, features = load_and_prep(args.data)
    norm = (data - mu) / sigma
    X, y = make_windows(norm, WINDOW)

    split = int(len(X) * 0.85)
    X_tr, y_tr = torch.tensor(X[:split]), torch.tensor(y[:split])
    X_val,y_val= torch.tensor(X[split:]), torch.tensor(y[split:])

    input_dim = X.shape[2]
    model = LSTMTwin(input_dim, HIDDEN_DIM, N_LAYERS, input_dim)
    opt   = torch.optim.Adam(model.parameters(), lr=LR)
    sched = torch.optim.lr_scheduler.ReduceLROnPlateau(opt, patience=5, factor=0.5)
    loss_fn = nn.MSELoss()

    print(f"[*] Training LSTM twin  features={len(features)}  window={WINDOW}  epochs={args.epochs}")
    print(f"    Train: {len(X_tr):,}  Val: {len(X_val):,}")

    best_val = float('inf')
    for ep in range(1, args.epochs + 1):
        model.train()
        idx = torch.randperm(len(X_tr))
        total_loss = 0
        for i in range(0, len(X_tr), BATCH_SIZE):
            batch_x = X_tr[idx[i:i+BATCH_SIZE]]
            batch_y = y_tr[idx[i:i+BATCH_SIZE]]
            opt.zero_grad()
            pred = model(batch_x)
            loss = loss_fn(pred, batch_y)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            total_loss += loss.item()

        model.eval()
        with torch.no_grad():
            val_loss = loss_fn(model(X_val), y_val).item()
        sched.step(val_loss)

        if val_loss < best_val:
            best_val = val_loss
            torch.save({'state': model.state_dict(), 'mu': mu, 'sigma': sigma,
                        'features': features, 'window': WINDOW,
                        'input_dim': input_dim}, args.model)

        if ep % 10 == 0:
            print(f"    Epoch {ep:4d}/{args.epochs}  train={total_loss/max(1,len(X_tr)//BATCH_SIZE):.5f}  val={val_loss:.5f}  best={best_val:.5f}")

    print(f"[+] Best val loss: {best_val:.5f}  Model saved: {args.model}")


def predict(args):
    print(f"[*] Loading model: {args.model}")
    ckpt     = torch.load(args.model, map_location='cpu')
    features = ckpt['features']
    mu, sigma= ckpt['mu'], ckpt['sigma']
    window   = ckpt['window']
    model    = LSTMTwin(ckpt['input_dim'])
    model.load_state_dict(ckpt['state'])
    model.eval()

    data, _, _, _ = load_and_prep(args.data, features)
    norm = (data - mu) / sigma
    X, y = make_windows(norm, window)
    X_t, y_t = torch.tensor(X), torch.tensor(y)

    with torch.no_grad():
        preds = model(X_t).numpy()

    # De-normalise
    real  = y * sigma + mu
    pred  = preds * sigma + mu
    residuals = real - pred
    rmse  = np.sqrt((residuals**2).mean(0))

    print(f"\n[*] LSTM Twin Prediction Performance ({len(features)} features):")
    print(f"{'Feature':30s}  {'RMSE':>10s}  {'MAE':>10s}")
    print("-" * 55)
    for i, f in enumerate(features):
        mae = np.mean(np.abs(residuals[:, i]))
        print(f"  {f:28s}  {rmse[i]:10.3f}  {mae:10.3f}")

    # Plot top 4 most interesting features
    fig, axes = plt.subplots(4, 1, figsize=(16, 12), facecolor='#0A0A14')
    fig.suptitle('SWaT LSTM Digital Twin — Predicted vs Real', color='white', fontsize=13, fontweight='bold')
    plot_feats = ['LIT101.Pv', 'FIT101.Pv', 'LIT301.Pv', 'LIT601.Pv']
    t = np.arange(len(real))
    for ax, feat in zip(axes, plot_feats):
        if feat not in features: continue
        fi = features.index(feat)
        ax.set_facecolor('#0D0D1A')
        ax.plot(t, real[:, fi],  color='#00D4FF', lw=1.0, label='Real', alpha=0.9)
        ax.plot(t, pred[:, fi],  color='#FF6B35', lw=1.0, label='LSTM Predicted', alpha=0.8, linestyle='--')
        ax.set_title(feat, color='#AAAACC', fontsize=10, pad=3)
        ax.set_ylabel('Value', color='white', fontsize=9)
        ax.tick_params(colors='white')
        ax.spines[:].set_color('#333355')
        ax.legend(fontsize=8, facecolor='#1A1A2E', labelcolor='white', loc='upper right')
    axes[-1].set_xlabel('Time (samples)', color='white')
    plt.tight_layout()
    out = args.output or 'lstm_twin_plot.png'
    plt.savefig(out, dpi=150, bbox_inches='tight', facecolor='#0A0A14')
    print(f"[+] Plot saved: {out}")
    plt.close()


def attack_sim(args):
    """Show what LSTM twin predicts when attack is injected vs real."""
    print(f"[*] Attack simulation using LSTM twin...")
    ckpt     = torch.load(args.model, map_location='cpu')
    features = ckpt['features']
    mu, sigma= ckpt['mu'], ckpt['sigma']
    window   = ckpt['window']
    model    = LSTMTwin(ckpt['input_dim'])
    model.load_state_dict(ckpt['state'])
    model.eval()

    data, _, _, _ = load_and_prep(args.data, features)
    start = args.attack_start
    dur   = args.attack_duration

    # Simulate attack: close MV101, keep P101 ON → tank drains
    data_attack = data.copy()
    lit_idx = features.index('LIT101.Pv') if 'LIT101.Pv' in features else None
    fit_idx = features.index('FIT101.Pv') if 'FIT101.Pv' in features else None

    # ODE-based attack trajectory (physics model from ode_twin.py)
    # dL/dt = -Q_out/A_tank when MV101=CLOSED, P101=ON
    # Q_out ≈ 1.8 L/s, A_tank ≈ 1.5 m² → drop rate ≈ 1.2 mm/s
    DROP_RATE = 1.8 / 1.5   # mm/s from ODE model
    if lit_idx is not None:
        lit_start = data[start, lit_idx]
        for i in range(start, min(start + dur, len(data_attack))):
            elapsed = i - start
            data_attack[i, lit_idx] = max(0, lit_start - DROP_RATE * elapsed)
            if fit_idx is not None:
                data_attack[i, fit_idx] = 0.0   # no flow when valve closed

    norm_clean  = (data - mu) / sigma
    norm_attack = (data_attack - mu) / sigma

    preds_clean  = []
    preds_attack = []
    for i in range(start, min(start + dur, len(norm_clean) - window)):
        xc = torch.tensor(norm_clean[i:i+window]).unsqueeze(0)
        xa = torch.tensor(norm_attack[i:i+window]).unsqueeze(0)
        with torch.no_grad():
            preds_clean.append(model(xc).numpy()[0])
            preds_attack.append(model(xa).numpy()[0])

    preds_clean  = np.array(preds_clean)  * sigma + mu
    preds_attack = np.array(preds_attack) * sigma + mu
    real_seg     = data[start+window:start+window+len(preds_clean)]

    if lit_idx is None or len(preds_clean) == 0:
        print("[!] Not enough data for attack simulation")
        return

    t = np.arange(len(preds_clean))
    fig, axes = plt.subplots(2, 1, figsize=(14, 8), facecolor='#0A0A14')
    fig.suptitle('LSTM Twin: Normal vs Attack-Injected Prediction', color='white', fontsize=13, fontweight='bold')
    plot_indices = [lit_idx, fit_idx if fit_idx is not None else 1]
    plot_titles  = ['LIT101 (Tank Level)', 'FIT101 (Flow)']
    for ax, fi, title in zip(axes, plot_indices, plot_titles):
        ax.set_facecolor('#0D0D1A')
        ax.plot(t, real_seg[:, fi],      color='#00D4FF', lw=1.2, label='Real')
        ax.plot(t, preds_clean[:, fi],   color='#00FF88', lw=1.2, linestyle='--', label='Twin (Normal)')
        ax.plot(t, preds_attack[:, fi],  color='#FF2244', lw=1.5, linestyle=':',  label='Twin (Attack injected)')
        ax.set_title(title, color='#AAAACC', fontsize=11)
        ax.tick_params(colors='white')
        ax.spines[:].set_color('#333355')
        ax.legend(fontsize=9, facecolor='#1A1A2E', labelcolor='white')
        ax.set_ylabel('Value', color='white')
    axes[-1].set_xlabel('Time (seconds from attack start)', color='white')
    plt.tight_layout()
    out = args.output or 'lstm_attack_plot.png'
    plt.savefig(out, dpi=150, bbox_inches='tight', facecolor='#0A0A14')
    print(f"[+] Attack simulation plot saved: {out}")
    plt.close()


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='mode', required=True)

    tr = sub.add_parser('train')
    tr.add_argument('--data',   required=True)
    tr.add_argument('--model',  default='lstm_twin.pt')
    tr.add_argument('--epochs', type=int, default=50)

    pr = sub.add_parser('predict')
    pr.add_argument('--data',   required=True)
    pr.add_argument('--model',  default='lstm_twin.pt')
    pr.add_argument('--output', default='lstm_twin_plot.png')

    at = sub.add_parser('attack')
    at.add_argument('--data',            required=True)
    at.add_argument('--model',           default='lstm_twin.pt')
    at.add_argument('--attack-start',    type=int, default=3000)
    at.add_argument('--attack-duration', type=int, default=600)
    at.add_argument('--output',          default='lstm_attack_plot.png')

    args = ap.parse_args()
    if   args.mode == 'train':   train(args)
    elif args.mode == 'predict': predict(args)
    elif args.mode == 'attack':  attack_sim(args)

if __name__ == '__main__':
    main()
