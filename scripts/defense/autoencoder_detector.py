"""
autoencoder_detector.py — SWaT Reconstruction Autoencoder Anomaly Detector (Layer 2)

Trains an LSTM/dense autoencoder on normal SWaT sensor data and flags anomalies
based on reconstruction MSE exceeding a learned threshold.

Usage:
    # Train:
    python3 autoencoder_detector.py train --data swat_normal.csv --epochs 50 --save ae_model.pt

    # Monitor live (inference):
    sudo python3 autoencoder_detector.py monitor --plc-ip 192.168.1.10 --model ae_model.pt

Output:
    - Console anomaly alerts
    - ae_scores.json — rolling MSE scores
    - /tmp/ae_flag — shared flag read by fusion.py (0=normal, 1=anomaly)

Architecture:
    Input: sliding window of W=30 cycles × N features (flattened)
    Encoder: Linear(W×N → 64) → ReLU → Linear(64 → 32) → ReLU → Linear(32 → 8)
    Decoder: Linear(8 → 32) → ReLU → Linear(32 → 64) → ReLU → Linear(64 → W×N)
    Threshold: 95th percentile of training reconstruction errors

Author: SWaT CPS Security Project Team, SUTD 51.508
"""

import argparse
import json
import os
import time
import logging
from collections import deque
from datetime import datetime

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

from pymodbus.client import ModbusTcpClient

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [AE] %(levelname)s %(message)s"
)
log = logging.getLogger("autoencoder")

# ── Config ────────────────────────────────────────────────────────────────────
WINDOW_SIZE   = 30      # cycles per input window
LATENT_DIM    = 8
HIDDEN_DIM    = 64
THRESHOLD_PCT = 95      # percentile for anomaly threshold
FEATURES      = ["FIT101", "LIT101", "FIT201"]   # extend with all sensors
N_FEATURES    = len(FEATURES)

FLAG_PATH  = "/tmp/ae_flag"
SCORE_LOG  = "ae_scores.json"

# Modbus register map (analog sensors, scaled ×100)
SENSOR_REGS = {
    "FIT101": 2,
    "LIT101": 1,
    "FIT201": 3,
}


# ── Model ─────────────────────────────────────────────────────────────────────
class Autoencoder(nn.Module):
    def __init__(self, input_dim, latent_dim=LATENT_DIM, hidden_dim=HIDDEN_DIM):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, latent_dim),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))


def mse(x, x_hat):
    return float(((x - x_hat) ** 2).mean())


# ── Training ──────────────────────────────────────────────────────────────────
def train(args):
    import pandas as pd
    from sklearn.preprocessing import MinMaxScaler

    log.info(f"Loading data from {args.data}")
    df = pd.read_csv(args.data)
    data = df[FEATURES].dropna().values.astype(np.float32)

    scaler = MinMaxScaler()
    data = scaler.fit_transform(data)

    # Build sliding windows
    windows = np.array([
        data[i:i + WINDOW_SIZE].flatten()
        for i in range(len(data) - WINDOW_SIZE)
    ], dtype=np.float32)

    X = torch.tensor(windows)
    loader = DataLoader(TensorDataset(X), batch_size=256, shuffle=True)

    input_dim = WINDOW_SIZE * N_FEATURES
    model = Autoencoder(input_dim)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.MSELoss()

    log.info(f"Training autoencoder for {args.epochs} epochs...")
    for epoch in range(args.epochs):
        total_loss = 0.0
        for (batch,) in loader:
            out = model(batch)
            loss = criterion(out, batch)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        if (epoch + 1) % 10 == 0:
            log.info(f"  Epoch {epoch+1}/{args.epochs}  loss={total_loss/len(loader):.6f}")

    # Compute threshold on training data
    model.eval()
    with torch.no_grad():
        recon = model(X)
        errors = ((X - recon) ** 2).mean(dim=1).numpy()
    threshold = float(np.percentile(errors, THRESHOLD_PCT))
    log.info(f"Anomaly threshold ({THRESHOLD_PCT}th pct): {threshold:.6f}")

    # Save
    import pickle
    checkpoint = {
        "model_state": model.state_dict(),
        "input_dim": input_dim,
        "threshold": threshold,
        "scaler": scaler,
        "features": FEATURES,
        "window_size": WINDOW_SIZE,
    }
    torch.save(checkpoint, args.save)
    log.info(f"Model saved to {args.save}")


# ── Live Monitoring ───────────────────────────────────────────────────────────
def monitor(args):
    log.info(f"Loading model from {args.model}")
    ckpt = torch.load(args.model, weights_only=False)
    model = Autoencoder(ckpt["input_dim"])
    model.load_state_dict(ckpt["model_state"])
    model.eval()
    threshold = ckpt["threshold"]
    scaler    = ckpt["scaler"]
    log.info(f"Anomaly threshold: {threshold:.6f}")

    client = ModbusTcpClient(args.plc_ip, port=args.plc_port)
    if not client.connect():
        log.error(f"Cannot connect to {args.plc_ip}:{args.plc_port}")
        return

    buffer = deque(maxlen=WINDOW_SIZE)
    score_log = []
    consecutive = 0

    log.info("Monitoring live sensor stream...")
    try:
        while True:
            row = []
            ok = True
            for feat in FEATURES:
                addr = SENSOR_REGS.get(feat)
                rr = client.read_holding_registers(addr, count=1, slave=1)
                if rr.isError():
                    ok = False
                    break
                row.append(rr.registers[0] / 100.0)

            if not ok:
                log.warning("Sensor read error — skipping cycle")
                time.sleep(args.interval)
                continue

            buffer.append(row)

            if len(buffer) < WINDOW_SIZE:
                time.sleep(args.interval)
                continue

            window = np.array(list(buffer), dtype=np.float32)
            window_scaled = scaler.transform(window).flatten()
            x = torch.tensor(window_scaled).unsqueeze(0)

            with torch.no_grad():
                x_hat = model(x)
            score = mse(x, x_hat)

            is_anomaly = score > threshold
            flag = 1 if is_anomaly else 0

            with open(FLAG_PATH, "w") as f:
                f.write(str(flag))

            entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "mse": round(score, 6),
                "threshold": round(threshold, 6),
                "anomaly": is_anomaly,
            }
            score_log.append(entry)

            if is_anomaly:
                consecutive += 1
                log.warning(f"ANOMALY DETECTED  MSE={score:.6f} > threshold={threshold:.6f}  (consecutive={consecutive})")
            else:
                consecutive = 0
                log.debug(f"Normal  MSE={score:.6f}")

            if len(score_log) % 60 == 0:
                with open(SCORE_LOG, "w") as f:
                    json.dump(score_log[-500:], f, indent=2)

            time.sleep(args.interval)

    except KeyboardInterrupt:
        log.info("Stopping autoencoder monitor.")
    finally:
        client.close()
        with open(SCORE_LOG, "w") as f:
            json.dump(score_log, f, indent=2)


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="SWaT Autoencoder Anomaly Detector")
    sub = parser.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("train")
    t.add_argument("--data",   required=True, help="Path to SWaT normal CSV")
    t.add_argument("--epochs", type=int, default=50)
    t.add_argument("--save",   default="ae_model.pt")

    m = sub.add_parser("monitor")
    m.add_argument("--plc-ip",   required=True)
    m.add_argument("--plc-port", type=int, default=502)
    m.add_argument("--model",    default="ae_model.pt")
    m.add_argument("--interval", type=float, default=1.0)

    args = parser.parse_args()
    if args.cmd == "train":
        train(args)
    else:
        monitor(args)


if __name__ == "__main__":
    main()
