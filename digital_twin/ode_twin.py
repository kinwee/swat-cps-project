#!/usr/bin/env python3
"""
ode_twin.py  —  SWaT P1 ODE-based Digital Twin
Physics model for LIT101 (tank level) based on mass balance:

    dL/dt = (Q_in - Q_out) / A_tank

Where:
    Q_in  = calibrated rise rate from data (mm/s when MV101 open)
    Q_out = calibrated fall rate from data (mm/s when P101 on)
    Drift correction (alpha=0.02) prevents accumulation during normal operation
    Correction disabled during attack → residual = anomaly signal

The twin:
1. Loads real sensor data from CSV
2. Uses MV101 and P101 states to simulate LIT101 via ODE
3. Compares simulated vs real LIT101 — deviation = anomaly signal
4. Can inject an attack (close MV101, stop P101) and show predicted effect

Usage:
    python3 ode_twin.py --data ../assets/19-Feb-2026_0930_1735.csv
    python3 ode_twin.py --data ../assets/19-Feb-2026_0930_1735.csv --attack --attack-start 5000 --attack-duration 300
"""

import argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from datetime import datetime

# ── SWaT P1 Physical Parameters ──────────────────────────────────────────────
DT = 1.0      # Timestep (seconds, matches 1Hz dataset)

# These are estimated from data during calibration — see calibrate_params()
DEFAULT_RISE_RATE = 0.85   # mm/s when MV101=OPEN, P101=OFF (filling)
DEFAULT_FALL_RATE = 0.67   # mm/s when MV101=CLOSED, P101=ON (draining)

# Drift correction: blend ODE prediction toward measured value each step
# 0.0 = pure ODE (diverges), 1.0 = just copy measured (useless)
# 0.02 gives ~50-step correction half-life while preserving ODE dynamics
CORRECTION_ALPHA = 0.02


def load_data(csv_path):
    print(f"[*] Loading {csv_path}...")
    df = pd.read_csv(csv_path, low_memory=False)
    cols = ['t_stamp', 'LIT101.Pv', 'FIT101.Pv', 'MV101.Status', 'P101.Status']
    for c in cols[1:]:
        df[c] = pd.to_numeric(df[c], errors='coerce')
    df = df[cols].dropna().reset_index(drop=True)
    print(f"    Loaded {len(df):,} rows | {df['t_stamp'].iloc[0]} → {df['t_stamp'].iloc[-1]}")
    return df


def calibrate_params(df):
    """Auto-calibrate rise/fall rates from actual LIT101 data."""
    lit = df['LIT101.Pv'].values
    mv  = df['MV101.Status'].values
    p1  = df['P101.Status'].values
    dlit = lit[1:] - lit[:-1]

    # Rise rate: when MV101=OPEN(2) and P101=OFF(1) → tank filling
    fill_mask = (mv[1:] == 2) & (p1[1:] == 1) & (dlit > 0.05)
    rise_rate = np.median(dlit[fill_mask]) if fill_mask.sum() > 50 else DEFAULT_RISE_RATE

    # Fall rate: when MV101=CLOSED(1) and P101=ON(2) → tank draining
    drain_mask = (mv[1:] == 1) & (p1[1:] == 2) & (dlit < -0.05)
    fall_rate = np.median(np.abs(dlit[drain_mask])) if drain_mask.sum() > 50 else DEFAULT_FALL_RATE

    # Net rate when both open/on: use direct FIT101 correlation
    both_mask = (mv[1:] == 2) & (p1[1:] == 2)
    if both_mask.sum() > 50:
        net_rate = np.median(dlit[both_mask])
    else:
        net_rate = rise_rate - fall_rate

    print(f"    Calibrated: rise={rise_rate:.3f} mm/s  fall={fall_rate:.3f} mm/s  net={net_rate:.3f} mm/s")
    return rise_rate, fall_rate, net_rate


def simulate_ode(df, attack_start=None, attack_duration=0):
    """
    Simulate LIT101 using ODE driven by MV101 and P101 states.
    Uses data-calibrated rates + drift correction for accuracy.
    Optionally inject attack: force MV101=CLOSED while P101 stays ON (Phase 1 pattern).
    """
    n = len(df)
    lit_sim    = np.zeros(n)
    lit_sim[0] = df['LIT101.Pv'].iloc[0]
    residuals  = np.zeros(n)
    attack_mask= np.zeros(n, dtype=bool)

    rise_rate, fall_rate, net_rate = calibrate_params(df)

    for i in range(1, n):
        mv_open = df['MV101.Status'].iloc[i] == 2
        p1_on   = df['P101.Status'].iloc[i] == 2

        # Inject attack: Phase 1 closes MV101, P101 stays ON → tank drains
        in_attack = False
        if attack_start and attack_start <= i < attack_start + attack_duration:
            mv_open = False    # force MV101 CLOSED (no inflow)
            p1_on   = True     # P101 stays ON (pump keeps draining)
            attack_mask[i] = True
            in_attack = True

        # ODE step using calibrated rates
        if mv_open and p1_on:
            dL = net_rate * DT
        elif mv_open and not p1_on:
            dL = rise_rate * DT
        elif not mv_open and p1_on:
            dL = -fall_rate * DT
        else:  # both off
            dL = 0.0

        lit_sim[i] = np.clip(lit_sim[i-1] + dL, 0, 1200)

        # Drift correction: gently pull ODE toward measured value
        # Skip during attack so the divergence is visible as anomaly signal
        lit_real = df['LIT101.Pv'].iloc[i]
        if not in_attack:
            lit_sim[i] += CORRECTION_ALPHA * (lit_real - lit_sim[i])

        residuals[i] = lit_real - lit_sim[i]

    return lit_sim, residuals, attack_mask


def plot_twin(df, lit_sim, residuals, attack_mask, output_path='ode_twin_plot.png'):
    fig, axes = plt.subplots(3, 1, figsize=(16, 10), facecolor='#0A0A14')
    fig.suptitle('SWaT P1 — ODE Digital Twin vs Real Sensor Data',
                 fontsize=14, color='white', fontweight='bold', y=0.98)

    t = np.arange(len(df))
    colors = {'real': '#00D4FF', 'sim': '#FF6B35', 'residual': '#FFD700',
              'attack': '#FF2244', 'll': '#FF4444', 'hh': '#FF4444'}

    # ── Panel 1: LIT101 real vs simulated ────────────────────────────────────
    ax1 = axes[0]
    ax1.set_facecolor('#0D0D1A')
    ax1.plot(t, df['LIT101.Pv'].values, color=colors['real'],  lw=1.2, label='LIT101 (Real)', alpha=0.9)
    ax1.plot(t, lit_sim,                color=colors['sim'],   lw=1.5, label='LIT101 (ODE Simulated)', alpha=0.85, linestyle='--')
    ax1.axhline(800, color=colors['hh'], lw=0.8, linestyle=':', alpha=0.6, label='HH (800mm)')
    ax1.axhline(250, color=colors['ll'], lw=0.8, linestyle=':', alpha=0.6, label='LL (250mm)')
    if attack_mask.any():
        ax1.axvspan(t[attack_mask][0], t[attack_mask][-1], color=colors['attack'], alpha=0.15, label='Attack Window')
    ax1.set_ylabel('Level (mm)', color='white', fontsize=10)
    ax1.set_ylim(0, 1000)
    ax1.tick_params(colors='white')
    ax1.spines[:].set_color('#333355')
    ax1.legend(loc='upper right', fontsize=8, facecolor='#1A1A2E', labelcolor='white')
    ax1.set_title('Tank Level: Real vs ODE Simulated', color='#AAAACC', fontsize=10, pad=4)

    # ── Panel 2: Residual (anomaly signal) ───────────────────────────────────
    ax2 = axes[1]
    ax2.set_facecolor('#0D0D1A')
    ax2.plot(t, residuals, color=colors['residual'], lw=1.0, alpha=0.8, label='Residual (Real − Simulated)')
    ax2.axhline(0, color='white', lw=0.5, alpha=0.3)
    threshold = np.percentile(np.abs(residuals), 95)
    ax2.axhline( threshold, color='#FF4444', lw=0.8, linestyle='--', alpha=0.7, label=f'±95th pct ({threshold:.1f}mm)')
    ax2.axhline(-threshold, color='#FF4444', lw=0.8, linestyle='--', alpha=0.7)
    if attack_mask.any():
        ax2.axvspan(t[attack_mask][0], t[attack_mask][-1], color=colors['attack'], alpha=0.15)
    ax2.set_ylabel('Residual (mm)', color='white', fontsize=10)
    ax2.tick_params(colors='white')
    ax2.spines[:].set_color('#333355')
    ax2.legend(loc='upper right', fontsize=8, facecolor='#1A1A2E', labelcolor='white')
    ax2.set_title('ODE Residual — Anomaly Signal', color='#AAAACC', fontsize=10, pad=4)

    # ── Panel 3: Actuator states ──────────────────────────────────────────────
    ax3 = axes[2]
    ax3.set_facecolor('#0D0D1A')
    mv_state = (df['MV101.Status'].values == 2).astype(float)
    p1_state = (df['P101.Status'].values == 2).astype(float) * 0.8
    ax3.fill_between(t, mv_state, alpha=0.6, color='#00FF88', label='MV101=OPEN', step='mid')
    ax3.fill_between(t, p1_state, alpha=0.5, color='#4488FF', label='P101=ON',   step='mid')
    if attack_mask.any():
        ax3.axvspan(t[attack_mask][0], t[attack_mask][-1], color=colors['attack'], alpha=0.25, label='Attack (MV101 CLOSED, P101 OFF)')
    ax3.set_ylabel('State', color='white', fontsize=10)
    ax3.set_xlabel('Time (seconds)', color='white', fontsize=10)
    ax3.set_ylim(-0.1, 1.2)
    ax3.tick_params(colors='white')
    ax3.spines[:].set_color('#333355')
    ax3.legend(loc='upper right', fontsize=8, facecolor='#1A1A2E', labelcolor='white')
    ax3.set_title('Actuator States', color='#AAAACC', fontsize=10, pad=4)

    plt.tight_layout(rect=[0, 0, 1, 0.97])
    plt.savefig(output_path, dpi=150, bbox_inches='tight', facecolor='#0A0A14')
    print(f"[+] Plot saved: {output_path}")
    plt.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data',            default='../assets/19-Feb-2026_0930_1735.csv')
    ap.add_argument('--attack',          action='store_true', help='Inject simulated attack')
    ap.add_argument('--attack-start',    type=int, default=5000, help='Attack start (sample index)')
    ap.add_argument('--attack-duration', type=int, default=300,  help='Attack duration (samples=seconds)')
    ap.add_argument('--output',          default='ode_twin_plot.png')
    args = ap.parse_args()

    df = load_data(args.data)
    attack_start = args.attack_start if args.attack else None
    lit_sim, residuals, attack_mask = simulate_ode(df, attack_start, args.attack_duration)

    # Stats
    rmse = np.sqrt(np.mean(residuals**2))
    mae  = np.mean(np.abs(residuals))
    print(f"\n[*] ODE Twin Performance:")
    print(f"    RMSE: {rmse:.2f} mm")
    print(f"    MAE:  {mae:.2f} mm")
    print(f"    Max residual: {np.max(np.abs(residuals)):.2f} mm")
    if attack_mask.any():
        attack_residual = residuals[attack_mask]
        print(f"\n[*] Under attack ({attack_mask.sum()}s):")
        print(f"    Mean residual: {np.mean(attack_residual):.2f} mm")
        print(f"    Max residual:  {np.max(np.abs(attack_residual)):.2f} mm")

    plot_twin(df, lit_sim, residuals, attack_mask, args.output)
    print(f"\n[+] ODE twin complete.")

if __name__ == '__main__':
    main()
