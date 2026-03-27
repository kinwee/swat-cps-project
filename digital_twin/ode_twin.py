#!/usr/bin/env python3
"""
ode_twin.py  —  SWaT P1 ODE-based Digital Twin
Physics model for LIT101 (tank level) based on mass balance:

    dL/dt = (Q_in - Q_out) / A_tank

Where:
    Q_in  = MV101_open × FIT101_max_flow  (inlet flow when valve open)
    Q_out = P101_on    × pump_flow_rate   (pump outflow)
    A_tank ≈ 1.5 m² (SWaT P1 tank cross-section)

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
A_TANK       = 1.5      # Tank cross-section (m²)
MAX_FLOW_IN  = 2.0      # Max inlet flow when MV101=OPEN (L/s → mm/s via tank area)
PUMP_FLOW    = 1.8      # Pump P101 outflow rate (L/s)
DT           = 1.0      # Timestep (seconds, matches 1Hz dataset)

# Convert L/s to mm/s using tank area:  1 L = 0.001 m³, A=1.5 m²
# dL/dt (mm/s) = Q (L/s) × 0.001 / A_tank × 1000  = Q / A_tank × (0.001/0.001) = Q/1.5
FLOW_TO_MMPS = 1.0 / A_TANK   # mm/s per L/s (approximate)


def load_data(csv_path):
    print(f"[*] Loading {csv_path}...")
    df = pd.read_csv(csv_path, low_memory=False)
    cols = ['t_stamp', 'LIT101.Pv', 'FIT101.Pv', 'MV101.Status', 'P101.Status']
    for c in cols[1:]:
        df[c] = pd.to_numeric(df[c], errors='coerce')
    df = df[cols].dropna().reset_index(drop=True)
    print(f"    Loaded {len(df):,} rows | {df['t_stamp'].iloc[0]} → {df['t_stamp'].iloc[-1]}")
    return df


def simulate_ode(df, attack_start=None, attack_duration=0):
    """
    Simulate LIT101 using ODE driven by MV101 and P101 states.
    Optionally inject attack: force MV101=CLOSED, P101=OFF from attack_start.
    """
    n = len(df)
    lit_sim   = np.zeros(n)
    lit_sim[0] = df['LIT101.Pv'].iloc[0]   # initialise from real value
    residuals  = np.zeros(n)
    attack_mask= np.zeros(n, dtype=bool)

    # Calibrate flow constants from real data
    # When MV101=OPEN (2) and P101=ON (2): median FIT101 ≈ real Q_in
    mask_open = (df['MV101.Status'] == 2) & (df['P101.Status'] == 2)
    if mask_open.sum() > 100:
        q_in_real = df.loc[mask_open, 'FIT101.Pv'].median()
        q_in = q_in_real if q_in_real > 0.1 else MAX_FLOW_IN
    else:
        q_in = MAX_FLOW_IN

    for i in range(1, n):
        # Get actuator states (2=ON/OPEN, 1=OFF/CLOSED)
        mv_open = df['MV101.Status'].iloc[i] == 2
        p1_on   = df['P101.Status'].iloc[i] == 2

        # Inject attack
        if attack_start and attack_start <= i < attack_start + attack_duration:
            mv_open = False   # force CLOSED
            p1_on   = False   # force OFF
            attack_mask[i] = True

        # ODE: dL/dt = (Q_in - Q_out) / A × unit_conversion
        flow_in  = q_in  * FLOW_TO_MMPS if mv_open else 0.0
        flow_out = PUMP_FLOW * FLOW_TO_MMPS if p1_on else 0.0
        dL = (flow_in - flow_out) * DT

        lit_sim[i] = np.clip(lit_sim[i-1] + dL, 0, 1200)
        residuals[i] = df['LIT101.Pv'].iloc[i] - lit_sim[i]

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
