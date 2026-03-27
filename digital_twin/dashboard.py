#!/usr/bin/env python3
"""
dashboard.py  —  SWaT Digital Twin Live Dashboard
Replays sensor data from CSV across all 6 stages in real time.
Shows live sensor values, trends, alarm states, and ODE prediction.

Usage:
    python3 dashboard.py --data ../assets/19-Feb-2026_0930_1735.csv
    python3 dashboard.py --data ../assets/19-Feb-2026_0930_1735.csv --speed 10 --attack 5000
"""

import argparse, time, sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import matplotlib.patches as mpatches
from matplotlib.animation import FuncAnimation
from collections import deque

# ── Colour scheme (SUTD red-based dark industrial) ───────────────────────────
BG      = '#0A0A14'
PANEL   = '#0D1020'
RED     = '#E8243C'
CYAN    = '#00D4FF'
GREEN   = '#00FF88'
ORANGE  = '#FF8C00'
YELLOW  = '#FFD700'
WHITE   = '#FFFFFF'
GREY    = '#555577'
DGREY   = '#1A1A2E'
ALARM   = '#FF2244'

# ── Stage definitions ─────────────────────────────────────────────────────────
STAGES = {
    'P1 Raw Water':     {'level': 'LIT101.Pv',  'flow': 'FIT101.Pv',  'valve': 'MV101.Status', 'pump': 'P101.Status',  'color': CYAN,   'limit': (250, 800)},
    'P3 Ultrafiltration':{'level': 'LIT301.Pv', 'flow': 'FIT301.Pv',  'valve': 'MV301.Status', 'pump': 'P301.Status',  'color': GREEN,  'limit': (500, 1000)},
    'P4 De-Chlor':      {'level': 'LIT401.Pv',  'flow': 'FIT401.Pv',  'valve': None,            'pump': 'P401.Status',  'color': ORANGE, 'limit': (500, 1000)},
    'P6 RO Product':    {'level': 'LIT601.Pv',  'flow': 'FIT602.Pv',  'valve': None,            'pump': 'P601.Status',  'color': YELLOW, 'limit': (100, 600)},
}

TRAIL = 300   # seconds of history to show in trend plots


def load_data(csv_path):
    print(f"[*] Loading {csv_path}...")
    df = pd.read_csv(csv_path, low_memory=False)
    for c in df.columns[1:]:
        df[c] = pd.to_numeric(df[c], errors='coerce')
    df = df.fillna(method='ffill').fillna(0)
    print(f"    {len(df):,} rows  {df.columns[0]}: {df.iloc[0, 0]} → {df.iloc[-1, 0]}")
    return df


def gauge_color(val, lo, hi):
    pct = (val - lo) / (hi - lo + 1e-8)
    if pct < 0.1 or pct > 0.9: return ALARM
    if pct < 0.2 or pct > 0.8: return ORANGE
    return GREEN


def run_dashboard(df, speed=5, attack_start=None):
    n = len(df)
    fig = plt.figure(figsize=(18, 10), facecolor=BG)
    fig.canvas.manager.set_window_title('SWaT Digital Twin — Live Dashboard')

    gs = gridspec.GridSpec(3, 5, figure=fig, hspace=0.45, wspace=0.35,
                           left=0.04, right=0.98, top=0.93, bottom=0.06)

    # Title
    fig.text(0.5, 0.965, 'SWaT Digital Twin  —  Live Plant Dashboard',
             ha='center', fontsize=14, fontweight='bold', color=WHITE,
             fontfamily='monospace')
    fig.text(0.5, 0.945, 'iTrust Lab · SUTD · 51.508 Secure Cyber Physical Systems',
             ha='center', fontsize=9, color=GREY, fontfamily='monospace')

    # ── Stage gauges (row 0, cols 0-3) ───────────────────────────────────────
    gauge_axes = {}
    stage_keys = list(STAGES.keys())
    for i, (name, cfg) in enumerate(STAGES.items()):
        ax = fig.add_subplot(gs[0, i], polar=True)
        ax.set_facecolor(PANEL)
        gauge_axes[name] = ax

    # ── Trend plots (row 1, cols 0-3) ─────────────────────────────────────────
    trend_axes = {}
    trend_data = {name: {'level': deque(maxlen=TRAIL), 'flow': deque(maxlen=TRAIL)}
                  for name in STAGES}
    for i, name in enumerate(stage_keys):
        ax = fig.add_subplot(gs[1, i])
        ax.set_facecolor(PANEL)
        ax.tick_params(colors=GREY, labelsize=7)
        for spine in ax.spines.values(): spine.set_color(DGREY)
        ax.set_title(name, color=STAGES[name]['color'], fontsize=8, fontfamily='monospace', pad=3)
        trend_axes[name] = ax

    # ── ODE twin panel (row 0-1, col 4) ──────────────────────────────────────
    ax_ode = fig.add_subplot(gs[0:2, 4])
    ax_ode.set_facecolor(PANEL)
    ax_ode.set_title('ODE Twin: P1 LIT101', color=CYAN, fontsize=9, fontfamily='monospace', pad=3)
    ax_ode.tick_params(colors=GREY, labelsize=7)
    for spine in ax_ode.spines.values(): spine.set_color(DGREY)
    ode_real = deque(maxlen=TRAIL)
    ode_sim  = deque(maxlen=TRAIL)
    lit_sim_val = df['LIT101.Pv'].iloc[0]
    Q_IN  = 2.0 / 1.5   # L/s → mm/s
    Q_OUT = 1.8 / 1.5

    # ── Status panel (row 2, all cols) ───────────────────────────────────────
    ax_status = fig.add_subplot(gs[2, :])
    ax_status.set_facecolor(PANEL)
    ax_status.set_xlim(0, 1)
    ax_status.set_ylim(0, 1)
    ax_status.axis('off')
    status_text = ax_status.text(0.02, 0.6, '', color=WHITE, fontsize=10,
                                  fontfamily='monospace', va='top')
    alarm_text  = ax_status.text(0.5, 0.6, '', color=ALARM, fontsize=11,
                                  fontfamily='monospace', va='top', ha='center', fontweight='bold')
    time_text   = fig.text(0.98, 0.965, '', ha='right', fontsize=9, color=GREY, fontfamily='monospace')

    frame_idx = [0]

    def draw_gauge(ax, val, lo, hi, label, color, unit='mm'):
        ax.clear()
        ax.set_facecolor(PANEL)
        ax.set_theta_zero_location('N')
        ax.set_theta_direction(-1)

        # Background arc
        theta = np.linspace(np.radians(-135), np.radians(135), 100)
        ax.plot(theta, [0.9]*100, color=DGREY, lw=8, solid_capstyle='round')

        # Value arc
        pct = np.clip((val - lo) / (hi - lo), 0, 1)
        end = np.radians(-135 + pct * 270)
        theta_v = np.linspace(np.radians(-135), end, 100)
        gcol = gauge_color(val, lo, hi)
        ax.plot(theta_v, [0.9]*len(theta_v), color=gcol, lw=8, solid_capstyle='round')

        # Value text
        ax.text(0, 0.15, f'{val:.0f}', ha='center', va='center',
                fontsize=13, fontweight='bold', color=gcol, fontfamily='monospace')
        ax.text(0, -0.15, unit, ha='center', va='center',
                fontsize=7, color=GREY, fontfamily='monospace')
        ax.text(0, -0.45, label, ha='center', va='center',
                fontsize=7, color=color, fontfamily='monospace')
        ax.set_ylim(0, 1.1)
        ax.set_rticks([])
        ax.set_thetagrids([])
        ax.spines['polar'].set_visible(False)
        # LL/HH markers
        for limit, lbl in [(lo, 'LL'), (hi, 'HH')]:
            p = np.clip((limit - lo) / (hi - lo), 0, 1)
            ang = np.radians(-135 + p * 270)
            ax.plot([ang], [0.9], 'o', color=ALARM, ms=5)

    def update(frame):
        i = frame_idx[0]
        if i >= n:
            return

        row = df.iloc[i]
        ts  = row.get('t_stamp', f't={i}')

        # Attack state
        in_attack = attack_start is not None and attack_start <= i < attack_start + 300
        mv_state = 1 if in_attack else row.get('MV101.Status', 2)
        p1_state = 1 if in_attack else row.get('P101.Status', 2)

        # ODE simulation
        nonlocal lit_sim_val
        q_in  = Q_IN  if mv_state == 2 else 0.0
        q_out = Q_OUT if p1_state == 2 else 0.0
        lit_sim_val = np.clip(lit_sim_val + (q_in - q_out), 0, 1200)
        ode_real.append(row.get('LIT101.Pv', 0))
        ode_sim.append(lit_sim_val)

        # Update gauges
        alarms = []
        for name, cfg in STAGES.items():
            lev = row.get(cfg['level'], 0)
            flo = row.get(cfg['flow'], 0)
            lo, hi = cfg['limit']
            trend_data[name]['level'].append(lev)
            trend_data[name]['flow'].append(flo)
            draw_gauge(gauge_axes[name], lev, lo, hi, cfg['level'].split('.')[0], cfg['color'])
            if lev < lo or lev > hi:
                alarms.append(f"⚠ {name}: {cfg['level'].split('.')[0]}={lev:.0f}mm")

        # Update trends
        for name, cfg in STAGES.items():
            ax = trend_axes[name]
            ax.clear()
            ax.set_facecolor(PANEL)
            ax.tick_params(colors=GREY, labelsize=6)
            for spine in ax.spines.values(): spine.set_color(DGREY)
            lev_d = list(trend_data[name]['level'])
            flo_d = list(trend_data[name]['flow'])
            t = np.arange(len(lev_d))
            if lev_d:
                ax.plot(t, lev_d, color=cfg['color'], lw=1.2, label='Level')
                lo, hi = cfg['limit']
                ax.axhline(hi, color=ALARM, lw=0.6, linestyle='--', alpha=0.5)
                ax.axhline(lo, color=ALARM, lw=0.6, linestyle='--', alpha=0.5)
            ax.set_title(name, color=cfg['color'], fontsize=7, fontfamily='monospace', pad=2)
            if in_attack and name == 'P1 Raw Water':
                ax.set_facecolor('#200010')

        # ODE panel
        ax_ode.clear()
        ax_ode.set_facecolor(PANEL if not in_attack else '#1A0010')
        ax_ode.tick_params(colors=GREY, labelsize=7)
        for spine in ax_ode.spines.values(): spine.set_color(DGREY)
        t_ode = np.arange(len(ode_real))
        if ode_real:
            ax_ode.plot(t_ode, list(ode_real), color=CYAN,   lw=1.2, label='Real LIT101')
            ax_ode.plot(t_ode, list(ode_sim),  color=ORANGE, lw=1.2, linestyle='--', label='ODE Prediction')
            residual = abs(list(ode_real)[-1] - list(ode_sim)[-1])
            ax_ode.set_title(f'ODE Twin: P1 LIT101  |  Δ={residual:.1f}mm',
                             color=ALARM if residual > 30 else CYAN,
                             fontsize=8, fontfamily='monospace', pad=3)
        ax_ode.axhline(800, color=ALARM, lw=0.7, linestyle=':', alpha=0.5)
        ax_ode.axhline(250, color=ALARM, lw=0.7, linestyle=':', alpha=0.5)
        ax_ode.legend(fontsize=7, facecolor=DGREY, labelcolor=WHITE, loc='upper right')

        # Status bar
        p1_lit = row.get('LIT101.Pv', 0)
        p1_fit = row.get('FIT101.Pv', 0)
        status_msg = (f"t={i:6d}  |  P1: LIT101={p1_lit:.1f}mm  FIT101={p1_fit:.3f}L/s  "
                      f"MV101={'OPEN' if mv_state==2 else 'CLOSED'}  P101={'ON' if p1_state==2 else 'OFF'}")
        if in_attack:
            status_msg += "  |  *** ATTACK ACTIVE ***"
        status_text.set_text(status_msg)
        status_text.set_color(ALARM if in_attack else WHITE)

        alarm_msg = '  '.join(alarms[:3]) if alarms else '✓  All stages nominal'
        alarm_text.set_text(alarm_msg)
        alarm_text.set_color(ALARM if alarms else GREEN)
        time_text.set_text(str(ts)[:19])

        frame_idx[0] = i + speed

    ani = FuncAnimation(fig, update, interval=50, cache_frame_data=False)
    plt.show()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data',         default='../assets/19-Feb-2026_0930_1735.csv')
    ap.add_argument('--speed',        type=int, default=5,    help='Samples per frame (playback speed)')
    ap.add_argument('--attack',       type=int, default=None, help='Inject attack at this sample index')
    args = ap.parse_args()

    df = load_data(args.data)
    run_dashboard(df, speed=args.speed, attack_start=args.attack)

if __name__ == '__main__':
    main()
