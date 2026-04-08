#!/usr/bin/env python3
"""
dashboard.py  —  SWaT Digital Twin Live Dashboard
Replays sensor data from CSV across all 6 stages in real time.
Shows: plant schematic, live gauges, trends, ODE twin, alarms.

Usage:
    python3 dashboard.py --data ../assets/19-Feb-2026_0930_1735.csv
    python3 dashboard.py --data ../assets/19-Feb-2026_0930_1735.csv --speed 10 --attack 5000
"""

import argparse, os
import numpy as np
import pandas as pd
import matplotlib
try:
    matplotlib.use('TkAgg')
except Exception:
    matplotlib.use('Agg')
    print("[!] TkAgg not available — using Agg (non-interactive, plots saved to file)")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import matplotlib.image as mpimg
from PIL import Image
from matplotlib.animation import FuncAnimation
from collections import deque

# ── Colours ───────────────────────────────────────────────────────────────────
BG    = '#0A0A14'
PANEL = '#0D1020'
RED   = '#E8243C'
CYAN  = '#00D4FF'
GREEN = '#00FF88'
ORANGE= '#FF8C00'
YELLOW= '#FFD700'
WHITE = '#FFFFFF'
GREY  = '#555577'
DGREY = '#1A1A2E'
ALARM = '#FF2244'
LGREY = '#AAAACC'

STAGES = {
    'P1\nRaw Water':       {'level':'LIT101.Pv', 'flow':'FIT101.Pv',  'lo':250,  'hi':800,  'color':CYAN},
    'P3\nUltrafiltration': {'level':'LIT301.Pv', 'flow':'FIT301.Pv',  'lo':500,  'hi':1000, 'color':GREEN},
    'P4\nDe-Chlorination': {'level':'LIT401.Pv', 'flow':'FIT401.Pv',  'lo':500,  'hi':1000, 'color':ORANGE},
    'P6\nRO Product':      {'level':'LIT601.Pv', 'flow':'FIT602.Pv',  'lo':100,  'hi':600,  'color':YELLOW},
}
TRAIL = 300

IMG_DIR = os.path.join(os.path.dirname(__file__), '..', 'assets', 'images')


def load_data(csv_path):
    print(f"[*] Loading {csv_path}...")
    df = pd.read_csv(csv_path, low_memory=False)
    for c in df.columns[1:]:
        df[c] = pd.to_numeric(df[c], errors='coerce')
    df = df.ffill().fillna(0)
    print(f"    {len(df):,} rows  {df['t_stamp'].iloc[0]} → {df['t_stamp'].iloc[-1]}")
    return df


def gauge_color(val, lo, hi):
    pct = (val - lo) / (hi - lo + 1e-8)
    if pct < 0.08 or pct > 0.92: return ALARM
    if pct < 0.18 or pct > 0.82: return ORANGE
    return GREEN


def draw_gauge(ax, val, lo, hi, label, color, unit='mm'):
    ax.clear()
    ax.set_facecolor(PANEL)
    ax.set_theta_zero_location('N')
    ax.set_theta_direction(-1)
    # Background arc
    theta_bg = np.linspace(np.radians(-135), np.radians(135), 200)
    ax.plot(theta_bg, [0.9]*200, color=DGREY, lw=10, solid_capstyle='round')
    # Value arc
    pct = np.clip((val - lo) / (hi - lo), 0, 1)
    end_ang = np.radians(-135 + pct * 270)
    theta_v = np.linspace(np.radians(-135), end_ang, max(2, int(pct*200)))
    gcol = gauge_color(val, lo, hi)
    if len(theta_v) > 1:
        ax.plot(theta_v, [0.9]*len(theta_v), color=gcol, lw=10, solid_capstyle='round')
    # Texts
    ax.text(0,  0.18, f'{val:.0f}', ha='center', va='center', fontsize=14,
            fontweight='bold', color=gcol, fontfamily='monospace')
    ax.text(0, -0.15, unit, ha='center', va='center', fontsize=7, color=GREY, fontfamily='monospace')
    ax.text(0, -0.48, label, ha='center', va='center', fontsize=7, color=color, fontfamily='monospace')
    # LL/HH dots
    for limit in [lo, hi]:
        p = np.clip((limit - lo)/(hi - lo), 0, 1)
        ang = np.radians(-135 + p * 270)
        ax.plot([ang], [0.9], 'o', color=ALARM, ms=6, zorder=5)
    ax.set_ylim(0, 1.1); ax.set_rticks([]); ax.set_thetagrids([])
    ax.spines['polar'].set_visible(False)


def run_dashboard(df, speed=5, attack_start=None):
    n = len(df)

    # Load schematic images
    p1_img = arch_img = None
    for name, path in [('p1', 'swat_p1_stage.png'), ('arch', 'swat_architecture.png')]:
        full = os.path.join(IMG_DIR, path)
        if os.path.exists(full):
            try:
                img = np.array(Image.open(full).convert('RGBA'))
                if name == 'p1':   p1_img   = img
                else:              arch_img = img
            except Exception as e:
                print(f"[!] Could not load {path}: {e}")

    # ── Layout ────────────────────────────────────────────────────────────────
    fig = plt.figure(figsize=(20, 11), facecolor=BG)
    fig.canvas.manager.set_window_title('SWaT Digital Twin — Live Dashboard')

    # 4 rows × 6 cols
    gs = gridspec.GridSpec(4, 6, figure=fig,
                           hspace=0.5, wspace=0.35,
                           left=0.03, right=0.98, top=0.92, bottom=0.05)

    # Header
    fig.text(0.5, 0.965, 'SWaT Digital Twin  —  Live Plant Dashboard',
             ha='center', fontsize=14, fontweight='bold', color=WHITE, fontfamily='monospace')
    fig.text(0.5, 0.945, 'iTrust Lab  ·  SUTD  ·  51.508 Secure Cyber Physical Systems',
             ha='center', fontsize=8.5, color=GREY, fontfamily='monospace')

    # Row 0: P1 schematic (cols 0-3) + architecture (cols 4-5)
    ax_p1   = fig.add_subplot(gs[0, 0:4])
    ax_arch = fig.add_subplot(gs[0, 4:6])
    for ax, img, title in [(ax_p1, p1_img, 'SWaT P1 P&ID — Raw Water Intake (Attack Target)'),
                           (ax_arch, arch_img, 'SWaT Network Architecture')]:
        ax.set_facecolor(PANEL)
        ax.axis('off')
        if img is not None:
            ax.imshow(img, aspect='auto')
        ax.set_title(title, color=LGREY, fontsize=8, fontfamily='monospace',
                     pad=3, loc='left')

    # Row 1: Gauges (4 stages)
    gauge_axes = {}
    stage_keys = list(STAGES.keys())
    for i, name in enumerate(stage_keys):
        ax = fig.add_subplot(gs[1, i], polar=True)
        ax.set_facecolor(PANEL)
        gauge_axes[name] = ax

    # Row 2: Trend plots (4 stages) + ODE twin (cols 4-5)
    trend_axes = {}
    trend_data = {n: deque(maxlen=TRAIL) for n in STAGES}
    for i, name in enumerate(stage_keys):
        ax = fig.add_subplot(gs[2, i])
        ax.set_facecolor(PANEL)
        ax.tick_params(colors=GREY, labelsize=6)
        for sp in ax.spines.values(): sp.set_color(DGREY)
        trend_axes[name] = ax

    ax_ode = fig.add_subplot(gs[1:3, 4:6])
    ax_ode.set_facecolor(PANEL)
    ax_ode.tick_params(colors=GREY, labelsize=7)
    for sp in ax_ode.spines.values(): sp.set_color(DGREY)
    ode_real = deque(maxlen=TRAIL)
    ode_sim  = deque(maxlen=TRAIL)
    lit_sim_val = [df['LIT101.Pv'].iloc[0]]
    Q_IN  = 2.0 / 1.5
    Q_OUT = 1.8 / 1.5

    # Row 3: Status bar
    ax_stat = fig.add_subplot(gs[3, :])
    ax_stat.set_facecolor(PANEL)
    ax_stat.axis('off')
    status_txt = ax_stat.text(0.01, 0.72, '', color=WHITE, fontsize=9,
                               fontfamily='monospace', va='top', transform=ax_stat.transAxes)
    alarm_txt  = ax_stat.text(0.5,  0.72, '', color=ALARM, fontsize=10,
                               fontfamily='monospace', va='top', ha='center',
                               fontweight='bold', transform=ax_stat.transAxes)
    time_txt   = fig.text(0.98, 0.965, '', ha='right', fontsize=8.5,
                          color=GREY, fontfamily='monospace')

    # Highlight P1 on schematic during attack
    attack_overlay = ax_p1.text(0.02, 0.88, '', color=ALARM, fontsize=11,
                                 fontweight='bold', fontfamily='monospace',
                                 transform=ax_p1.transAxes, va='top',
                                 bbox=dict(boxstyle='round,pad=0.3', facecolor='#300010',
                                           edgecolor=ALARM, alpha=0.9))

    frame_idx = [0]

    def update(frame):
        i = frame_idx[0]
        if i >= n:
            frame_idx[0] = 0
            return

        row = df.iloc[i]
        ts  = str(row.get('t_stamp', f't={i}'))[:19]
        in_attack = (attack_start is not None) and (attack_start <= i < attack_start + 300)

        mv_state = 1 if in_attack else int(row.get('MV101.Status', 2))
        p1_state = 1 if in_attack else int(row.get('P101.Status',  2))

        # ODE
        q_in  = Q_IN  if mv_state == 2 else 0.0
        q_out = Q_OUT if p1_state == 2 else 0.0
        lit_sim_val[0] = np.clip(lit_sim_val[0] + (q_in - q_out), 0, 1200)
        ode_real.append(float(row.get('LIT101.Pv', 0)))
        ode_sim.append(lit_sim_val[0])

        # Gauges + trends
        alarms = []
        for j, (name, cfg) in enumerate(STAGES.items()):
            lev = float(row.get(cfg['level'], 0))
            trend_data[name].append(lev)
            draw_gauge(gauge_axes[name], lev, cfg['lo'], cfg['hi'],
                       cfg['level'].split('.')[0], cfg['color'])
            if lev < cfg['lo'] or lev > cfg['hi']:
                alarms.append(f"⚠ {name.replace(chr(10),' ')}: {lev:.0f}mm")

            ax = trend_axes[name]
            ax.clear()
            ax.set_facecolor('#200010' if in_attack and j == 0 else PANEL)
            ax.tick_params(colors=GREY, labelsize=6)
            for sp in ax.spines.values(): sp.set_color(DGREY)
            d = list(trend_data[name])
            if d:
                ax.plot(d, color=cfg['color'], lw=1.3)
                ax.axhline(cfg['hi'], color=ALARM, lw=0.5, linestyle='--', alpha=0.5)
                ax.axhline(cfg['lo'], color=ALARM, lw=0.5, linestyle='--', alpha=0.5)
            sname = name.replace('\n', ' ')
            ax.set_title(sname, color=cfg['color'], fontsize=7,
                         fontfamily='monospace', pad=2)

        # ODE panel
        ax_ode.clear()
        ax_ode.set_facecolor('#1A0010' if in_attack else PANEL)
        ax_ode.tick_params(colors=GREY, labelsize=7)
        for sp in ax_ode.spines.values(): sp.set_color(DGREY)
        t_ode = np.arange(len(ode_real))
        if ode_real:
            ax_ode.plot(t_ode, list(ode_real), color=CYAN,   lw=1.3, label='Real LIT101')
            ax_ode.plot(t_ode, list(ode_sim),  color=ORANGE, lw=1.3, linestyle='--', label='ODE Sim')
            res = abs(ode_real[-1] - ode_sim[-1])
            rcol = ALARM if res > 40 else CYAN
            ax_ode.set_title(f'ODE Twin: P1 LIT101   Δ={res:.1f}mm',
                             color=rcol, fontsize=8.5, fontfamily='monospace', pad=3)
        ax_ode.axhline(800, color=ALARM, lw=0.6, linestyle=':', alpha=0.4)
        ax_ode.axhline(250, color=ALARM, lw=0.6, linestyle=':', alpha=0.4)
        ax_ode.legend(fontsize=7.5, facecolor=DGREY, labelcolor=WHITE, loc='upper right')
        ax_ode.set_ylabel('Level (mm)', color=GREY, fontsize=8)

        # Schematic overlay
        if in_attack:
            attack_overlay.set_text('⚠  ATTACK ACTIVE\nMV101 CLOSED · P101 OFF')
        else:
            attack_overlay.set_text('')

        # Status bar
        p1_lit = float(row.get('LIT101.Pv', 0))
        p1_fit = float(row.get('FIT101.Pv', 0))
        smsg = (f"t={i:6d}  │  LIT101={p1_lit:.1f}mm  FIT101={p1_fit:.3f}L/s  "
                f"MV101={'OPEN' if mv_state==2 else 'CLOSED'}  "
                f"P101={'ON' if p1_state==2 else 'OFF'}  │  {ts}")
        if in_attack: smsg += "  │  *** ATTACK ACTIVE ***"
        status_txt.set_text(smsg)
        status_txt.set_color(ALARM if in_attack else WHITE)

        alarm_msg = '   '.join(alarms[:3]) if alarms else '✓  All stages nominal'
        alarm_txt.set_text(alarm_msg)
        alarm_txt.set_color(ALARM if alarms else GREEN)
        time_txt.set_text(ts)

        frame_idx[0] = i + speed

    ani = FuncAnimation(fig, update, interval=50, cache_frame_data=False)
    plt.show()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data',   default='../assets/19-Feb-2026_0930_1735.csv')
    ap.add_argument('--speed',  type=int, default=5,    help='Samples per frame')
    ap.add_argument('--attack', type=int, default=None, help='Inject attack at sample index')
    args = ap.parse_args()
    df = load_data(args.data)
    run_dashboard(df, speed=args.speed, attack_start=args.attack)

if __name__ == '__main__':
    main()
