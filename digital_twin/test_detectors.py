#!/usr/bin/env python3
"""
test_detectors.py — Offline test of AE + Invariant detectors against 3 scenarios

Scenario 1: Normal operation       → both detectors should be clean
Scenario 2: Phase 1 only           → both detectors should fire
Scenario 3: Phase 1 + Phase 2      → AE evaded, invariant fires (hybrid catches it)

Uses PLC simulator + real CSV data for AE, simulated tag writes for invariant checker.
"""

import sys, os, time, threading, types
import numpy as np
import pandas as pd
import torch

# ── Setup: patch pylogix with simulator ──────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from plc_simulator import MockPLC, TAG_STORE, lock, physics_loop

mock_module = types.ModuleType('pylogix')
mock_module.PLC = MockPLC
sys.modules['pylogix'] = mock_module

REPO = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, REPO)

import scripts.defense.invariant_checker as ic

# Start physics
threading.Thread(target=physics_loop, daemon=True).start()
time.sleep(1)

CSV_PATH = os.path.join(REPO, 'assets', '19-Feb-2026_0930_1735.csv')
AE_MODEL = os.path.join(REPO, 'ae_model.pt')
ADV_MODEL = os.path.join(REPO, 'adv_model.pt')

WINDOW = 10


def separator(label):
    print(f"\n{'='*10} {label} {'='*(60-len(label))}")


def read_invariants():
    """Read tags from simulator and check invariants."""
    plc = MockPLC()
    r = plc.Read(*ic.READ_TAGS)
    if not isinstance(r, list): r = [r]
    state = {x.TagName: x.Value for x in r if x.Value is not None}
    viols = ic.check_invariants(state)
    return state, viols


def load_ae():
    """Load the trained autoencoder model."""
    if not os.path.exists(AE_MODEL):
        print(f"[!] ae_model.pt not found at {AE_MODEL}")
        return None, None, None, None
    ckpt = torch.load(AE_MODEL, map_location='cpu', weights_only=False)

    from scripts.defense.autoencoder_detector import Autoencoder
    ae = Autoencoder(ckpt['input_dim'])
    ae.load_state_dict(ckpt['state'])
    ae.eval()
    return ae, ckpt['mu'], ckpt['sigma'], ckpt['threshold']


def load_adv():
    """Load the trained adversarial encoder."""
    if not os.path.exists(ADV_MODEL):
        print(f"[!] adv_model.pt not found at {ADV_MODEL}")
        return None, None, None
    ckpt = torch.load(ADV_MODEL, map_location='cpu', weights_only=False)

    from scripts.attack.phase2_spoof import Autoencoder, AdversarialEncoder
    ae = Autoencoder(ckpt['input_dim'])
    ae.load_state_dict(ckpt['ae'])
    ae.eval()
    adv = AdversarialEncoder(ckpt['input_dim'])
    adv.load_state_dict(ckpt['adv'])
    adv.eval()
    return adv, ckpt['mu'], ckpt['sigma']


def ae_score(ae, mu, sigma, window_data):
    """Compute AE reconstruction MSE on a window of normalised sensor data."""
    norm = (window_data - mu) / sigma
    x = torch.tensor(norm.flatten(), dtype=torch.float32).unsqueeze(0)
    with torch.no_grad():
        mse = float(((ae(x) - x)**2).mean())
    return mse


def load_csv_windows():
    """Load CSV and prepare sliding windows for AE testing."""
    df = pd.read_csv(CSV_PATH, low_memory=False)
    for c in ['LIT101.Pv', 'FIT101.Pv']:
        df[c] = pd.to_numeric(df[c], errors='coerce')
    data = df[['LIT101.Pv', 'FIT101.Pv']].dropna().values.astype(np.float32)
    return data


# ═══════════════════════════════════════════════════════════════════════════════
print("=" * 72)
print("  SWaT Detector Test — AE + Invariant Checker + Fusion")
print("  Testing 3 scenarios: Normal, Phase 1, Phase 1+2 (adversarial)")
print("=" * 72)

ae, ae_mu, ae_sigma, ae_threshold = load_ae()
adv, adv_mu, adv_sigma = load_adv()
csv_data = load_csv_windows()

if ae is None:
    print("[!] Cannot proceed without ae_model.pt")
    sys.exit(1)

print(f"\n[*] AE threshold: {ae_threshold:.6f}")
print(f"[*] CSV data: {len(csv_data)} samples")
print(f"[*] Adversarial model: {'loaded' if adv is not None else 'NOT FOUND — Phase 2 test will be skipped'}")

results = {}

# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 1: Normal Operation
# ═══════════════════════════════════════════════════════════════════════════════
separator("SCENARIO 1: Normal Operation")
print("[*] Testing AE on 500 normal windows from CSV...")

ae_scores_normal = []
test_start = 1000  # skip initial transient
for i in range(test_start, test_start + 500):
    window = csv_data[i:i+WINDOW]
    score = ae_score(ae, ae_mu, ae_sigma, window)
    ae_scores_normal.append(score)

ae_alarms_normal = sum(1 for s in ae_scores_normal if s > ae_threshold)
ae_normal_mean = np.mean(ae_scores_normal)
ae_normal_max  = np.max(ae_scores_normal)
print(f"    AE MSE — mean={ae_normal_mean:.6f}  max={ae_normal_max:.6f}  threshold={ae_threshold:.6f}")
print(f"    AE alarms: {ae_alarms_normal}/500 ({ae_alarms_normal/5:.1f}%)")

# Invariant check on simulator (normal state)
with lock:
    TAG_STORE['HMI_MV101.Cmd'] = 2; TAG_STORE['HMI_MV101.Auto'] = True
    TAG_STORE['HMI_P101.Cmd']  = 2; TAG_STORE['HMI_P101.Auto']  = True
time.sleep(2)

inv_normal = []
for _ in range(10):
    _, viols = read_invariants()
    inv_normal.append(1 if viols else 0)
    time.sleep(0.5)

inv_alarms_normal = sum(inv_normal)
print(f"    Invariant alarms: {inv_alarms_normal}/10")

# Fusion
ae_flag  = 1 if ae_alarms_normal > 25 else 0   # >5% alarm rate
inv_flag = 1 if inv_alarms_normal > 0 else 0
score1   = 1.5 * inv_flag + 1.0 * ae_flag
print(f"    Fusion: inv={inv_flag} ae={ae_flag} score={score1:.1f} → {'ALERT' if score1>=1.5 else 'OK'}")

results['normal'] = {
    'ae_alarms': ae_alarms_normal, 'ae_alarm_pct': ae_alarms_normal/5,
    'inv_alarms': inv_alarms_normal, 'fusion_score': score1,
    'expected': 'no alert', 'pass': score1 < 1.5
}

# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 2: Phase 1 Only (no evasion)
# ═══════════════════════════════════════════════════════════════════════════════
separator("SCENARIO 2: Phase 1 Attack (MV101=CLOSED, P101=ON, no evasion)")
print("[*] Simulating attacked sensor readings for AE...")

# Under Phase 1: LIT101 drops, FIT101 goes to zero
# Take a normal window as starting point, then inject attack trajectory
attack_start_idx = 5000
ae_scores_phase1 = []
for i in range(100):
    window = csv_data[attack_start_idx:attack_start_idx+WINDOW].copy()
    # Simulate attack: FIT101→0, LIT101 drops linearly
    for j in range(WINDOW):
        window[j, 0] = max(250, window[0, 0] - (i + j) * 0.7)  # LIT101 drops
        window[j, 1] = 0.0  # FIT101 = 0 (valve closed)
    score = ae_score(ae, ae_mu, ae_sigma, window)
    ae_scores_phase1.append(score)

ae_alarms_phase1 = sum(1 for s in ae_scores_phase1 if s > ae_threshold)
ae_phase1_mean = np.mean(ae_scores_phase1)
ae_phase1_max  = np.max(ae_scores_phase1)
print(f"    AE MSE — mean={ae_phase1_mean:.6f}  max={ae_phase1_max:.6f}  threshold={ae_threshold:.6f}")
print(f"    AE alarms: {ae_alarms_phase1}/100 ({ae_alarms_phase1}%)")

# Invariant check — inject attack into simulator
with lock:
    TAG_STORE['HMI_MV101.Auto'] = False; TAG_STORE['HMI_MV101.Cmd'] = 1  # CLOSE
    # P101 stays ON (Auto=True, Cmd=2)
    TAG_STORE['HMI_P101.Auto'] = True; TAG_STORE['HMI_P101.Cmd'] = 2
time.sleep(2)

inv_phase1 = []
for _ in range(10):
    state, viols = read_invariants()
    inv_phase1.append(1 if viols else 0)
    if viols:
        print(f"    Invariant: {[v[0] for v in viols]}")
    time.sleep(0.5)

inv_alarms_phase1 = sum(inv_phase1)
print(f"    Invariant alarms: {inv_alarms_phase1}/10")

ae_flag  = 1 if ae_alarms_phase1 > 5 else 0
inv_flag = 1 if inv_alarms_phase1 > 0 else 0
score2   = 1.5 * inv_flag + 1.0 * ae_flag
print(f"    Fusion: inv={inv_flag} ae={ae_flag} score={score2:.1f} → {'ALERT' if score2>=1.5 else 'OK'}")

results['phase1'] = {
    'ae_alarms': ae_alarms_phase1, 'ae_alarm_pct': ae_alarms_phase1,
    'inv_alarms': inv_alarms_phase1, 'fusion_score': score2,
    'expected': 'ALERT (both fire)', 'pass': score2 >= 1.5
}

# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 3: Phase 1 + Phase 2 (adversarial evasion)
# ═══════════════════════════════════════════════════════════════════════════════
separator("SCENARIO 3: Phase 1 + Phase 2 (adversarial evasion)")

if adv is not None:
    print("[*] Applying adversarial perturbation to attacked windows...")

    ae_scores_evaded = []
    for i in range(100):
        window = csv_data[attack_start_idx:attack_start_idx+WINDOW].copy()
        # Simulate attack trajectory (same as Phase 1)
        for j in range(WINDOW):
            window[j, 0] = max(250, window[0, 0] - (i + j) * 0.7)
            window[j, 1] = 0.0

        # Apply adversarial perturbation to evade AE
        norm = (window - adv_mu) / adv_sigma
        x = torch.tensor(norm.flatten(), dtype=torch.float32).unsqueeze(0)
        with torch.no_grad():
            delta = adv(x)
            x_perturbed = x + delta

        # Score the perturbed input against the DEFENSE AE (not the adversarial one)
        with torch.no_grad():
            mse = float(((ae(x_perturbed) - x_perturbed)**2).mean())
        ae_scores_evaded.append(mse)

    ae_alarms_evaded = sum(1 for s in ae_scores_evaded if s > ae_threshold)
    ae_evaded_mean = np.mean(ae_scores_evaded)
    ae_evaded_max  = np.max(ae_scores_evaded)
    evasion_rate   = (100 - ae_alarms_evaded)
    print(f"    AE MSE — mean={ae_evaded_mean:.6f}  max={ae_evaded_max:.6f}  threshold={ae_threshold:.6f}")
    print(f"    AE alarms: {ae_alarms_evaded}/100 ({ae_alarms_evaded}%)")
    print(f"    Evasion rate: {evasion_rate}% (Paper #31 expects ~94%)")

    # Invariant still fires — attack state unchanged in simulator
    inv_phase2 = []
    for _ in range(10):
        _, viols = read_invariants()
        inv_phase2.append(1 if viols else 0)
        time.sleep(0.5)

    inv_alarms_phase2 = sum(inv_phase2)
    print(f"    Invariant alarms: {inv_alarms_phase2}/10 (Phase 2 cannot evade physics)")

    ae_flag  = 1 if ae_alarms_evaded > 5 else 0
    inv_flag = 1 if inv_alarms_phase2 > 0 else 0
    score3   = 1.5 * inv_flag + 1.0 * ae_flag
    print(f"    Fusion: inv={inv_flag} ae={ae_flag} score={score3:.1f} → {'ALERT' if score3>=1.5 else 'OK'}")

    results['phase1_2'] = {
        'ae_alarms': ae_alarms_evaded, 'ae_alarm_pct': ae_alarms_evaded,
        'ae_evasion_rate': evasion_rate,
        'inv_alarms': inv_alarms_phase2, 'fusion_score': score3,
        'expected': 'ALERT (invariant catches, AE evaded)', 'pass': score3 >= 1.5
    }
else:
    print("[!] adv_model.pt not found — skipping Phase 2 evasion test")
    print("    Train it with: python3 scripts/attack/phase2_spoof.py train --data assets/19-Feb-2026_0930_1735.csv")
    results['phase1_2'] = {'skipped': True, 'pass': None}

# Restore simulator to normal
with lock:
    TAG_STORE['HMI_MV101.Cmd'] = 2; TAG_STORE['HMI_MV101.Auto'] = True
    TAG_STORE['HMI_P101.Cmd']  = 2; TAG_STORE['HMI_P101.Auto']  = True

# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════
separator("SUMMARY")
print(f"""
  {'Scenario':<30s}  {'AE':<15s}  {'Invariant':<12s}  {'Fusion':<10s}  {'Result':<8s}
  {'─'*30}  {'─'*15}  {'─'*12}  {'─'*10}  {'─'*8}""")

for name, r in results.items():
    if r.get('skipped'):
        print(f"  {name:<30s}  {'SKIPPED':<15s}  {'SKIPPED':<12s}  {'SKIPPED':<10s}  {'N/A':<8s}")
        continue
    ae_str = f"{r['ae_alarms']} alarms" + (f" ({r.get('ae_evasion_rate','')}% evade)" if 'ae_evasion_rate' in r else '')
    inv_str = f"{r['inv_alarms']} alarms"
    fus_str = f"{r['fusion_score']:.1f}"
    status = '✓ PASS' if r['pass'] else '✗ FAIL'
    print(f"  {name:<30s}  {ae_str:<15s}  {inv_str:<12s}  {fus_str:<10s}  {status:<8s}")

print(f"""
  Expected behaviour:
    Normal:     AE clean, Invariant clean  → Fusion=0 (no alert)         → {'✓' if results['normal']['pass'] else '✗'}
    Phase 1:    AE fires, Invariant fires  → Fusion=2.5 (both detect)    → {'✓' if results['phase1']['pass'] else '✗'}
    Phase 1+2:  AE evaded, Invariant fires → Fusion=1.5 (hybrid catches) → {'✓' if results.get('phase1_2',{}).get('pass','?') else '✗' if results.get('phase1_2',{}).get('pass') is False else '?'}
""")

all_pass = all(r.get('pass', True) for r in results.values() if r.get('pass') is not None)
print(f"  Overall: {'✓ ALL SCENARIOS PASS' if all_pass else '✗ SOME SCENARIOS FAILED'}")
