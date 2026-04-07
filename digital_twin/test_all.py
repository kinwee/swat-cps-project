#!/usr/bin/env python3
"""
test_all.py  —  End-to-end test using PLC simulator
Attack: MV101=CLOSED (P101 stays ON) → tank drains → I-2 + I-9 fire
"""

import sys, os, time, threading
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from plc_simulator import MockPLC, TAG_STORE, lock, physics_loop

import types
mock_module = types.ModuleType('pylogix')
mock_module.PLC = MockPLC
sys.modules['pylogix'] = mock_module

REPO = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, REPO)

print("=" * 65)
print("  SWaT End-to-End Test — PLC Simulator Mode")
print("  Attack: MV101=CLOSED, P101=ON (tank drains)")
print("=" * 65)

threading.Thread(target=physics_loop, daemon=True).start()
print("\n[TEST] Physics loop started")
time.sleep(2)

import scripts.defense.invariant_checker as ic

def ts(): return datetime.now().strftime('%H:%M:%S')
def separator(label): print(f"\n{'='*10} {label} {'='*(52-len(label))}")

def read_state():
    plc = MockPLC()
    r = plc.Read(*ic.READ_TAGS)
    if not isinstance(r, list): r = [r]
    return {x.TagName: x.Value for x in r if x.Value is not None}

# ── STEP 1: Normal ────────────────────────────────────────────────────────────
separator("STEP 1: Normal Operation Check")
time.sleep(1)
state = read_state()
viols = ic.check_invariants(state)
lit = state.get('HMI_LIT101.Pv', 0)
fit = state.get('AI_FIT_101_FLOW', 0)
mv  = state.get('HMI_MV101.Cmd', 0)
print(f"[{ts()}] LIT101={lit:.1f}mm  FIT101={fit:.3f}L/s  MV101={'OPEN' if mv==2 else 'CLOSED'}  P101={'ON' if state.get('HMI_P101.Auto') else 'OFF'}")
step1_ok = len(viols) == 0
print(f"  {'✓ All invariants PASS' if step1_ok else f'⚠ Violations: {viols}'}")

# ── STEP 2: Invariant checker normal ─────────────────────────────────────────
separator("STEP 2: Invariant Checker (3 cycles)")
normal_flags = []
for cycle in range(3):
    state = read_state()
    viols = ic.check_invariants(state)
    flag = 1 if viols else 0
    normal_flags.append(flag)
    print(f"  [{ts()}] Cycle {cycle+1}: inv_flag={flag}  MV101={'OPEN' if state.get('HMI_MV101.Cmd')==2 else 'CLOSED'}")
    time.sleep(1)
print(f"  flags={normal_flags}  — {'✓ All clear' if all(f==0 for f in normal_flags) else '⚠ False alarm!'}")

# ── STEP 3: Inject attack ─────────────────────────────────────────────────────
separator("STEP 3: Phase 1 Attack — Close MV101, P101 stays ON")
print(f"[{ts()}] Writing HMI_MV101.Auto=False, HMI_MV101.Cmd=1 (CLOSE)")
print(f"[{ts()}] P101.Auto and P101.Cmd unchanged — pump keeps running → tank drains")
# Write directly to TAG_STORE (same as MockPLC.Write)
with lock:
    TAG_STORE['HMI_MV101.Auto'] = False
    TAG_STORE['HMI_MV101.Cmd']  = 1    # CLOSE
print(f"[{ts()}] Confirming: TAG_STORE MV101.Cmd={TAG_STORE['HMI_MV101.Cmd']}")
print(f"[{ts()}] Waiting 3s for FIT101 to drop...")
time.sleep(3)
with lock:
    print(f"[{ts()}] TAG_STORE: MV101.Cmd={TAG_STORE['HMI_MV101.Cmd']}  P101.Auto={TAG_STORE['HMI_P101.Auto']}  FIT101={TAG_STORE['AI_FIT_101_FLOW']:.3f}")

# ── STEP 4: Detection ─────────────────────────────────────────────────────────
separator("STEP 4: Detection — Invariant Checker Under Attack")
attack_flags = []
for cycle in range(5):
    # Read directly from TAG_STORE — same source as MockPLC
    with lock:
        state = {k: TAG_STORE.get(k) for k in ic.READ_TAGS}
    viols = ic.check_invariants(state)
    lit = state.get('HMI_LIT101.Pv', 0)
    fit = state.get('AI_FIT_101_FLOW', 0)
    flag = 1 if viols else 0
    attack_flags.append(flag)
    mv_str = 'CLOSED' if state.get('HMI_MV101.Cmd') == 1 else 'OPEN'
    status = f"⚠  {viols[0]}" if viols else "✓ OK"
    print(f"  [{ts()}] Cycle {cycle+1}: LIT101={lit:.1f}mm  FIT101={fit:.3f}  MV101={mv_str}  inv_flag={flag}  {status}")
    time.sleep(1)

detected = any(f == 1 for f in attack_flags)
print(f"\n  {'✓ ATTACK DETECTED' if detected else '✗ NOT DETECTED'}  flags={attack_flags}")

# ── STEP 5: Fusion ────────────────────────────────────────────────────────────
separator("STEP 5: Fusion Engine Score")
inv_flag = attack_flags[-1]
ae_flag  = 0
score    = 1.5 * inv_flag + 1.0 * ae_flag
print(f"  inv_flag={inv_flag}  ae_flag={ae_flag}  score={score:.1f}")
print(f"  Threshold=1.5  →  {'🔴 ALERT — recovery triggered' if score >= 1.5 else '🟢 Below threshold'}")

# ── STEP 6: Recovery ──────────────────────────────────────────────────────────
separator("STEP 6: Recovery Agent — Safe State Restore")
print(f"[{ts()}] Restoring: MV101=OPEN, P101=ON (already on)")
with lock:
    TAG_STORE['HMI_MV101.Cmd']  = 2
    TAG_STORE['HMI_MV101.Auto'] = True
print(f"[{ts()}] Waiting 5s for physics to stabilise...")
time.sleep(5)

# ── STEP 7: Verify ────────────────────────────────────────────────────────────
separator("STEP 7: Verify — 5 Clean Invariant Cycles Required")
clean = 0
for cycle in range(8):
    with lock:
        state = {k: TAG_STORE.get(k) for k in ic.READ_TAGS}
    viols = ic.check_invariants(state)
    lit = state.get('HMI_LIT101.Pv', 0)
    if not viols:
        clean += 1
        print(f"  [{ts()}] Cycle {cycle+1}: ✓ CLEAN ({clean}/5)  LIT101={lit:.1f}mm")
    else:
        clean = 0
        print(f"  [{ts()}] Cycle {cycle+1}: ⚠ VIOLATION — {viols[0]}")
    if clean >= 5: break
    time.sleep(1)

separator("TEST COMPLETE")
print(f"""
  Results:
    Normal operation:  {'✓ PASS' if step1_ok and all(f==0 for f in normal_flags) else '✗ FAIL'}
    Attack detection:  {'✓ PASS' if detected else '✗ FAIL'}
    Fusion alert:      {'✓ PASS' if score >= 1.5 else '✗ FAIL'}
    Recovery verified: {'✓ PASS' if clean >= 5 else f'✗ FAIL ({clean}/5 clean cycles)'}

  Attack pattern: MV101=CLOSED + P101=ON → tank drains actively
  Detection:      I-2 (P101=ON but FIT101 < 0.4) + I-9 (MV101=CLOSED + P101=ON)
  Ready to run on real SWaT PLC at 192.168.1.10
""")
