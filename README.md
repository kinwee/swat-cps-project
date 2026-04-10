# SWaT CPS Attack & Defense Project
**Course:** 51.508 Secure Cyber-Physical Systems — SUTD  
**Target:** SWaT Testbed (iTrust Lab), Stage P1 — Raw Water Intake  
**Papers:** #9 (Alsabbagh et al., IEEE CCNC 2023) + #31 (Castellanos et al., ACM ACSAC 2020)  
**Protocol:** EtherNet/IP / Allen-Bradley ControlLogix via pylogix  
**PLC1:** 192.168.1.10  |  **PLC1B:** 192.168.1.11  |  **PLC2:** 192.168.1.20

---

## Repository Structure

```
swat-cps-project/
├── slides/swat_sutd.pptx          ← MAIN DECK (49 slides, SUTD theme)
├── scripts/
│   ├── attack/
│   │   ├── phase1_inject.py       ← False CIP tag injection (PLC1 + PLC2)
│   │   └── phase2_spoof.py        ← Adversarial AE sensor spoofing (Paper #31)
│   ├── defense/
│   │   ├── invariant_checker.py   ← 9 P1 process invariants (Layer 1)
│   │   ├── autoencoder_detector.py← Reconstruction AE anomaly detector (Layer 2)
│   │   └── fusion.py              ← Weighted fusion engine (Layer 3)
│   └── recovery/
│       ├── recovery_agent.py      ← 5-step shallow recovery pipeline
│       ├── ode_estimator.py       ← ODE-based LIT101 state estimator
│       ├── sse_observer.py        ← Luenberger secure state estimator
│       └── reentry_gate.py        ← Invariant-gated sensor re-entry
├── digital_twin/
│   ├── dashboard.py               ← Live animated dashboard (P1 P&ID + gauges)
│   ├── ode_twin.py                ← Physics ODE model for LIT101
│   ├── lstm_twin.py               ← LSTM for all 24 analog sensors
│   ├── plc_simulator.py           ← Mock pylogix PLC for local testing
│   └── test_all.py                ← End-to-end test (all 4 PASS)
├── assets/
│   ├── 19-Feb-2026_0930_1735.csv  ← Normal operation dataset (8.1 hrs)
│   ├── 20-Feb-2026_0905_1710.csv  ← Normal operation dataset (8.1 hrs)
│   ├── mssd_group02_mar26.py      ← Lab reference script (confirmed tag names)
│   └── images/                    ← SWaT testbed photos + diagrams
├── ae_model.pt                    ← Trained autoencoder (threshold=0.000950)
├── adv_model.pt                   ← Trained adversarial model (Paper #31)
├── swat_project_report.docx       ← Project report
├── swat_lab_checklist.docx        ← Pre-run lab checklist
└── swat_demo_runbook.docx         ← Lab demo guide
```

---

## Real SWaT Tag Names (confirmed on lab hardware)

| Signal | Tag | PLC | Type |
|--------|-----|-----|------|
| LIT101 level | `HMI_LIT101.Pv` | PLC1 | REAL (mm) |
| FIT101 flow | `AI_FIT_101_FLOW` | PLC1 | REAL (L/s) |
| MV101 valve cmd | `HMI_MV101.Cmd` | PLC1 | INT (1=CLOSE, 2=OPEN) |
| MV101 auto mode | `HMI_MV101.Auto` | PLC1 | BOOL |
| P101 pump auto | `HMI_P101.Auto` | PLC1 | BOOL |
| P101 pump cmd | `HMI_P101.Cmd` | PLC1 | INT (1=OFF, 2=ON) |
| LIT101 sim enable | `HMI_LIT101.Sim` | PLC1 | BOOL |
| LIT101 sim value | `HMI_LIT101.Sim_Pv` | PLC1 | REAL (lowercase v) |
| FIT101 sim enable | `AI_FIT_101_FLOW.Sim` | PLC1 | BOOL |
| FIT101 sim value | `AI_FIT_101_FLOW.Sim_PV` | PLC1 | REAL (uppercase PV) |
| MV201 valve cmd | `HMI_MV201.Cmd` | PLC2 | INT (1=CLOSE, 2=OPEN) |
| MV201 auto mode | `HMI_MV201.Auto` | PLC2 | BOOL |

---

## Lab Day — Step by Step

### 1. Dependencies
```bash
pip install pylogix torch numpy pandas scikit-learn matplotlib Pillow
```

### 2. Connectivity Check
```bash
python3 -c "
from pylogix import PLC
with PLC() as plc:
    plc.IPAddress = '192.168.1.10'
    tags = ['HMI_LIT101.Pv', 'AI_FIT_101_FLOW',
            'HMI_MV101.Cmd', 'HMI_P101.Auto',
            'HMI_LIT101.Sim', 'HMI_LIT101.Sim_Pv',
            'AI_FIT_101_FLOW.Sim', 'AI_FIT_101_FLOW.Sim_PV']
    for t in tags:
        r = plc.Read(t)
        print(f'{t:35s} = {r.Value}  [{r.Status}]')
"
```

### 3. Start Defense (terminals 3, 4, 5 — start BEFORE attack)
```bash
# Terminal 3 — Layer 1: Invariant Checker
python3 scripts/defense/invariant_checker.py --plc-ip 192.168.1.10

# Terminal 4 — Layer 2: Autoencoder Detector
python3 scripts/defense/autoencoder_detector.py monitor \
    --plc-ip 192.168.1.10 --model ae_model.pt

# Terminal 5 — Layer 3: Fusion Engine (auto-triggers recovery on ALERT)
python3 scripts/defense/fusion.py
```

Wait for all 3 to show clean readings (inv_flag=0, MSE below threshold).

### 4. Run Attack (terminals 1 and 2)
```bash
# Terminal 1 — Phase 1: False command injection
# PLC1: P101 ON (manual), MV101 CLOSED
# PLC2: MV201 OPEN
python3 scripts/attack/phase1_inject.py \
    --plc-ip 192.168.1.10 \
    --plc2-ip 192.168.1.20 \
    --duration 120

# Terminal 2 — Phase 2: Adversarial sensor spoofing (evades AE detector)
python3 scripts/attack/phase2_spoof.py attack \
    --plc-ip 192.168.1.10 \
    --model adv_model.pt \
    --duration 120
```

### 5. What to Observe
| Terminal | Expected |
|----------|----------|
| 4 (AE) | MSE stays below threshold — **fooled by Phase 2** |
| 3 (Invariant) | I-2 + I-9 fire within 6 seconds; if PLC failover to P102 occurs, I-9b + I-9c continue firing |
| 5 (Fusion) | score=1.5 → ALERT → recovery auto-launches |
| 1 (Phase 1) | LIT101 dropping, MV101=CLOSED, MV201=OPEN |

---

## Local Testing (no real PLC needed)
```bash
# Run full end-to-end test against PLC simulator
python3 digital_twin/test_all.py

# Expected output:
#   Normal operation:  ✓ PASS
#   Attack detection:  ✓ PASS
#   Fusion alert:      ✓ PASS
#   Recovery verified: ✓ PASS

# Live dashboard
python3 digital_twin/dashboard.py \
    --data assets/19-Feb-2026_0930_1735.csv --speed 5
```

---

## 9 Invariant Rules (Layer 1)

| ID | Condition | Rule | Catches |
|----|-----------|------|---------|
| I-1 | MV101=OPEN | FIT101 > 0.4 L/s | No flow with open valve |
| I-2 | P101.Auto=True | FIT101 > 0.4 L/s | Pump running but no flow |
| I-3 | LIT101 > 800mm | MV101 not OPEN | Overflow protection |
| I-4 | LIT101 < 250mm | P101 not ON | Dry-run protection |
| I-5 | LIT101 < 250mm | MV101 not CLOSED | Refill required |
| I-6 | Always | P101 and P102 not both ON | Backup pump logic |
| I-7 | P101=OFF + MV101=CLOSED | FIT101 ~0 | Phantom flow |
| I-8 | Always | FIT101 ≤ 2.0 L/s | Pipe capacity |
| I-9 ★ | MV101=CLOSED + P101.Auto=True | LIT101 in 300–850mm → VIOLATION | **Phase 1 direct signature** |
| I-9b | MV101=CLOSED + P102.Auto=True | LIT101 in 300–850mm → VIOLATION | Attack ongoing after PLC failover to backup pump |
| I-9c | MV101=CLOSED + FIT101 < 0 | LIT101 in 300–850mm → VIOLATION | Negative flow = sensor anomaly under attack |

---

## Recovery Pipeline (recovery_agent.py)

Auto-launched by fusion.py when score ≥ 1.5 for 3 consecutive cycles.

| Step | Action | Detail |
|------|--------|--------|
| 1 DETECT | Log incident | Writes timestamp + state to `recovery_log.json` |
| 2 CONTAIN | Block attacker | iptables DROP port 44818 (only if `--attacker-ip` passed) |
| 3 SAFE STATE | Restore actuators | PLC1: MV101=OPEN + P101=ON (auto); PLC2: MV201=CLOSED (auto) |
| 4 FAILOVER | Write to PLC1B | Same safe state written to redundant PLC at 192.168.1.11 |
| 5 VERIFY | Confirm clean | 5 consecutive clean invariant cycles required |

```bash
# Manual run (fusion.py auto-launches this)
python3 scripts/recovery/recovery_agent.py     --plc-ip 192.168.1.10     --plc2-ip 192.168.1.20     --plc-b-ip 192.168.1.11
```

---

## PLC Failover Behaviour (observed on real SWaT)

During the attack, the PLC's own safety logic may detect the abnormal state and automatically switch from P101 (primary pump) to P102 (backup pump):
- `P101.Auto` flips to `False`
- `P102.Auto` flips to `True`

This breaks I-2 and I-9 (which check P101.Auto) but **I-9b and I-9c continue firing** because:
- I-9b: MV101 is still CLOSED while P102 is now running
- I-9c: FIT101 reads -28 (invalid/backpressure) while MV101 is CLOSED

LIT101 continues dropping even after failover — the root cause (MV101 CLOSED) is unchanged.

---

## Fusion Scoring

```
score = 1.5 × inv_flag + 1.0 × ae_flag
ALERT if score ≥ 1.5 for 3 consecutive cycles
```

| inv_flag | ae_flag | score | Result |
|----------|---------|-------|--------|
| 0 | 0 | 0.0 | All clear |
| 0 | 1 | 1.0 | AE suspicious — monitor |
| 1 | 0 | 1.5 | **ALERT** — recovery triggered |
| 1 | 1 | 2.5 | **ALERT** — high confidence |

---

## References
- [1] Alsabbagh et al., "A Stealthy False Command Injection Attack on Modbus based SCADA Systems," IEEE CCNC 2023.
- [2] Castellanos et al., "Constrained Concealment Attacks against Reconstruction-based Anomaly Detectors in ICS," ACM ACSAC 2020.
- [3] Adepu & Mathur, "Using Process Invariants to Detect Cyber Attacks on a Water Treatment System," IFIP SEC 2016.

---

## Pre-Run Checklist (run through this before every demo)

### 1. Connectivity — confirm both PLCs reachable
```bash
python3 -c "
from pylogix import PLC
for ip in ['192.168.1.10', '192.168.1.20', '192.168.1.11']:
    with PLC() as plc:
        plc.IPAddress = ip
        r = plc.Read('HMI_LIT101.Pv') if ip == '192.168.1.10' else plc.Read('HMI_MV201.Cmd')
        print(f'{ip}  {r.Status}  val={r.Value}')
"
```
**Expected:** all 3 return `Success`

---

### 2. Tag names — confirm all confirmed tags read correctly
```bash
python3 -c "
from pylogix import PLC
with PLC() as plc:
    plc.IPAddress = '192.168.1.10'
    tags = [
        'HMI_LIT101.Pv',
        'AI_FIT_101_FLOW',
        'HMI_MV101.Cmd',
        'HMI_MV101.Auto',
        'HMI_P101.Auto',
        'HMI_P101.Cmd',
        'HMI_LIT101.Sim',
        'HMI_LIT101.Sim_Pv',
        'AI_FIT_101_FLOW.Sim',
        'AI_FIT_101_FLOW.Sim_PV',
    ]
    for t in tags:
        r = plc.Read(t)
        print(f'{t:35s} = {r.Value}  [{r.Status}]')
"
```
**Expected:** all return `Success` with real values (not None)

---

### 3. Plant state — confirm normal before attack
```bash
python3 -c "
from pylogix import PLC
with PLC() as plc:
    plc.IPAddress = '192.168.1.10'
    lit = plc.Read('HMI_LIT101.Pv').Value
    mv1 = plc.Read('HMI_MV101.Cmd').Value
    p1a = plc.Read('HMI_P101.Auto').Value
    fit = plc.Read('AI_FIT_101_FLOW').Value
    sim = plc.Read('HMI_LIT101.Sim').Value
    print(f'LIT101  = {lit:.1f}mm   (should be 300-850mm)')
    print(f'MV101   = {mv1}         (should be 2=OPEN)')
    print(f'P101    = {p1a}         (should be True=auto)')
    print(f'FIT101  = {fit:.3f}     (should be > 0)')
    print(f'Sim     = {sim}         (should be False)')
"
```
**Expected:** LIT101 in range, MV101=2, P101=True, Sim=False

---

### 4. MV201 state on PLC2
```bash
python3 -c "
from pylogix import PLC
with PLC() as plc:
    plc.IPAddress = '192.168.1.20'
    mv2 = plc.Read('HMI_MV201.Cmd').Value
    mv2a = plc.Read('HMI_MV201.Auto').Value
    print(f'MV201.Cmd  = {mv2}    (should be 1=CLOSED)')
    print(f'MV201.Auto = {mv2a}   (should be True)')
"
```
**Expected:** MV201=1 (CLOSED), Auto=True

---

### 5. Model files present
```bash
ls -lh ae_model.pt adv_model.pt
```
**Expected:** both files present, non-zero size

---

### 6. Confirm model loads correctly
```bash
python3 -c "
import torch
ckpt = torch.load('adv_model.pt', map_location='cpu')
print('feat_cols:', ckpt['feat_cols'])
print('input_dim:', ckpt['input_dim'])
print('window:   ', ckpt['window'])
"
```
**Expected:** feat_cols = `['HMI_LIT101.Pv', 'AI_FIT_101_FLOW']`

---

### 7. Dependencies installed
```bash
python3 -c "
import pylogix, torch, numpy, pandas, sklearn
print('pylogix', pylogix.__version__)
print('torch  ', torch.__version__)
print('numpy  ', numpy.__version__)
print('pandas ', pandas.__version__)
print('All OK')
"
```

---

### 8. Logs directory writable
```bash
mkdir -p logs && touch logs/test.log && echo "logs dir OK" && rm logs/test.log
```

---

### 9. Sim tags are OFF (no leftover simulation from previous run)
```bash
python3 -c "
from pylogix import PLC
with PLC() as plc:
    plc.IPAddress = '192.168.1.10'
    for t in ['HMI_LIT101.Sim', 'AI_FIT_101_FLOW.Sim']:
        r = plc.Read(t)
        print(f'{t:30s} = {r.Value}')
        if r.Value == True:
            plc.Write(t, False)
            print(f'  *** Sim was ON — disabled')
"
```
**Expected:** both False. If True, script disables them automatically.

---

### 10. Open 5 terminals and confirm paths
```bash
# In each terminal, confirm you are in the right directory
cd ~/swat-cps-project
ls scripts/defense/ scripts/attack/ scripts/recovery/
```

---

### Quick go/no-go summary
| Check | Command | Pass condition |
|-------|---------|---------------|
| PLC1 reachable | Read HMI_LIT101.Pv | Status=Success |
| PLC2 reachable | Read HMI_MV201.Cmd | Status=Success |
| LIT101 in range | Read HMI_LIT101.Pv | 300–850mm |
| MV101 open | Read HMI_MV101.Cmd | Value=2 |
| P101 in auto | Read HMI_P101.Auto | Value=True |
| MV201 closed | Read HMI_MV201.Cmd | Value=1 |
| Sim tags off | Read HMI_LIT101.Sim | Value=False |
| Models present | ls ae_model.pt adv_model.pt | Both exist |
| feat_cols correct | torch.load adv_model.pt | ['HMI_LIT101.Pv', 'AI_FIT_101_FLOW'] |
| logs writable | mkdir logs | No error |

**All 10 must pass before running the demo.**
