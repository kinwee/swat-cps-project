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
├── run_demo.py                    ← ONE-COMMAND DEMO (runs everything)
├── setup.sh                       ← One-command environment bootstrap (installs uv + deps)
├── pyproject.toml                 ← Project config for uv
├── .python-version                ← Pins Python 3.10
├── slides/swat_sutd.pptx          ← Main deck (49 slides, SUTD theme)
├── scripts/
│   ├── attack/
│   │   ├── phase1_inject.py       ← False CIP tag injection from HMI
│   │   └── phase2_spoof.py        ← Adversarial sensor spoofing (numpy inference)
│   ├── defense/
│   │   ├── invariant_checker.py   ← 9 P1 process invariants (Layer 1)
│   │   ├── autoencoder_detector.py← Reconstruction AE detector (numpy inference)
│   │   └── fusion.py              ← Weighted fusion engine (Layer 3)
│   └── recovery/
│       ├── recovery_agent.py      ← 5-step shallow recovery pipeline
│       ├── ode_estimator.py       ← ODE-based LIT101 state estimator
│       ├── sse_observer.py        ← Luenberger secure state estimator
│       └── reentry_gate.py        ← Invariant-gated sensor re-entry
├── digital_twin/
│   ├── ode_twin.py                ← Physics ODE model (auto-calibrated, RMSE=16mm)
│   ├── lstm_twin.py               ← LSTM for all 24 analog sensors
│   ├── dashboard.py               ← Live animated dashboard (gauges + ODE twin)
│   ├── plc_simulator.py           ← Mock pylogix PLC for local testing
│   ├── test_all.py                ← End-to-end pipeline test (4/4 PASS)
│   └── test_detectors.py          ← AE + invariant + fusion test (3/3 PASS)
├── assets/
│   ├── 19-Feb-2026_0930_1735.csv  ← Normal operation dataset (29,153 samples, 8.1 hrs)
│   ├── 20-Feb-2026_0905_1710.csv  ← Normal operation dataset (8.1 hrs)
│   ├── mssd_group02_mar26.py      ← Lab reference script (confirmed tag names)
│   └── images/                    ← SWaT testbed photos + diagrams
├── ae_model.npz                   ← Trained AE (threshold=0.000717, numpy format)
├── adv_model.npz                  ← Trained adversarial model (numpy format)
├── swat_project_report.docx       ← Project report
├── swat_lab_checklist.docx        ← Pre-run lab checklist
└── swat_demo_runbook.docx         ← Lab demo guide
```

---

## Quick Start (2 commands)

```bash
# 1. Bootstrap environment (installs uv + creates venv + installs deps)
bash setup.sh

# 2. Run the demo (everything automated — preflight, defense, attack, recovery, evidence)
uv run python3 run_demo.py --plc-ip 192.168.1.10 --duration 120
```

That's it. `setup.sh` installs `uv` if missing, creates a `.venv`, and installs `pylogix`, `numpy`, `pandas`. No PyTorch required on the HMI.

For training on Mac: `bash setup.sh --train` (adds PyTorch, matplotlib, scikit-learn).

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
| LIT101 sim value | `HMI_LIT101.Sim_Pv` | PLC1 | REAL |
| FIT101 sim enable | `HMI_FIT101.Sim` | PLC1 | BOOL |
| FIT101 sim value | `HMI_FIT101.Sim_PV` | PLC1 | REAL |

---

## Lab Day — One Command

```bash
# Full demo — attack + defense + recovery + evidence collection
uv run python3 run_demo.py --plc-ip 192.168.1.10 --duration 120

# Phase 1 only (no adversarial evasion)
uv run python3 run_demo.py --plc-ip 192.168.1.10 --duration 120 --skip-phase2
```

`run_demo.py` automatically:
1. Runs preflight checks (PLC connectivity, model files, sim tags off)
2. Saves pre-attack plant state snapshot
3. Starts all 3 defense layers (invariant checker, AE detector, fusion)
4. Waits 15s for clean baseline readings
5. Launches Phase 1 + Phase 2 attack
6. Monitors for invariant detection (logs time-to-detect)
7. Saves mid-attack and post-attack state snapshots
8. Waits for recovery to complete
9. Stops all processes and collects evidence
10. Generates summary report

Evidence saved to `evidence/demo_YYYYMMDD_HHMMSS/` with all logs, state snapshots, timeline, and summary.

Press Ctrl+C at any time to stop gracefully and save whatever evidence has been collected.

### Manual mode (5 terminals)

If you prefer to run each component separately:

```bash
# Terminal 3 — Layer 1: Invariant Checker
uv run python3 scripts/defense/invariant_checker.py --plc-ip 192.168.1.10

# Terminal 4 — Layer 2: Autoencoder Detector
uv run python3 scripts/defense/autoencoder_detector.py monitor \
    --plc-ip 192.168.1.10 --model ae_model.npz

# Terminal 5 — Layer 3: Fusion Engine
uv run python3 scripts/defense/fusion.py

# Terminal 1 — Phase 1: False command injection
uv run python3 scripts/attack/phase1_inject.py --plc-ip 192.168.1.10 --duration 120

# Terminal 2 — Phase 2: Adversarial sensor spoofing
uv run python3 scripts/attack/phase2_spoof.py attack \
    --plc-ip 192.168.1.10 --model adv_model.npz --duration 120
```

---

## Simulated Test Results (PLC Simulator)

### End-to-End Pipeline (test_all.py)
```
Normal operation:  ✓ PASS
Attack detection:  ✓ PASS  (I-2 + I-9 fire every cycle)
Fusion alert:      ✓ PASS  (score=1.5 → ALERT)
Recovery verified: ✓ PASS  (5/5 clean cycles in <12s)
```

### Detector Validation (test_detectors.py)
| Scenario | AE | Invariant | Fusion | Result |
|----------|-----|-----------|--------|--------|
| Normal (500 windows) | 0 alarms (0% FPR) | 0/10 | 0.0 | ✓ PASS |
| Phase 1 only | 85/100 alarms (85%) | 10/10 (I-2+I-9) | 2.5 | ✓ PASS |
| Phase 1+2 (adversarial) | Evaded in live, caught offline | 10/10 (I-2+I-9) | ≥1.5 | ✓ PASS |

### ODE Digital Twin (ode_twin.py)
| Metric | Normal | Under Attack |
|--------|--------|-------------|
| RMSE | 16mm | 21mm |
| Mean residual | 8mm | 106mm |
| Max residual | 153mm | 212mm |

AE threshold=0.000717 (95th percentile). Auto-calibrated from CSV data: rise=1.256 mm/s, fall=0.707 mm/s.

---

## Local Testing (no real PLC needed)

```bash
# Full end-to-end pipeline test
uv run python3 digital_twin/test_all.py

# Detector validation (AE + invariant + fusion, 3 scenarios)
uv run python3 digital_twin/test_detectors.py

# One-command demo against PLC simulator
uv run python3 run_demo.py --sim --duration 30

# ODE twin with simulated attack
uv run python3 digital_twin/ode_twin.py \
    --data assets/19-Feb-2026_0930_1735.csv --attack --attack-start 5000

# Live dashboard
uv run python3 digital_twin/dashboard.py \
    --data assets/19-Feb-2026_0930_1735.csv --speed 5 --attack 5000
```

---

## Retraining Models (Mac only — requires `bash setup.sh --train`)

```bash
# Retrain AE detector → saves ae_model.npz
uv run python3 scripts/defense/autoencoder_detector.py train \
    --data assets/19-Feb-2026_0930_1735.csv --save ae_model.npz --epochs 500

# Retrain adversarial encoder → saves adv_model.npz
uv run python3 scripts/attack/phase2_spoof.py train \
    --data assets/19-Feb-2026_0930_1735.csv --model adv_model.npz --epochs 500
```

Copy the `.npz` files to the HMI via USB. No retraining needed on the HMI.

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
| I-7 | P101=OFF + MV101=CLOSED | FIT101 ≈ 0 | Phantom flow |
| I-8 | Always | FIT101 ≤ 2.0 L/s | Pipe capacity |
| I-9 ★ | MV101=CLOSED + P101=ON | LIT101 in 300–850mm → VIOLATION | **Phase 1 attack signature** |

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

## Recovery Pipeline (recovery_agent.py)

Auto-launched by fusion.py when score ≥ 1.5 for 3 consecutive cycles.

| Step | Action | Detail |
|------|--------|--------|
| 1 DETECT | Log incident | Writes timestamp + state to `recovery_log.json` |
| 2 CONTAIN | Block attacker | iptables DROP port 44818 |
| 3 SAFE STATE | Restore actuators | MV101=OPEN, P101=OFF (Auto=False → Cmd → Auto=True) |
| 4 FAILOVER | Write to PLC1B | Same safe state to redundant PLC at 192.168.1.11 |
| 5 VERIFY | Confirm clean | 5 consecutive clean invariant cycles required |

---

## References
- [1] Alsabbagh et al., "A Stealthy False Command Injection Attack on Modbus based SCADA Systems," IEEE CCNC 2023.
- [2] Castellanos et al., "Constrained Concealment Attacks against Reconstruction-based Anomaly Detectors in ICS," ACM ACSAC 2020.
- [3] Adepu & Mathur, "Using Process Invariants to Detect Cyber Attacks on a Water Treatment System," IFIP SEC 2016.
