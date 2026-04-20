# SWaT CPS Attack & Defense Project
**Course:** 51.508 Secure Cyber-Physical Systems — SUTD  
**Target:** SWaT Testbed (iTrust Lab), Stage P1 — Raw Water Intake  
**Papers:** #9 (Alsabbagh et al., IEEE CCNC 2023) + #31 (Castellanos et al., ACM ACSAC 2020)  
**Protocol:** EtherNet/IP / Allen-Bradley ControlLogix via pylogix  
**PLC1:** 192.168.1.10  |  **PLC1B:** 192.168.1.11  |  **PLC2:** 192.168.1.20

---

## Quick Start (Lab Day)

```bash
# 1. Setup (once — installs uv + creates venv + installs deps)
cd ~/Desktop/Group\ 2/swat-cps-project
git pull
bash setup.sh

# 2. Run full demo (one command — everything automated)
uv run python3 run_demo.py --plc-ip 192.168.1.10 --once --duration 60
```

Evidence saved to `evidence/demo_YYYYMMDD_HHMMSS/`

---

## All Commands Reference

### Full Demo (automated)
```bash
# Single-shot attack + defence + recovery (recommended for clean results)
uv run python3 run_demo.py --plc-ip 192.168.1.10 --once --duration 60

# Continuous attack + Phase 2 adversarial spoofing
uv run python3 run_demo.py --plc-ip 192.168.1.10 --duration 120

# Phase 1 only (no Phase 2 sensor spoofing)
uv run python3 run_demo.py --plc-ip 192.168.1.10 --once --skip-phase2 --duration 60

# Simulator mode (no real PLC needed)
uv run python3 run_demo.py --sim --duration 30
```

### Attack Only (manual)
```bash
# Single-shot: write attack commands once and exit
uv run python3 scripts/attack/phase1_inject.py --plc-ip 192.168.1.10 --once

# Continuous: keep writing attack commands for 120s
uv run python3 scripts/attack/phase1_inject.py --plc-ip 192.168.1.10 --duration 120

# Phase 2: adversarial sensor spoofing via Sim tags
uv run python3 scripts/attack/phase2_spoof.py attack \
    --plc-ip 192.168.1.10 --model adv_model.npz --duration 120
```

### Defence Only (manual — run each in a separate terminal)
```bash
# Terminal 1 — Layer 1: Invariant Checker
uv run python3 scripts/defense/invariant_checker.py --plc-ip 192.168.1.10

# Terminal 2 — Layer 2: Autoencoder Detector (LIT101-only, numpy)
uv run python3 scripts/defense/autoencoder_detector.py monitor \
    --plc-ip 192.168.1.10 --model ae_model.npz

# Terminal 3 — Layer 3: Fusion Engine (auto-triggers recovery)
uv run python3 scripts/defense/fusion.py
```

### Recovery Only (manual)
```bash
uv run python3 scripts/recovery/recovery_agent.py \
    --plc-ip 192.168.1.10 --plc2-ip 192.168.1.20 --plc-b-ip 192.168.1.11
```

### Local Testing (no real PLC)
```bash
# End-to-end pipeline test (4/4 PASS)
uv run python3 digital_twin/test_all.py

# Detector validation — 3 scenarios (3/3 PASS)
uv run python3 digital_twin/test_detectors.py

# ODE twin with simulated attack
uv run python3 digital_twin/ode_twin.py \
    --data assets/19-Feb-2026_0930_1735.csv --attack --attack-start 5000
```

### Retraining Models (Mac only — needs `bash setup.sh --train`)
```bash
# Retrain AE detector (LIT101-only)
uv run python3 scripts/defense/autoencoder_detector.py train \
    --data assets/19-Feb-2026_0930_1735.csv --save ae_model.npz --epochs 500

# Retrain adversarial encoder
uv run python3 scripts/attack/phase2_spoof.py train \
    --data assets/19-Feb-2026_0930_1735.csv --model adv_model.npz --epochs 500
```

---

## What to Expect During Demo

### `--once` mode (recommended):
```
[PREFLIGHT]     Model files found, PLC reachable
[BASELINE CHECK] Validating plant state...
  ✓ LIT101 = 650mm (normal range)
  ✓ MV101 = OPEN (Cmd=2)
  ✓ FIT101 ≥ 0
  ✓ Sim tags OFF
  ✓ All invariants pass
[PHASE]         Starting defence layers (15s baseline)
[BASELINE]      Defence clean — ready for attack
[PHASE]         Launching attack (SINGLE-SHOT)
  → MV101.Auto=False, MV101.Cmd=1 (CLOSE) — written once, exits
[DETECTED]      Invariant violation at T+1.0s (I-2 + I-9)
[FUSION ALERT]  score=1.5 at T+4.0s (3 consecutive cycles)
[RECOVERY]      Safe state written — MV101=OPEN, P101=OFF
[RECOVERED]     Invariants clean again at T+15.0s
[DEMO COMPLETE] Evidence saved to evidence/demo_YYYYMMDD_HHMMSS/
```

### What to observe:
| What | Expected |
|------|----------|
| Invariant checker | I-2 + I-9 fire within 1 cycle |
| AE detector | MSE rises above 0.000738 threshold |
| Fusion score | 1.5 → ALERT (invariant alone is enough) |
| Recovery | MV101 restored to OPEN, Sim disabled |
| Physical plant | Tank was draining, stops after recovery |

---

## Troubleshooting

### FIT101 = -31 (sensor fault)
The AE is trained on LIT101 only — FIT101 doesn't affect it. The invariant checker will fire I-9c (sensor fault under closed valve) but this is a true positive. Baseline validation will warn you but won't block the demo.

### Plant not in safe state
The baseline validator auto-fixes what it can (MV101, Sim tags). If LIT101 is out of range or FIT101 is faulty, it tells you exactly what to fix manually.

### Model files corrupted
```bash
rm ae_model.npz adv_model.npz
git checkout -- ae_model.npz adv_model.npz
file ae_model.npz adv_model.npz
# Both should say: Zip archive data
```

### Recovery doesn't hold (continuous mode)
This is the write race — Phase 1 keeps overwriting MV101=CLOSED. Use `--once` mode instead, or note it as a finding (containment step needs architectural separation).

---

## Repository Structure

```
swat-cps-project/
├── run_demo.py                    ← ONE-COMMAND DEMO (runs everything)
├── setup.sh                       ← Environment bootstrap (installs uv + deps)
├── pyproject.toml                 ← Project config for uv
├── ae_model.npz                   ← Trained AE (LIT101-only, threshold=0.000738)
├── adv_model.npz                  ← Trained adversarial model (numpy)
├── scripts/
│   ├── attack/
│   │   ├── phase1_inject.py       ← CIP tag injection (--once or --duration)
│   │   └── phase2_spoof.py        ← Adversarial sensor spoofing (baseline-anchored)
│   ├── defense/
│   │   ├── invariant_checker.py   ← 9 P1 process invariants (I-1 to I-9)
│   │   ├── autoencoder_detector.py← LIT101-only reconstruction AE (numpy)
│   │   └── fusion.py              ← Weighted fusion (1.5×inv + 1.0×ae)
│   └── recovery/
│       ├── recovery_agent.py      ← 5-step recovery pipeline
│       ├── ode_estimator.py       ← ODE-based state estimator
│       ├── sse_observer.py        ← Luenberger secure state estimator
│       └── reentry_gate.py        ← Invariant-gated sensor re-entry
├── digital_twin/
│   ├── ode_twin.py                ← Physics ODE model (RMSE=16mm)
│   ├── plc_simulator.py           ← Mock PLC for local testing
│   ├── test_all.py                ← End-to-end test (4/4 PASS)
│   └── test_detectors.py          ← Detector validation (3/3 PASS)
├── assets/
│   ├── 19-Feb-2026_0930_1735.csv  ← Normal operation data (29,153 samples)
│   └── demo_20260416_163307/      ← Live demo evidence (16 Apr 2026)
├── slides/swat_sutd.pptx          ← Presentation (55 slides)
├── swat_project_report.docx       ← Project report
└── evidence/                      ← Auto-generated demo evidence folders
```

---

## Simulated Test Results

### End-to-End Pipeline (test_all.py): 4/4 PASS
| Step | Result |
|------|--------|
| Normal operation | ✓ All invariants clean |
| Attack detection | ✓ I-2 + I-9 fired cycle 1 |
| Fusion alert | ✓ score=1.5 → ALERT |
| Recovery verified | ✓ 5/5 clean cycles, <12s |

### Detector Validation (test_detectors.py): 3/3 PASS
| Scenario | AE (LIT-only) | Invariant | Fusion | Result |
|----------|---------------|-----------|--------|--------|
| Normal (500 windows) | 0 alarms (0.0% FPR) | 0/10 | 0.0 | ✓ PASS |
| Phase 1 only | 94/100 (94%) | 10/10 (I-2+I-9) | 2.5 | ✓ PASS |
| Phase 1+2 adversarial | Invariant catches regardless | 10/10 | 2.5 | ✓ PASS |

### ODE Digital Twin
| Metric | Normal | Under Attack |
|--------|--------|-------------|
| RMSE | 16mm | 21mm |
| Mean residual | 8mm | 106mm |
| Max residual | 153mm | 212mm |

---

## Key Findings

1. **Invariant detection in 1 cycle** — I-2 + I-9 fire immediately, immune to sensor spoofing
2. **AE 94% detection rate** on LIT101-only (no FIT101 dependency)
3. **0% false positive rate** on 29,153 samples of real SWaT data
4. **Fusion ALERT in 3s** — exact match with design specification
5. **Phase 2 concealment** — adversarial perturbation now baseline-anchored (±7mm, not drifting)
6. **Single-shot attack** — more realistic, eliminates write race with recovery
7. **Recovery in <12s** on simulator, holds when attacker exits (--once mode)
