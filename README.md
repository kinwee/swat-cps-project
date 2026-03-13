# SWaT CPS Attack & Defense Project
**Course:** 51.508 Secure Cyber-Physical Systems — SUTD  
**Target:** SWaT Testbed (iTrust Lab), Stage P1 — Raw Water Intake  
**Papers:** #9 (Alsabbagh et al., IEEE CCNC 2023) + #31 (Castellanos et al., ACM ACSAC 2020)

---

## Repository Structure

```
swat-cps-project/
├── slides/
│   ├── swat_with_images.pptx     ← MAIN DECK (40 slides, with diagrams)
│   └── swat_final_fixed.pptx     ← Previous version (no images)
├── scripts/
│   ├── README.md                  ← Usage guide for all scripts
│   ├── attack/
│   │   ├── phase0_recon.py        ← Passive Modbus recon + NMAP scan
│   │   ├── phase1_inject.py       ← ARP poison + false command injection
│   │   └── phase2_spoof.py        ← Adversarial AE sensor spoofing (Paper #31)
│   ├── defense/
│   │   ├── invariant_checker.py   ← 8 P1 process invariants (Layer 1)
│   │   ├── autoencoder_detector.py← Reconstruction AE anomaly detector (Layer 2)
│   │   └── fusion.py              ← Weighted fusion engine (Layer 3)
│   └── recovery/
│       ├── recovery_agent.py      ← 5-step shallow recovery pipeline
│       ├── ode_estimator.py       ← ODE-based LIT101 prediction
│       ├── sse_observer.py        ← Luenberger secure state estimator
│       └── reentry_gate.py        ← Invariant-gated sensor re-entry
├── assets/
│   └── images/                    ← Drop real SWaT testbed photos here
└── swat_demo_runbook.docx         ← Step-by-step Week 13 demo guide (19 pages)
```

---

## Quick Start (iTrust Lab Only)

> ⚠️ Run only on the SWaT testbed at iTrust Lab with lab engineer present.

```bash
pip install pymodbus scapy torch numpy pandas scikit-learn

# Phase 0 — Recon
sudo python3 scripts/attack/phase0_recon.py --subnet 192.168.1.0/24 --iface eth0 --duration 1800

# Defense (start before attack)
sudo python3 scripts/defense/invariant_checker.py --plc-ip <PLC1_IP>
python3 scripts/defense/autoencoder_detector.py monitor --plc-ip <PLC1_IP> --model ae_model.pt
python3 scripts/defense/fusion.py --recovery-script scripts/recovery/recovery_agent.py

# Phase 1 — Attack
sudo python3 scripts/attack/phase1_inject.py --plc-ip <PLC1_IP> --hmi-ip <HMI_IP> --iface eth0 --db modbus_db.pkl --duration 120

# Phase 2 — ML Evasion
sudo python3 scripts/attack/phase2_spoof.py attack --plc-ip <PLC1_IP> --hmi-ip <HMI_IP> --iface eth0 --duration 120
```

---

## Pending Before Lab Session
- [ ] Fill `REGISTER_MAP` in `phase1_inject.py` with actual PLC1 register addresses
- [ ] Confirm Modbus TCP enabled on ControlLogix PLC1 (ask lab engineer)
- [ ] Download SWaT normal dataset and train autoencoder: `python3 scripts/defense/autoencoder_detector.py train --data swat_normal.csv`
- [ ] Book lab time: https://itrustestbed.simplybook.asia/v2/
- [ ] Add real SWaT testbed photos to `assets/images/`

---

## Presentation
- **Week 10:** Submit `slides/swat_with_images.pptx` as project proposal
- **Week 13:** Live demo at iTrust Lab — follow `swat_demo_runbook.docx`
