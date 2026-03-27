# SWaT CPS Attack & Defense Project
**Course:** 51.508 Secure Cyber-Physical Systems — SUTD  
**Target:** SWaT Testbed (iTrust Lab), Stage P1 — Raw Water Intake  
**Papers:** #9 (Alsabbagh et al., IEEE CCNC 2023) + #31 (Castellanos et al., ACM ACSAC 2020)  
**Protocol:** EtherNet/IP / Allen-Bradley ControlLogix via pylogix  
**PLC1:** 192.168.1.10  |  **PLC1B:** 192.168.1.11

---

## Repository Structure

```
swat-cps-project/
├── slides/
│   ├── swat_with_images.pptx     ← MAIN DECK (40 slides, real lab photos)
│   └── swat_final_fixed.pptx     ← Previous version (no images)
├── scripts/
│   ├── README.md                  ← Usage guide + real tag names
│   ├── attack/
│   │   ├── phase0_recon.py        ← EtherNet/IP recon + tag discovery (pylogix)
│   │   ├── phase1_inject.py       ← ARP poison + false CIP tag injection
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
│   ├── 19-Feb-2026_0930_1735.csv  ← SWaT normal operation dataset (8.1 hrs)
│   ├── mssd_group02_mar26.py      ← Lab reference script (pylogix tag names)
│   └── images/                    ← SWaT testbed photos + diagrams
├── ae_model.pt                    ← Trained autoencoder (threshold=0.000950)
├── adv_model.pt                   ← Trained adversarial model (Paper #31)
├── swat_demo_runbook.docx         ← 19-page lab demo guide
└── swat_project_report.docx       ← 14-page project report
```

---

## Quick Start (Lab Day)

```bash
# Install dependencies (offline from thumb drive)
pip install pylogix scapy torch numpy pandas scikit-learn

# Test PLC connectivity
python3 -c "
from pylogix import PLC
with PLC() as plc:
    plc.IPAddress = '192.168.1.10'
    r = plc.Read('HMI_LIT101.Pv')
    print('LIT101:', r.Value, r.Status)
"

# Run defense monitors first (3 terminals)
python3 scripts/defense/invariant_checker.py --plc-ip 192.168.1.10
python3 scripts/defense/autoencoder_detector.py monitor --plc-ip 192.168.1.10 --model ae_model.pt
python3 scripts/defense/fusion.py

# Run attack (2 more terminals)
sudo python3 scripts/attack/phase1_inject.py --plc-ip 192.168.1.10 --hmi-ip <HMI_IP> --iface eth0
python3 scripts/attack/phase2_spoof.py attack --plc-ip 192.168.1.10
```

---

## Real SWaT P1 Tag Names

| Signal | Tag | Type |
|--------|-----|------|
| LIT101 level | `HMI_LIT101.Pv` | REAL (mm) |
| FIT101 flow | `AI_FIT_101_FLOW` | REAL (L/s) |
| MV101 valve cmd | `HMI_MV101.Cmd` | INT (1=CLOSE, 2=OPEN) |
| MV101 auto mode | `HMI_MV101.Auto` | BOOL |
| P101 pump auto | `HMI_P101.Auto` | BOOL |
| LIT101 sim enable | `HMI_LIT101.Sim` | BOOL |
| LIT101 sim value | `HMI_LIT101.Sim_PV` | REAL |

---

## References
- [1] Alsabbagh et al., "A Stealthy False Command Injection Attack on Modbus based SCADA Systems," IEEE CCNC 2023.
- [2] Castellanos et al., "Constrained Concealment Attacks against Reconstruction-based Anomaly Detectors in ICS," ACM ACSAC 2020.
- [3] Adepu & Mathur, "Using Process Invariants to Detect Cyber Attacks on a Water Treatment System," IFIP SEC 2016.
