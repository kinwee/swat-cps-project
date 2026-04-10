# SWaT Attack & Defense Scripts

**Protocol:** EtherNet/IP / Allen-Bradley ControlLogix  
**Library:** pylogix (confirmed from lab reference script)  
**Inference:** Pure numpy (no PyTorch required on HMI)  
**PLC1:** 192.168.1.10  |  **PLC1B:** 192.168.1.11

## HMI Dependencies
```bash
pip install pylogix numpy pandas
```

Training (Mac only) additionally requires: `pip install torch scikit-learn`

## Real SWaT P1 Tag Names (confirmed from lab)
| Signal | Tag | Type |
|--------|-----|------|
| LIT101 level | `HMI_LIT101.Pv` | REAL (mm) |
| FIT101 flow | `AI_FIT_101_FLOW` | REAL (L/s) |
| MV101 valve cmd | `HMI_MV101.Cmd` | INT (1=CLOSE, 2=OPEN) |
| MV101 auto mode | `HMI_MV101.Auto` | BOOL |
| P101 auto mode | `HMI_P101.Auto` | BOOL |
| LIT101 sim enable | `HMI_LIT101.Sim` | BOOL |
| LIT101 sim value | `HMI_LIT101.Sim_PV` | REAL |

## Attack Scripts
```bash
# Phase 1: Direct CIP tag injection (no ARP/sudo needed)
python3 attack/phase1_inject.py --plc-ip 192.168.1.10 --duration 120

# Phase 2: Adversarial AE sensor spoofing via Sim tags (numpy inference)
python3 attack/phase2_spoof.py attack --plc-ip 192.168.1.10 --model ../../adv_model.npz --duration 120
```

## Defense Scripts
```bash
# Layer 1: Process invariant checker
python3 defense/invariant_checker.py --plc-ip 192.168.1.10

# Layer 2: Reconstruction AE anomaly detector (numpy inference)
python3 defense/autoencoder_detector.py monitor --plc-ip 192.168.1.10 --model ../../ae_model.npz

# Layer 3: Decision fusion (auto-triggers recovery)
python3 defense/fusion.py
```

## Recovery Scripts
```bash
python3 recovery/recovery_agent.py --plc-ip 192.168.1.10 --plc-b-ip 192.168.1.11
```

## Retraining (Mac — requires PyTorch)
```bash
# AE detector
python3 defense/autoencoder_detector.py train --data ../../assets/19-Feb-2026_0930_1735.csv --save ../../ae_model.npz --epochs 500

# Adversarial encoder
python3 attack/phase2_spoof.py train --data ../../assets/19-Feb-2026_0930_1735.csv --model ../../adv_model.npz --epochs 500
```

Copy `.npz` files to HMI via USB. No PyTorch needed on the HMI.
