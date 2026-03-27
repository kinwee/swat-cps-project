# SWaT Attack & Defense Scripts

**Protocol: EtherNet/IP over TCP port 44818 (Allen-Bradley ControlLogix)**
**Library: pycomm3 (CIP tag read/write)**

## Dependencies
```bash
pip install pycomm3 scapy torch numpy pandas scikit-learn
```

## Tag paths (confirm with lab engineer before running)
| Signal | Tag path | Type |
|--------|----------|------|
| MV101 (valve) | `HMI_MV101:O.Data` | BOOL |
| P101 (pump) | `HMI_P101:O.Data` | BOOL |
| P102 (standby) | `HMI_P102:O.Data` | BOOL |
| LIT101 (level) | `HMI_LIT101:I.Data` | REAL (mm) |
| FIT101 (flow) | `HMI_FIT101:I.Data` | REAL (L/s) |

## Attack
```bash
# Phase 0: recon + tag DB
sudo python3 attack/phase0_recon.py --plc-ip <IP> --iface eth0 --duration 1800

# Phase 1: ARP poison + false CIP tag writes
sudo python3 attack/phase1_inject.py --plc-ip <PLC1A_IP> --hmi-ip <HMI_IP> \
    --iface eth0 --db enip_db.pkl --duration 120

# Phase 2: adversarial ML evasion
python3 attack/phase2_spoof.py train  --data swat_normal.csv
python3 attack/phase2_spoof.py attack --plc-ip <IP> --duration 120
```

## Defense
```bash
python3 defense/invariant_checker.py --plc-ip <IP>
python3 defense/autoencoder_detector.py monitor --plc-ip <IP> --model ae_model.pt
python3 defense/fusion.py
```

## Recovery
```bash
python3 recovery/recovery_agent.py --plc-ip <PLC1A_IP> --plc-b-ip <PLC1B_IP> \
    --attacker-ip <ATTACKER_IP>
```
