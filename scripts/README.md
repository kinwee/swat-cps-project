# SWaT Attack & Defense Scripts

**Protocol:** EtherNet/IP / Allen-Bradley ControlLogix  
**Library:** pylogix  
**Threat Model:** Compromised HMI workstation (insider/supply-chain attack)  
**PLC1:** 192.168.1.10  |  **PLC1B:** 192.168.1.11

## Threat Model
All scripts run on the HMI workstation. The attacker has compromised the HMI
(e.g. via phishing or USB drop). The HMI has legitimate EtherNet/IP access to
all PLCs — no external laptop or network MITM required. This reflects the most
common real-world ICS attack vector (Stuxnet, Ukraine 2015, Oldsmar 2021).

## Dependencies
```bash
pip install pylogix torch numpy pandas scikit-learn
```
Note: scapy is NOT required — no ARP poisoning needed when running from HMI.

## Real SWaT P1 Tag Names (confirmed from lab)
| Signal | Tag | Type |
|--------|-----|------|
| LIT101 level | `HMI_LIT101.Pv` | REAL (mm) |
| FIT101 flow | `AI_FIT_101_FLOW` | REAL (L/s) |
| MV101 valve cmd | `HMI_MV101.Cmd` | INT (1=CLOSE, 2=OPEN) |
| MV101 auto mode | `HMI_MV101.Auto` | BOOL |
| P101 pump auto | `HMI_P101.Auto` | BOOL |
| LIT101 sim enable | `HMI_LIT101.Sim` | BOOL |
| LIT101 sim value | `HMI_LIT101.Sim_PV` | REAL |

## PLC IP Addresses
| PLC | Primary | Redundant |
|-----|---------|-----------|
| PLC1 | 192.168.1.10 | 192.168.1.11 |
| PLC2 | 192.168.1.20 | 192.168.1.21 |
| PLC3 | 192.168.1.30 | 192.168.1.31 |

## Attack (run from HMI)
```bash
# Phase 0: tag discovery + baseline logging
python3 attack/phase0_recon.py --plc-ip 192.168.1.10 --duration 1800

# Phase 1: direct false CIP tag injection (no sudo, no ARP needed)
python3 attack/phase1_inject.py --plc-ip 192.168.1.10 --duration 120

# Phase 2: adversarial ML evasion via sensor simulation tags
python3 attack/phase2_spoof.py attack --plc-ip 192.168.1.10 --duration 120
```

## Defense (run from HMI)
```bash
python3 defense/invariant_checker.py --plc-ip 192.168.1.10
python3 defense/autoencoder_detector.py monitor --plc-ip 192.168.1.10 --model ae_model.pt
python3 defense/fusion.py
```

## Recovery (run from HMI)
```bash
python3 recovery/recovery_agent.py --plc-ip 192.168.1.10 --plc-b-ip 192.168.1.11
```
