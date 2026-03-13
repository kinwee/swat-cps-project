# SWaT CPS Security Project — Scripts
**SUTD 51.508 Secure Cyber-Physical Systems**

> ⚠️ **Lab use only.** All scripts must be run on the iTrust SWaT testbed with
> prior approval from lab engineers. Never run on production systems.

---

## Folder Structure

```
swat_scripts/
├── attack/
│   ├── phase0_recon.py        Phase 0 — Passive Modbus reconnaissance
│   ├── phase1_inject.py       Phase 1 — False command injection (Paper #9)
│   └── phase2_spoof.py        Phase 2 — Adversarial ML sensor spoofing (Paper #31)
│
├── defense/
│   ├── invariant_checker.py   Layer 1 — Process invariant monitor
│   ├── autoencoder_detector.py Layer 2 — Reconstruction autoencoder
│   └── fusion.py              Layer 3 — Decision fusion & alert engine
│
└── recovery/
    ├── recovery_agent.py      Shallow recovery orchestrator (Steps 1–5)
    ├── ode_estimator.py       Deep recovery — ODE-based sensor estimator
    ├── sse_observer.py        Deep recovery — Luenberger SSE observer
    └── reentry_gate.py        Deep recovery — Invariant-guided sensor re-entry
```

---

## Dependencies

```bash
pip install pymodbus scapy torch numpy pandas scikit-learn
sudo apt install nmap
```

---

## Attack Scripts

### `phase0_recon.py` — Passive Recon
Scans for Modbus devices and sniffs traffic to build a request-response DB.

```bash
sudo python3 phase0_recon.py --subnet 192.168.1.0/24 --iface eth0 --duration 1800
```
Outputs: `swat_capture.pcap`, `modbus_db.pkl`, `recon_results.json`

---

### `phase1_inject.py` — False Command Injection (Paper #9)
ARP-poisons HMI↔PLC, injects false write_coil commands, replays captured
responses to conceal the attack.

```bash
sudo python3 phase1_inject.py \
  --plc-ip 192.168.1.10 --hmi-ip 192.168.1.20 \
  --iface eth0 --db modbus_db.pkl --duration 120
```
> ⚠️ Fill `REGISTER_MAP` in the script with addresses from Phase 0 output first.

---

### `phase2_spoof.py` — Adversarial ML Sensor Spoofing (Paper #31)
Trains an adversarial autoencoder on normal SWaT data, then generates
ML-evasive spoofed sensor values.

```bash
# Train
python3 phase2_spoof.py train --data swat_normal.csv --epochs 100

# Attack
sudo python3 phase2_spoof.py attack \
  --plc-ip 192.168.1.10 --hmi-ip 192.168.1.20 \
  --iface eth0 --duration 120
```
Download SWaT normal dataset: https://itrust.sutd.edu.sg/itrust-labs_datasets/dataset_info/

---

## Defense Scripts

Run all three layers in separate terminals simultaneously.

### `invariant_checker.py` — Layer 1: Physics Invariants
Monitors 8 SWaT P1 process invariants in real time.

```bash
sudo python3 invariant_checker.py --plc-ip 192.168.1.10
```
Flag file: `/tmp/inv_flag` (0=OK, 1=violated)

---

### `autoencoder_detector.py` — Layer 2: Reconstruction Autoencoder
Train on normal data, then monitor live sensor stream for anomalies.

```bash
# Train (offline)
python3 autoencoder_detector.py train --data swat_normal.csv --save ae_model.pt

# Monitor live
sudo python3 autoencoder_detector.py monitor --plc-ip 192.168.1.10 --model ae_model.pt
```
Flag file: `/tmp/ae_flag` (0=normal, 1=anomaly)

---

### `fusion.py` — Layer 3: Decision Fusion
Reads both flags, applies weighted fusion, triggers recovery on sustained alert.

```bash
python3 fusion.py --recovery-script ../recovery/recovery_agent.py
```
Fusion rule: `score = 1.5 × inv_flag + 1.0 × ae_flag`
ALERT if `score ≥ 1.5` for **3 consecutive cycles**

---

## Recovery Scripts

### Shallow Recovery (< 15s target)

```bash
sudo python3 recovery_agent.py \
  --plc-ip 192.168.1.10 \
  --attacker-ip 192.168.1.99 \
  --attacker-mac AA:BB:CC:DD:EE:FF \
  --standby-plc-ip 192.168.1.11
```

Steps executed:
1. Log incident + notify operator
2. `iptables` block port 502 from attacker; VLAN isolate attacker MAC
3. Write safe-state values to all PLC stages (MV101 CLOSED, P101/P102 OFF, etc.)
4. Trigger PLC1 hot-standby failover (EtherNet/IP handshake)
5. Verify: wait for 5 consecutive clean invariant cycles

---

### Deep Recovery (Research Extension)

Run in sequence after shallow recovery completes:

```bash
# Terminal 1: ODE estimator (cross-check LIT101 predictions)
python3 ode_estimator.py --plc-ip 192.168.1.10 --duration 120

# Terminal 2: Luenberger SSE observer (secure state estimation)
python3 sse_observer.py --plc-ip 192.168.1.10 --duration 120

# Terminal 3: Re-entry gate (sequential sensor acceptance)
python3 reentry_gate.py --plc-ip 192.168.1.10 --ode-mode --sse-mode
```

All three scripts write to `/tmp/` flag files consumed by `reentry_gate.py`.
Re-entry succeeds only when all 8 P1 invariants pass for 5+ consecutive cycles
AND sensor value agrees with ODE/SSE prediction within 30mm tolerance.

---

## Execution Order (Full Demo)

```
Phase 0 recon → Phase 1+2 attack
         ↓ (attack active)
Layer 1 invariant_checker  ─┐
Layer 2 autoencoder_monitor  ├─→ fusion.py → recovery_agent.py
                             ┘         ↓
                              ode_estimator + sse_observer
                                         ↓
                                    reentry_gate.py
                                         ↓
                                  Normal operation
```

---

## Key Register Addresses
Fill these from Phase 0 (`recon_results.json`) before running Phase 1+:

| Tag    | Type    | Address (TODO) |
|--------|---------|----------------|
| MV101  | coil    | ?              |
| P101   | coil    | ?              |
| P102   | coil    | ?              |
| LIT101 | holding | ?              |
| FIT101 | holding | ?              |
| FIT201 | holding | ?              |

---

## References
- Paper #9: W. Alsabbagh et al., IEEE CCNC 2023
- Paper #31: J. H. Castellanos et al., ACM ACSAC 2020
- SSE: A. Y. Lu & G. H. Yang, Information Sciences 2017
- NIST SP 800-82r3: https://csrc.nist.gov/pubs/sp/800/82/r3/final
