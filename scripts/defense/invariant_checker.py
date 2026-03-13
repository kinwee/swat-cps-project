"""
invariant_checker.py — SWaT P1 Process Invariant Checker (Layer 1 of Hybrid Defense)

Monitors live Modbus sensor/actuator readings from SWaT PLC1 and evaluates
8 physics-based invariants for Stage P1 (raw water intake).

Usage:
    sudo python3 invariant_checker.py --plc-ip 192.168.1.10 --interval 1.0

Output:
    - Console alerts on invariant violations
    - JSON log: invariant_violations.json
    - Shared-memory flag read by fusion.py: /tmp/inv_flag

SWaT P1 Invariants Checked:
    INV-1:  MV101==OPEN  → FIT101 > 0.5 L/s        (flow when inlet open)
    INV-2:  MV101==CLOSED → FIT101 < 0.1 L/s       (no flow when closed)
    INV-3:  P101==ON OR P102==ON → FIT201 > 0.0     (pump implies downstream flow)
    INV-4:  LIT101 > HH (1000mm) → P101==OFF AND P102==OFF (high-high stops pumps)
    INV-5:  LIT101 < LL (250mm)  → MV101==OPEN      (low-low opens inlet)
    INV-6:  P101==ON AND P102==ON → ALERT           (both pumps never run together)
    INV-7:  LIT101 in [250, 1000] OR MV101==OPEN OR P101==OFF (tank bounds)
    INV-8:  FIT101 rate-of-change < 2.0 L/s per cycle (physical ramp limit)

Author: SWaT CPS Security Project Team, SUTD 51.508
"""

import argparse
import json
import os
import time
import logging
from datetime import datetime
from pymodbus.client import ModbusTcpClient

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [INV] %(levelname)s %(message)s"
)
log = logging.getLogger("invariant_checker")

# ── Modbus Register Map (fill from Phase 0 recon output) ─────────────────────
REGISTER_MAP = {
    # Coil addresses (digital outputs) — PLC1 P1 stage
    "MV101":  {"type": "coil",    "addr": 1},   # TODO: fill from phase0 output
    "P101":   {"type": "coil",    "addr": 2},
    "P102":   {"type": "coil",    "addr": 3},
    # Holding registers (analog sensors, scaled ×100)
    "LIT101": {"type": "holding", "addr": 1},   # mm, ×100
    "FIT101": {"type": "holding", "addr": 2},   # L/s, ×100
    "FIT201": {"type": "holding", "addr": 3},   # L/s, ×100 (inter-stage)
}

# ── Thresholds ────────────────────────────────────────────────────────────────
LIT_HH = 1000.0   # mm high-high level
LIT_LL = 250.0    # mm low-low level
FIT_MIN_FLOW = 0.5
FIT_NO_FLOW  = 0.1
FIT_MAX_DELTA = 2.0  # L/s per cycle

VIOLATION_LOG = "invariant_violations.json"
FLAG_PATH = "/tmp/inv_flag"


def read_sensor(client, name):
    cfg = REGISTER_MAP[name]
    if cfg["type"] == "coil":
        rr = client.read_coils(cfg["addr"], count=1, slave=1)
        if rr.isError():
            return None
        return int(rr.bits[0])
    else:
        rr = client.read_holding_registers(cfg["addr"], count=1, slave=1)
        if rr.isError():
            return None
        return rr.registers[0] / 100.0


def read_all(client):
    return {name: read_sensor(client, name) for name in REGISTER_MAP}


def check_invariants(state, prev_fit101):
    violations = []

    mv  = state.get("MV101")
    p1  = state.get("P101")
    p2  = state.get("P102")
    lit = state.get("LIT101")
    fit = state.get("FIT101")
    fit201 = state.get("FIT201")

    if None in (mv, p1, p2, lit, fit, fit201):
        log.warning("Incomplete sensor read — skipping invariant check")
        return violations

    # INV-1: inlet open → flow expected
    if mv == 1 and fit < FIT_MIN_FLOW:
        violations.append(("INV-1", f"MV101 OPEN but FIT101={fit:.2f} < {FIT_MIN_FLOW}"))

    # INV-2: inlet closed → no flow
    if mv == 0 and fit > FIT_NO_FLOW:
        violations.append(("INV-2", f"MV101 CLOSED but FIT101={fit:.2f} > {FIT_NO_FLOW}"))

    # INV-3: pump on → downstream flow
    if (p1 == 1 or p2 == 1) and fit201 <= 0.0:
        violations.append(("INV-3", f"Pump ON but FIT201={fit201:.2f}"))

    # INV-4: high-high → pumps must be off
    if lit > LIT_HH and (p1 == 1 or p2 == 1):
        violations.append(("INV-4", f"LIT101={lit:.1f} > HH={LIT_HH} but pump running"))

    # INV-5: low-low → inlet must open
    if lit < LIT_LL and mv == 0:
        violations.append(("INV-5", f"LIT101={lit:.1f} < LL={LIT_LL} but MV101 CLOSED"))

    # INV-6: both pumps never run simultaneously
    if p1 == 1 and p2 == 1:
        violations.append(("INV-6", "P101 and P102 both ON simultaneously"))

    # INV-7: tank level in valid bounds
    if not (LIT_LL <= lit <= LIT_HH):
        violations.append(("INV-7", f"LIT101={lit:.1f} outside bounds [{LIT_LL}, {LIT_HH}]"))

    # INV-8: flow rate-of-change limit
    if prev_fit101 is not None:
        delta = abs(fit - prev_fit101)
        if delta > FIT_MAX_DELTA:
            violations.append(("INV-8", f"FIT101 delta={delta:.2f} > {FIT_MAX_DELTA} L/s/cycle"))

    return violations


def write_flag(flag: int):
    with open(FLAG_PATH, "w") as f:
        f.write(str(flag))


def main():
    parser = argparse.ArgumentParser(description="SWaT P1 Invariant Checker")
    parser.add_argument("--plc-ip",   required=True, help="PLC1 IP address")
    parser.add_argument("--plc-port", type=int, default=502)
    parser.add_argument("--interval", type=float, default=1.0, help="Poll interval (s)")
    args = parser.parse_args()

    client = ModbusTcpClient(args.plc_ip, port=args.plc_port)
    if not client.connect():
        log.error(f"Cannot connect to PLC at {args.plc_ip}:{args.plc_port}")
        return

    log.info(f"Connected to PLC1 at {args.plc_ip}. Monitoring P1 invariants...")
    log_entries = []
    prev_fit101 = None
    consecutive_violations = 0

    try:
        while True:
            state = read_all(client)
            violations = check_invariants(state, prev_fit101)
            prev_fit101 = state.get("FIT101")

            if violations:
                consecutive_violations += 1
                for inv_id, msg in violations:
                    log.warning(f"VIOLATION {inv_id}: {msg}")
                    entry = {
                        "timestamp": datetime.utcnow().isoformat(),
                        "invariant": inv_id,
                        "message": msg,
                        "state": state
                    }
                    log_entries.append(entry)
                write_flag(1)
                if consecutive_violations >= 3:
                    log.error("ALERT: 3+ consecutive invariant violations — triggering fusion")
            else:
                consecutive_violations = 0
                write_flag(0)
                log.debug(f"All invariants OK | LIT101={state.get('LIT101'):.1f}mm "
                          f"FIT101={state.get('FIT101'):.2f}L/s")

            if log_entries:
                with open(VIOLATION_LOG, "w") as f:
                    json.dump(log_entries, f, indent=2)

            time.sleep(args.interval)

    except KeyboardInterrupt:
        log.info("Shutting down invariant checker.")
    finally:
        client.close()


if __name__ == "__main__":
    main()
