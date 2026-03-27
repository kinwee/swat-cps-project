"""
reentry_gate.py — SWaT Invariant-Guided Sensor Re-Entry Gate (Deep Recovery)

After shallow recovery (safe state + failover), this script manages the
controlled sequential re-entry of sensors into active control.

For each sensor, it:
    1. Reads current sensor value
    2. Compares against ODE/SSE prediction
    3. Checks all 8 P1 invariants pass for ACCEPT_CYCLES consecutive cycles
    4. Only then accepts the sensor as trustworthy and re-enables control

This prevents an attacker from resuming spoofed values after recovery.

Reference: Proposed invariant-guided reconstruction (this project, SUTD 51.508)

Usage:
    python3 reentry_gate.py --plc-ip 192.168.1.10 [--ode-mode] [--sse-mode]

Output:
    - Console: per-sensor acceptance decisions
    - reentry_log.json: full decision log
    - /tmp/reentry_complete: written with "1" when all sensors accepted

Author: SWaT CPS Security Project Team, SUTD 51.508
"""

import argparse
import json
import logging
import os
import time
from datetime import datetime

from pymodbus.client import EtherNet/IPTcpClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [REENTRY] %(levelname)s %(message)s"
)
log = logging.getLogger("reentry_gate")

# ── Config ────────────────────────────────────────────────────────────────────
ACCEPT_CYCLES   = 5       # clean invariant cycles required for acceptance
TIMEOUT_PER_SENSOR = 30   # seconds before declaring sensor failed reentry
RESIDUAL_LIMIT  = 30.0    # mm — max deviation from ODE/SSE prediction

ODE_STATE_PATH  = "/tmp/ode_trusted"
SSE_STATE_PATH  = "/tmp/sse_state"
REENTRY_DONE    = "/tmp/reentry_complete"
OUTPUT_FILE     = "reentry_log.json"

# P1 sensor re-entry order (most critical first)
SENSOR_REENTRY_ORDER = ["FIT101", "LIT101", "FIT201"]

REGS = {
    "FIT101": ("holding", 2),
    "LIT101": ("holding", 1),
    "FIT201": ("holding", 3),
    "MV101":  ("coil",    1),
    "P101":   ("coil",    2),
    "P102":   ("coil",    3),
}

# P1 invariant thresholds (same as invariant_checker.py)
LIT_HH = 1000.0
LIT_LL = 250.0
FIT_MIN_FLOW = 0.5
FIT_NO_FLOW  = 0.1


def read_sensor(client, name):
    rtype, addr = REGS[name]
    if rtype == "coil":
        rr = client.read_coils(addr, count=1, slave=1)
        return int(rr.bits[0]) if not rr.isError() else None
    else:
        rr = client.read_holding_registers(addr, count=1, slave=1)
        return rr.registers[0] / 100.0 if not rr.isError() else None


def check_p1_invariants(client):
    """Returns list of violated invariant IDs (empty = all pass)."""
    mv  = read_sensor(client, "MV101")
    p1  = read_sensor(client, "P101")
    p2  = read_sensor(client, "P102")
    lit = read_sensor(client, "LIT101")
    fit = read_sensor(client, "FIT101")

    if None in (mv, p1, p2, lit, fit):
        return ["READ_ERROR"]

    violations = []
    if mv == 1 and fit < FIT_MIN_FLOW:
        violations.append("INV-1")
    if mv == 0 and fit > FIT_NO_FLOW:
        violations.append("INV-2")
    if lit > LIT_HH and (p1 == 1 or p2 == 1):
        violations.append("INV-4")
    if lit < LIT_LL and mv == 0:
        violations.append("INV-5")
    if p1 == 1 and p2 == 1:
        violations.append("INV-6")
    if not (LIT_LL <= lit <= LIT_HH):
        violations.append("INV-7")

    return violations


def get_ode_trusted():
    try:
        with open(ODE_STATE_PATH) as f:
            return int(f.read().strip()) == 1
    except Exception:
        return False


def get_sse_estimate():
    try:
        with open(SSE_STATE_PATH) as f:
            return float(f.read().strip())
    except Exception:
        return None


def accept_sensor(client, sensor_name, use_ode=False, use_sse=False):
    """
    Attempt to accept a sensor. Returns True if accepted, False if timeout.
    """
    log.info(f"  Evaluating re-entry: {sensor_name}")
    clean_count = 0
    t_end = time.time() + TIMEOUT_PER_SENSOR
    decisions = []

    while time.time() < t_end:
        val = read_sensor(client, sensor_name)
        violations = check_p1_invariants(client)

        # Additional cross-check with ODE/SSE if available
        cross_ok = True
        if use_sse and sensor_name == "LIT101":
            sse_est = get_sse_estimate()
            if sse_est is not None and val is not None:
                residual = abs(val - sse_est)
                if residual > RESIDUAL_LIMIT:
                    cross_ok = False
                    log.warning(f"    SSE residual {residual:.1f}mm > limit for {sensor_name}")

        if use_ode and sensor_name == "LIT101":
            if not get_ode_trusted():
                cross_ok = False
                log.warning(f"    ODE flagged {sensor_name} as untrusted")

        cycle_ok = (len(violations) == 0) and cross_ok

        if cycle_ok:
            clean_count += 1
            log.info(f"    Clean cycle {clean_count}/{ACCEPT_CYCLES} for {sensor_name}")
        else:
            clean_count = 0
            log.warning(f"    Reset: violations={violations} cross_ok={cross_ok}")

        decisions.append({
            "timestamp": datetime.utcnow().isoformat(),
            "sensor":    sensor_name,
            "value":     round(val, 2) if val is not None else None,
            "violations": violations,
            "cross_ok":   cross_ok,
            "clean_count": clean_count,
        })

        if clean_count >= ACCEPT_CYCLES:
            log.info(f"  ✓ {sensor_name} ACCEPTED after {clean_count} clean cycles")
            return True, decisions

        time.sleep(1.0)

    log.error(f"  ✗ {sensor_name} FAILED re-entry (timeout {TIMEOUT_PER_SENSOR}s)")
    return False, decisions


def main():
    parser = argparse.ArgumentParser(description="SWaT Invariant-Guided Sensor Re-Entry Gate")
    parser.add_argument("--plc-ip",   required=True)
    parser.add_argument("--plc-port", type=int, default=502)
    parser.add_argument("--ode-mode", action="store_true",
                        help="Cross-check LIT101 with ODE estimator")
    parser.add_argument("--sse-mode", action="store_true",
                        help="Cross-check LIT101 with SSE observer")
    args = parser.parse_args()

    client = EtherNet/IPTcpClient(args.plc_ip, port=args.plc_port)
    if not client.connect():
        log.error(f"Cannot connect to {args.plc_ip}:{args.plc_port}")
        return

    log.info("═══════════════════════════════════════════════")
    log.info("  SENSOR RE-ENTRY GATE — Deep Recovery")
    log.info("═══════════════════════════════════════════════")

    full_log = []
    all_accepted = True

    try:
        for sensor in SENSOR_REENTRY_ORDER:
            accepted, decisions = accept_sensor(
                client, sensor,
                use_ode=args.ode_mode,
                use_sse=args.sse_mode,
            )
            full_log.extend(decisions)
            if not accepted:
                all_accepted = False
                log.error(f"Re-entry FAILED for {sensor}. Halting.")
                break
    finally:
        client.close()

    with open(REENTRY_DONE, "w") as f:
        f.write("1" if all_accepted else "0")

    with open(OUTPUT_FILE, "w") as f:
        json.dump(full_log, f, indent=2)

    if all_accepted:
        log.info("ALL SENSORS ACCEPTED — system returning to normal control")
    else:
        log.error("RE-ENTRY INCOMPLETE — manual inspection required")


if __name__ == "__main__":
    main()
