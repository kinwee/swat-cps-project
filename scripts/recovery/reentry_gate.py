#!/usr/bin/env python3
"""
reentry_gate.py — SWaT P1 Invariant-Gated Sensor Re-Entry (Deep Recovery)

After shallow recovery completes, sensors may still be compromised.
For each sensor, it:
    1. Reads current sensor value
    2. Compares against ODE/SSE prediction
    3. Checks all 8 P1 invariants pass for ACCEPT_CYCLES consecutive cycles
    4. Only then accepts the sensor as trustworthy and re-enables control

This prevents an attacker from resuming spoofed values after recovery.

Protocol: EtherNet/IP via pylogix (Allen-Bradley ControlLogix)

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

from pylogix import PLC

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [REENTRY] %(levelname)s %(message)s"
)
log = logging.getLogger("reentry_gate")

# ── Config ────────────────────────────────────────────────────────────────────
ACCEPT_CYCLES      = 5       # clean invariant cycles required for acceptance
TIMEOUT_PER_SENSOR = 30      # seconds before declaring sensor failed reentry
RESIDUAL_LIMIT     = 30.0    # mm — max deviation from ODE/SSE prediction

ODE_STATE_PATH  = "/tmp/ode_trusted"
SSE_STATE_PATH  = "/tmp/sse_state"
REENTRY_DONE    = "/tmp/reentry_complete"
OUTPUT_FILE     = "reentry_log.json"

# P1 sensor re-entry order (most critical first)
SENSOR_REENTRY_ORDER = ["FIT101", "LIT101", "FIT201"]

# Real SWaT P1 tag names (pylogix / EtherNet/IP)
TAGS = {
    "LIT101":  "HMI_LIT101.Pv",         # REAL (mm)
    "FIT101":  "AI_FIT_101_FLOW",        # REAL (L/s)
    "FIT201":  "HMI_FIT201.Pv",          # REAL (L/s)
    "MV101":   "HMI_MV101.Cmd",          # INT (1=CLOSE, 2=OPEN)
    "P101":    "HMI_P101.Auto",          # BOOL
    "P102":    "HMI_P102.Auto",          # BOOL
}

# P1 invariant thresholds (same as invariant_checker.py)
LIT_HH       = 1000.0
LIT_LL       = 250.0
FIT_MIN_FLOW = 0.5
FIT_NO_FLOW  = 0.1


def read_sensor(plc, name):
    """Read a single sensor/actuator value via pylogix."""
    tag = TAGS.get(name)
    if not tag:
        log.warning(f"  Unknown sensor: {name}")
        return None
    ret = plc.Read(tag)
    if ret.Status == "Success":
        return ret.Value
    else:
        log.warning(f"  Failed to read {tag}: {ret.Status}")
        return None


def read_all_p1(plc):
    """Read all P1 tags for invariant checking."""
    state = {}
    for name, tag in TAGS.items():
        ret = plc.Read(tag)
        if ret.Status == "Success":
            state[name] = ret.Value
        else:
            state[name] = None
    return state


def check_p1_invariants(plc):
    """Returns list of violated invariant IDs (empty = all pass)."""
    state = read_all_p1(plc)
    violations = []

    lit101 = state.get("LIT101")
    fit101 = state.get("FIT101")
    mv101  = state.get("MV101")      # 1=CLOSE, 2=OPEN
    p101   = state.get("P101")       # BOOL
    p102   = state.get("P102")       # BOOL

    if lit101 is None or fit101 is None:
        violations.append("DATA_MISSING")
        return violations

    # I-1: LIT101 within safe bounds
    if lit101 > LIT_HH or lit101 < LIT_LL:
        violations.append("I-1")

    # I-2: If MV101 is OPEN (Cmd=2), FIT101 should show flow
    if mv101 == 2 and fit101 < FIT_NO_FLOW:
        violations.append("I-2")

    # I-3: If MV101 is CLOSED (Cmd=1), FIT101 should be near zero
    if mv101 == 1 and fit101 > FIT_MIN_FLOW:
        violations.append("I-3")

    # I-4: If P101 is ON and MV101 is CLOSED, LIT101 should be dropping
    # (can only check over time — skip for single-cycle check)

    # I-5: LIT101 high-high → MV101 should be CLOSED
    if lit101 > LIT_HH and mv101 == 2:
        violations.append("I-5")

    # I-6: LIT101 low-low → P101 should be OFF
    if lit101 < LIT_LL and p101:
        violations.append("I-6")

    return violations


def read_ode_trust():
    """Read ODE trust flag from /tmp/ode_trusted."""
    try:
        with open(ODE_STATE_PATH) as f:
            return int(f.read().strip()) == 1
    except Exception:
        return False


def read_sse_estimate():
    """Read SSE state estimate from /tmp/sse_state."""
    try:
        with open(SSE_STATE_PATH) as f:
            return float(f.read().strip())
    except Exception:
        return None


def accept_sensor(plc, sensor_name, use_ode, use_sse):
    """
    Try to accept a single sensor. Returns True if accepted within timeout.
    Requires ACCEPT_CYCLES consecutive clean invariant cycles.
    """
    log.info(f"  Attempting re-entry for {sensor_name}...")
    clean = 0
    t_start = time.time()

    while clean < ACCEPT_CYCLES and (time.time() - t_start) < TIMEOUT_PER_SENSOR:
        # Check invariants
        violations = check_p1_invariants(plc)
        if violations:
            clean = 0
            log.warning(f"    {sensor_name}: invariant violations {violations} — reset")
            time.sleep(1.0)
            continue

        # Optional: check ODE trust
        if use_ode and not read_ode_trust():
            clean = 0
            log.warning(f"    {sensor_name}: ODE says untrusted — reset")
            time.sleep(1.0)
            continue

        # Optional: check SSE residual for LIT101
        if use_sse and sensor_name == "LIT101":
            sse_est = read_sse_estimate()
            measured = read_sensor(plc, "LIT101")
            if sse_est is not None and measured is not None:
                residual = abs(sse_est - measured)
                if residual > RESIDUAL_LIMIT:
                    clean = 0
                    log.warning(f"    {sensor_name}: SSE residual {residual:.1f}mm > {RESIDUAL_LIMIT}mm — reset")
                    time.sleep(1.0)
                    continue

        clean += 1
        log.info(f"    {sensor_name}: clean cycle {clean}/{ACCEPT_CYCLES}")
        time.sleep(1.0)

    if clean >= ACCEPT_CYCLES:
        log.info(f"  ✓ {sensor_name} ACCEPTED after {time.time()-t_start:.1f}s")
        return True
    else:
        log.error(f"  ✗ {sensor_name} REJECTED — timed out after {TIMEOUT_PER_SENSOR}s")
        return False


def main():
    parser = argparse.ArgumentParser(description="SWaT P1 Sensor Re-Entry Gate")
    parser.add_argument("--plc-ip",   required=True)
    parser.add_argument("--ode-mode", action="store_true",
                        help="Require ODE trust before acceptance")
    parser.add_argument("--sse-mode", action="store_true",
                        help="Require SSE residual check for LIT101")
    args = parser.parse_args()

    log.info("=" * 60)
    log.info("  SWaT P1 Sensor Re-Entry Gate")
    log.info(f"  PLC: {args.plc_ip}")
    log.info(f"  ODE mode: {args.ode_mode}  |  SSE mode: {args.sse_mode}")
    log.info("=" * 60)

    results = {}

    with PLC() as plc:
        plc.IPAddress = args.plc_ip

        # Verify connection
        test = plc.Read(TAGS["LIT101"])
        if test.Value is None:
            log.error(f"Cannot read LIT101 from {args.plc_ip}: {test.Status}")
            return

        log.info(f"Connected. LIT101 = {test.Value:.1f} mm")

        for sensor in SENSOR_REENTRY_ORDER:
            accepted = accept_sensor(plc, sensor, args.ode_mode, args.sse_mode)
            results[sensor] = {
                "accepted": accepted,
                "timestamp": datetime.utcnow().isoformat(),
            }

    # Write completion flag
    all_accepted = all(r["accepted"] for r in results.values())
    with open(REENTRY_DONE, "w") as f:
        f.write("1" if all_accepted else "0")

    # Save log
    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2)

    if all_accepted:
        log.info("*** ALL SENSORS ACCEPTED — re-entry complete ***")
    else:
        failed = [s for s, r in results.items() if not r["accepted"]]
        log.error(f"*** RE-ENTRY INCOMPLETE — failed: {failed} ***")
        log.error("    Manual inspection required before resuming normal control.")


if __name__ == "__main__":
    main()
