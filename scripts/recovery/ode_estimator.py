"""
ode_estimator.py — SWaT P1 ODE-Based Sensor State Estimator (Deep Recovery)

Uses the SWaT P1 tank ODE to predict LIT101 (tank level) from FIT101 (inflow)
and estimated outflow, enabling secure sensor re-entry validation after attack.

P1 Tank ODE:
    dL/dt = (Q_in - Q_out) / A_tank

    Where:
        L       = LIT101 tank level (mm)
        Q_in    = FIT101 inflow (L/s) when MV101 OPEN
        Q_out   = estimated outflow to P2 via P101/P102 (L/s)
        A_tank  = SWaT P1 tank cross-sectional area (≈ 1.0 m² = 1,000,000 mm²/L)

Usage:
    python3 ode_estimator.py --plc-ip 192.168.1.10 --duration 60

Output:
    - Console: predicted vs. measured LIT101 with residual
    - ode_estimates.json: time-series of predictions, measurements, residuals
    - /tmp/ode_trusted: 1 if ODE agrees with sensor (safe to trust), 0 otherwise

This script is invoked by reentry_gate.py during deep recovery to validate
that sensor readings are trustworthy before restoring normal control.

Author: SWaT CPS Security Project Team, SUTD 51.508
"""

import argparse
import json
import logging
import time
from datetime import datetime

import numpy as np
from pylogix import PLC

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ODE] %(levelname)s %(message)s"
)
log = logging.getLogger("ode_estimator")

# ── Physical Constants ────────────────────────────────────────────────────────
# SWaT P1 tank: approximate cross-section.
# 1 L = 1000 cm³; A_tank ≈ 1 m² = 10000 cm²
# → 1 L raises level by 1000/10000 = 0.1 mm  → scale = 0.1 mm/L
MM_PER_LITRE = 0.1     # mm per litre (adjust to actual SWaT tank geometry)
DT = 1.0               # integration step = 1 second (polling interval)

# Pump outflow estimates (L/s) — fill from SWaT datasheet
Q_OUT_P101 = 2.5
Q_OUT_P102 = 2.5

# Residual tolerance: if |predicted - measured| > TOLERANCE, sensor untrusted
TOLERANCE_MM = 30.0    # mm

# EtherNet/IP register map
REGS = {
    "MV101": ("coil",    1),
    "P101":  ("coil",    2),
    "P102":  ("coil",    3),
    "LIT101":("holding", 1),   # mm × 100
    "FIT101":("holding", 2),   # L/s × 100
}

FLAG_PATH   = "/tmp/ode_trusted"
OUTPUT_FILE = "ode_estimates.json"


def read_state(client):
    state = {}
    for name, (rtype, addr) in REGS.items():
        if rtype == "coil":
            rr = client.read_coils(addr, count=1, slave=1)
            state[name] = int(rr.bits[0]) if not rr.isError() else None
        else:
            rr = client.read_holding_registers(addr, count=1, slave=1)
            state[name] = rr.registers[0] / 100.0 if not rr.isError() else None
    return state


def estimate_qout(p101, p102):
    """Estimate outflow based on pump states."""
    q = 0.0
    if p101 == 1:
        q += Q_OUT_P101
    if p102 == 1:
        q += Q_OUT_P102
    return q


def main():
    parser = argparse.ArgumentParser(description="SWaT P1 ODE Estimator")
    parser.add_argument("--plc-ip",   required=True)
    parser.add_argument("--plc-port", type=int, default=502)
    parser.add_argument("--duration", type=float, default=120.0,
                        help="Estimation window (s)")
    parser.add_argument("--init-level", type=float, default=None,
                        help="Initial LIT101 reading (mm). Auto-read if not set.")
    args = parser.parse_args()

    client = PLC(args.plc_ip, port=args.plc_port)
    if not client.connect():
        log.error(f"Cannot connect to {args.plc_ip}:{args.plc_port}")
        return

    # Initialise from actual sensor if no override
    if args.init_level is None:
        rr = client.read_holding_registers(REGS["LIT101"][1], count=1, slave=1)
        L_pred = rr.registers[0] / 100.0 if not rr.isError() else 500.0
    else:
        L_pred = args.init_level

    log.info(f"ODE estimator started. Initial level: {L_pred:.1f} mm")

    records = []
    t_end = time.time() + args.duration
    trusted_count = 0
    total_count = 0

    try:
        while time.time() < t_end:
            t0 = time.time()
            state = read_state(client)

            fit101 = state.get("FIT101") or 0.0
            mv101  = state.get("MV101")  or 0
            p101   = state.get("P101")   or 0
            p102   = state.get("P102")   or 0
            lit_measured = state.get("LIT101")

            # Q_in is non-zero only when inlet valve is open
            q_in  = fit101 if mv101 == 1 else 0.0
            q_out = estimate_qout(p101, p102)

            # Euler integration: L(t+dt) = L(t) + (Q_in - Q_out) * MM_PER_LITRE * dt
            dL = (q_in - q_out) * MM_PER_LITRE * DT
            L_pred = L_pred + dL

            residual = None
            trusted = False
            if lit_measured is not None:
                residual = abs(L_pred - lit_measured)
                trusted = residual <= TOLERANCE_MM
                total_count += 1
                if trusted:
                    trusted_count += 1

            flag = 1 if trusted else 0
            with open(FLAG_PATH, "w") as f:
                f.write(str(flag))

            entry = {
                "timestamp":    datetime.utcnow().isoformat(),
                "L_predicted":  round(L_pred, 2),
                "L_measured":   round(lit_measured, 2) if lit_measured else None,
                "residual_mm":  round(residual, 2) if residual is not None else None,
                "trusted":      trusted,
                "Q_in":         round(q_in, 3),
                "Q_out":        round(q_out, 3),
            }
            records.append(entry)

            if trusted:
                log.info(f"  LIT101: pred={L_pred:.1f} meas={lit_measured:.1f} "
                         f"Δ={residual:.1f}mm ✓ TRUSTED")
            else:
                log.warning(f"  LIT101: pred={L_pred:.1f} meas={lit_measured:.1f} "
                            f"Δ={residual:.1f}mm ✗ UNTRUSTED")

            elapsed = time.time() - t0
            time.sleep(max(0, DT - elapsed))

    except KeyboardInterrupt:
        log.info("ODE estimator stopped.")
    finally:
        client.close()
        with open(OUTPUT_FILE, "w") as f:
            json.dump(records, f, indent=2)
        pct = 100 * trusted_count / total_count if total_count > 0 else 0
        log.info(f"Trust rate: {trusted_count}/{total_count} ({pct:.1f}%)")
        log.info(f"Estimates saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
