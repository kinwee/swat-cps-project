#!/usr/bin/env python3
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
        A_tank  = SWaT P1 tank cross-sectional area (≈ 1.0 m²)

Protocol: EtherNet/IP via pylogix (Allen-Bradley ControlLogix)

Usage:
    python3 ode_estimator.py --plc-ip 192.168.1.10 --duration 60

Output:
    - Console: predicted vs. measured LIT101 with residual
    - ode_estimates.json: time-series of predictions, measurements, residuals
    - /tmp/ode_trusted: 1 if ODE agrees with sensor (safe to trust), 0 otherwise

Author: SWaT CPS Security Project Team, SUTD 51.508
"""

import argparse
import json
import logging
import time
from datetime import datetime

from pylogix import PLC

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ODE] %(levelname)s %(message)s"
)
log = logging.getLogger("ode_estimator")

# ── Physical Constants ────────────────────────────────────────────────────────
MM_PER_LITRE = 0.1     # mm per litre (adjust to actual SWaT P1 tank geometry)
DT = 1.0               # integration step = 1 second (polling interval)

# Pump outflow estimates (L/s) — fill from SWaT datasheet
Q_OUT_P101 = 2.5
Q_OUT_P102 = 2.5

# Residual tolerance: if |predicted - measured| > TOLERANCE, sensor untrusted
TOLERANCE_MM = 30.0    # mm

# Real SWaT P1 tag names (pylogix / EtherNet/IP)
TAGS = {
    "LIT101": "HMI_LIT101.Pv",         # REAL (mm)
    "FIT101": "AI_FIT_101_FLOW",        # REAL (L/s)
    "MV101":  "HMI_MV101.Cmd",          # INT (1=CLOSE, 2=OPEN)
    "P101":   "HMI_P101.Auto",          # BOOL
    "P102":   "HMI_P102.Auto",          # BOOL
}

FLAG_PATH   = "/tmp/ode_trusted"
OUTPUT_FILE = "ode_estimates.json"


def read_state(plc):
    """Read all P1 tags via pylogix. Returns dict of tag name -> value."""
    state = {}
    for name, tag in TAGS.items():
        ret = plc.Read(tag)
        if ret.Status == "Success":
            state[name] = ret.Value
        else:
            log.warning(f"  Failed to read {tag}: {ret.Status}")
            state[name] = None
    return state


def estimate_qout(p101, p102):
    """Estimate outflow based on pump states."""
    q = 0.0
    if p101:   # True/ON
        q += Q_OUT_P101
    if p102:   # True/ON
        q += Q_OUT_P102
    return q


def main():
    parser = argparse.ArgumentParser(description="SWaT P1 ODE Estimator")
    parser.add_argument("--plc-ip",     required=True)
    parser.add_argument("--duration",   type=float, default=120.0,
                        help="Estimation window (s)")
    parser.add_argument("--init-level", type=float, default=None,
                        help="Initial LIT101 reading (mm). Auto-read if not set.")
    args = parser.parse_args()

    with PLC() as plc:
        plc.IPAddress = args.plc_ip

        # Verify connection
        test = plc.Read(TAGS["LIT101"])
        if test.Value is None:
            log.error(f"Cannot read LIT101 from {args.plc_ip}: {test.Status}")
            return

        # Initialise from actual sensor if no override
        if args.init_level is None:
            L_pred = test.Value
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
                state = read_state(plc)

                fit101 = state.get("FIT101") or 0.0
                mv101  = state.get("MV101")  or 1     # default CLOSE
                p101   = state.get("P101")   or False
                p102   = state.get("P102")   or False
                lit_measured = state.get("LIT101")

                # Q_in is non-zero only when inlet valve is open (Cmd=2=OPEN)
                q_in  = fit101 if mv101 == 2 else 0.0
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
                    status = f"meas={lit_measured:.1f}" if lit_measured else "meas=N/A"
                    log.warning(f"  LIT101: pred={L_pred:.1f} {status} "
                                f"Δ={residual:.1f}mm ✗ UNTRUSTED" if residual else
                                f"  LIT101: pred={L_pred:.1f} {status} ✗ NO DATA")

                elapsed = time.time() - t0
                time.sleep(max(0, DT - elapsed))

        except KeyboardInterrupt:
            log.info("ODE estimator stopped.")
        finally:
            with open(OUTPUT_FILE, "w") as f:
                json.dump(records, f, indent=2)

            pct = (trusted_count / total_count * 100) if total_count > 0 else 0
            log.info(f"Done. {trusted_count}/{total_count} readings trusted ({pct:.0f}%)")
            log.info(f"Saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
