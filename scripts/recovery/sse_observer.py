#!/usr/bin/env python3
"""
sse_observer.py — SWaT P1 Secure State Estimator (Luenberger Observer)

Selects attack-free sensor subsets and reconstructs the true plant state even
when a subset of sensors is compromised.

Reference:
    A. Y. Lu & G. H. Yang, "Secure State Estimation for Cyber-Physical Systems
    under Sparse Sensor Attacks via a Switched Luenberger Observer,"
    Information Sciences, vol. 417, 2017.

State-space model (linearised SWaT P1):
    x(k+1) = A x(k) + B u(k)
    y(k)   = C x(k) + D u(k) + δ(k)   ← δ = attack signal

    States x:  [LIT101 (tank level, mm)]
    Inputs u:  [FIT101 (inflow, L/s), pump_state (0/1)]
    Outputs y: [LIT101_measured]

    A = [[1]]                   (tank level persists)
    B = [[MM_PER_LITRE, -MM_PER_LITRE * Q_PUMP]]
    C = [[1]]
    L = observer gain (set so A-LC has eigenvalue ≈ 0.7)

Protocol: EtherNet/IP via pylogix (Allen-Bradley ControlLogix)

Usage:
    python3 sse_observer.py --plc-ip 192.168.1.10 --duration 60

Output:
    - Console: estimated state vs measured, attack residual δ
    - sse_estimates.json
    - /tmp/sse_state — last estimated LIT101 value (mm)

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
    format="%(asctime)s [SSE] %(levelname)s %(message)s"
)
log = logging.getLogger("sse_observer")

# ── System Matrices (linearised SWaT P1 — 1D state) ──────────────────────────
MM_PER_LITRE = 0.1      # mm per litre (A_tank dependent)
Q_PUMP       = 2.5      # L/s per pump
DT           = 1.0      # polling interval (s)

A = np.array([[1.0]])
B = np.array([[MM_PER_LITRE * DT, -MM_PER_LITRE * Q_PUMP * DT]])
C = np.array([[1.0]])

# Observer gain L: choose so eigenvalue of (A - L C) = 0.7
# A - L*C = 1 - L → set L = 0.3
L_GAIN = np.array([[0.3]])

# Innovation threshold: |y - C*x_hat| > THRESHOLD → attack suspected
INNOVATION_THRESHOLD = 50.0  # mm

SSE_STATE_PATH = "/tmp/sse_state"
OUTPUT_FILE    = "sse_estimates.json"

# Real SWaT P1 tag names (pylogix / EtherNet/IP)
TAGS = {
    "LIT101": "HMI_LIT101.Pv",         # REAL (mm)
    "FIT101": "AI_FIT_101_FLOW",        # REAL (L/s)
    "MV101":  "HMI_MV101.Cmd",          # INT (1=CLOSE, 2=OPEN)
    "P101":   "HMI_P101.Auto",          # BOOL
    "P102":   "HMI_P102.Auto",          # BOOL
}


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


def luenberger_update(x_hat, u, y_meas, attack_detected):
    """
    One-step Luenberger observer update.

    If attack is detected on y_meas, skip correction (open-loop prediction).
    Otherwise, apply standard correction.
    """
    # Prediction: x_hat_minus = A x_hat + B u
    x_pred = A @ x_hat + B @ u

    if attack_detected:
        # Open-loop: don't trust measurement
        return x_pred
    else:
        # Correction: x_hat = x_pred + L (y - C x_pred)
        innovation = y_meas - C @ x_pred
        x_hat_new = x_pred + L_GAIN @ innovation
        return x_hat_new


def main():
    parser = argparse.ArgumentParser(description="SWaT P1 SSE Observer")
    parser.add_argument("--plc-ip",     required=True)
    parser.add_argument("--duration",   type=float, default=120.0,
                        help="Observation window (s)")
    parser.add_argument("--init-level", type=float, default=None,
                        help="Initial LIT101 estimate (mm). Auto-read if not set.")
    args = parser.parse_args()

    with PLC() as plc:
        plc.IPAddress = args.plc_ip

        # Verify connection + initialise state
        test = plc.Read(TAGS["LIT101"])
        if test.Value is None:
            log.error(f"Cannot read LIT101 from {args.plc_ip}: {test.Status}")
            return

        if args.init_level is None:
            x_hat = np.array([[test.Value]])
        else:
            x_hat = np.array([[args.init_level]])

        log.info(f"SSE observer started. Initial estimate: {x_hat[0,0]:.1f} mm")

        records = []
        t_end = time.time() + args.duration
        attack_count = 0

        try:
            while time.time() < t_end:
                t0 = time.time()
                state = read_state(plc)

                fit101 = state.get("FIT101") or 0.0
                mv101  = state.get("MV101")  or 1     # default CLOSE
                p101   = state.get("P101")   or False
                p102   = state.get("P102")   or False
                lit_measured = state.get("LIT101")

                # Build input vector u = [Q_in, pump_active]
                q_in = fit101 if mv101 == 2 else 0.0
                pump_active = 1.0 if (p101 or p102) else 0.0
                u = np.array([[q_in], [pump_active]])

                # Check innovation (pre-update residual)
                attack_detected = False
                innovation_val = None
                if lit_measured is not None:
                    y_meas = np.array([[lit_measured]])
                    innovation_val = float(abs(y_meas - C @ x_hat))
                    attack_detected = innovation_val > INNOVATION_THRESHOLD
                    if attack_detected:
                        attack_count += 1
                else:
                    y_meas = C @ x_hat  # use prediction as fallback
                    attack_detected = True  # can't trust missing data

                # Luenberger update
                x_hat = luenberger_update(x_hat, u, y_meas, attack_detected)
                estimate = float(x_hat[0, 0])

                # Write state estimate to flag file
                with open(SSE_STATE_PATH, "w") as f:
                    f.write(f"{estimate:.2f}")

                entry = {
                    "timestamp":      datetime.utcnow().isoformat(),
                    "x_hat":          round(estimate, 2),
                    "y_measured":     round(lit_measured, 2) if lit_measured else None,
                    "innovation":     round(innovation_val, 2) if innovation_val is not None else None,
                    "attack_detected": attack_detected,
                    "Q_in":           round(q_in, 3),
                    "pump_active":    pump_active,
                }
                records.append(entry)

                status = "ATTACK" if attack_detected else "OK"
                meas_str = f"{lit_measured:.1f}" if lit_measured else "N/A"
                innov_str = f"{innovation_val:.1f}" if innovation_val is not None else "N/A"
                log.info(f"  x̂={estimate:.1f} y={meas_str} innov={innov_str} [{status}]")

                elapsed = time.time() - t0
                time.sleep(max(0, DT - elapsed))

        except KeyboardInterrupt:
            log.info("SSE observer stopped.")
        finally:
            with open(OUTPUT_FILE, "w") as f:
                json.dump(records, f, indent=2)

            log.info(f"Done. {attack_count} attack detections. Saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
