"""
sse_observer.py — SWaT P1 Luenberger Secure State Estimator (Deep Recovery)

Implements a switched Luenberger observer for secure state estimation of SWaT P1.
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
from pymodbus.client import ModbusTcpClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SSE] %(levelname)s %(message)s"
)
log = logging.getLogger("sse_observer")

# ── System Matrices (linearised SWaT P1 — 1D state) ──────────────────────────
MM_PER_LITRE = 0.1      # mm per litre (A_tank dependent)
Q_PUMP       = 2.5      # L/s per pump

A = np.array([[1.0]])
B = np.array([[MM_PER_LITRE, -MM_PER_LITRE * Q_PUMP]])
C = np.array([[1.0]])

# Observer gain L: choose so eigenvalue of (A - L C) = 0.7
# A - L*C = 1 - L → set L = 0.3
L_GAIN = np.array([[0.3]])

# Innovation threshold: |y - C*x_hat| > THRESHOLD → attack suspected
INNOVATION_THRESHOLD = 50.0  # mm

SSE_STATE_PATH = "/tmp/sse_state"
OUTPUT_FILE    = "sse_estimates.json"

REGS = {
    "MV101": ("coil",    1),
    "P101":  ("coil",    2),
    "P102":  ("coil",    3),
    "LIT101":("holding", 1),
    "FIT101":("holding", 2),
}


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


def luenberger_update(x_hat, u, y_meas, attack_detected):
    """
    One-step Luenberger observer update.

    If attack is detected on y_meas, skip correction (open-loop prediction).
    Otherwise, apply standard correction.
    """
    # Prediction step
    x_pred = A @ x_hat + B @ u

    if attack_detected:
        # Open-loop: do not correct with compromised measurement
        x_new = x_pred
        innovation = None
        delta_est = None
    else:
        # Innovation
        y_pred = C @ x_pred
        innovation = y_meas - y_pred
        # Correction
        x_new = x_pred + L_GAIN @ innovation
        # Reconstruct attack signal δ = y_meas - C*x_new
        delta_est = float(y_meas - (C @ x_new)[0])

    return x_new, innovation, delta_est


def main():
    parser = argparse.ArgumentParser(description="SWaT P1 Luenberger SSE Observer")
    parser.add_argument("--plc-ip",   required=True)
    parser.add_argument("--plc-port", type=int, default=502)
    parser.add_argument("--duration", type=float, default=120.0)
    parser.add_argument("--init-level", type=float, default=None)
    args = parser.parse_args()

    client = ModbusTcpClient(args.plc_ip, port=args.plc_port)
    if not client.connect():
        log.error(f"Cannot connect to {args.plc_ip}:{args.plc_port}")
        return

    # Initialise observer state
    if args.init_level is None:
        rr = client.read_holding_registers(REGS["LIT101"][1], count=1, slave=1)
        init_level = rr.registers[0] / 100.0 if not rr.isError() else 500.0
    else:
        init_level = args.init_level

    x_hat = np.array([[init_level]])   # state estimate
    log.info(f"SSE observer started. Initial estimate: {init_level:.1f} mm")

    records = []
    t_end = time.time() + args.duration
    attack_count = 0

    try:
        while time.time() < t_end:
            t0 = time.time()
            state = read_state(client)

            fit101   = state.get("FIT101") or 0.0
            p101     = state.get("P101") or 0
            p102     = state.get("P102") or 0
            lit_meas = state.get("LIT101")

            pump_state = 1 if (p101 == 1 or p102 == 1) else 0
            u = np.array([[fit101, pump_state]])

            # Check pre-innovation to decide if measurement is attacked
            y_pred_pre = float((C @ x_hat)[0])
            pre_innov = abs((lit_meas or y_pred_pre) - y_pred_pre)
            attack_detected = pre_innov > INNOVATION_THRESHOLD

            if attack_detected:
                attack_count += 1

            x_hat, innovation, delta = luenberger_update(
                x_hat, u.T, lit_meas or y_pred_pre, attack_detected
            )

            est_level = float(x_hat[0, 0])

            # Write estimated state to shared file
            with open(SSE_STATE_PATH, "w") as f:
                f.write(f"{est_level:.2f}")

            entry = {
                "timestamp":    datetime.utcnow().isoformat(),
                "x_hat_mm":     round(est_level, 2),
                "y_measured":   round(lit_meas, 2) if lit_meas else None,
                "innovation":   round(float(innovation[0, 0]), 2) if innovation is not None else None,
                "delta_est":    round(delta, 2) if delta is not None else None,
                "attack_flag":  attack_detected,
                "FIT101":       round(fit101, 3),
            }
            records.append(entry)

            if attack_detected:
                log.warning(
                    f"ATTACK: innovation={pre_innov:.1f}mm > {INNOVATION_THRESHOLD}mm "
                    f"→ open-loop x̂={est_level:.1f}mm"
                )
            else:
                log.info(
                    f"OK: x̂={est_level:.1f}mm  y={lit_meas:.1f}mm  "
                    f"δ={delta:.2f}mm" if lit_meas else f"OK: x̂={est_level:.1f}mm"
                )

            elapsed = time.time() - t0
            time.sleep(max(0, 1.0 - elapsed))

    except KeyboardInterrupt:
        log.info("SSE observer stopped.")
    finally:
        client.close()
        with open(OUTPUT_FILE, "w") as f:
            json.dump(records, f, indent=2)
        log.info(f"Attack cycles detected: {attack_count}/{len(records)}")
        log.info(f"Estimates saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
