#!/usr/bin/env python3
"""
invariant_checker.py  —  SWaT P1 Process Invariant Checker
Target: Allen-Bradley ControlLogix PLC1 via EtherNet/IP (pycomm3)

Reads PLC1 tags directly (not from Modbus traffic) every poll_interval seconds.
Checks 8 process invariants derived from SWaT P1 P&ID (Adepu & Mathur, IFIP SEC 2016).
Writes /tmp/inv_flag (0 or 1) for fusion.py to read.

Usage:
  python3 invariant_checker.py --plc-ip 192.168.1.10
"""

import argparse, time, json
from datetime import datetime
from pycomm3 import LogixDriver, PycommException

# Tag paths — confirm with lab engineer
TAGS = {
    'MV101' : 'HMI_MV101:O.Data',    # BOOL
    'P101'  : 'HMI_P101:O.Data',     # BOOL
    'P102'  : 'HMI_P102:O.Data',     # BOOL
    'LIT101': 'HMI_LIT101:I.Data',   # REAL (mm)
    'FIT101': 'HMI_FIT101:I.Data',   # REAL (L/s)
}

# Thresholds from SWaT P1 normal operating ranges
LIT_HH = 800.0   # High-high level (mm)
LIT_LL = 250.0   # Low-low level (mm)
FIT_MIN = 0.4    # Minimum flow when MV101 open (m³/h equivalent)


def check_invariants(state: dict) -> list:
    """
    8 SWaT P1 invariants. Returns list of violated invariant IDs.
    """
    mv  = state.get('MV101')   # True=OPEN, False=CLOSED
    p1  = state.get('P101')    # True=ON
    p2  = state.get('P102')    # True=ON
    lit = state.get('LIT101')  # mm float
    fit = state.get('FIT101')  # L/s float

    violations = []

    # I-1: If MV101 open, inflow FIT101 must be > threshold
    if mv is True and fit is not None and fit < FIT_MIN:
        violations.append(('I-1', f'MV101=OPEN but FIT101={fit:.3f} < {FIT_MIN}'))

    # I-2: If P101 on, FIT101 must be > threshold (pump running -> flow)
    if p1 is True and fit is not None and fit < FIT_MIN:
        violations.append(('I-2', f'P101=ON but FIT101={fit:.3f} < {FIT_MIN}'))

    # I-3: If LIT101 > HH, MV101 should be closed (overflow protection)
    if lit is not None and lit > LIT_HH and mv is True:
        violations.append(('I-3', f'LIT101={lit:.1f} > {LIT_HH} but MV101=OPEN'))

    # I-4: If LIT101 < LL, P101 should be off (dry pump protection)
    if lit is not None and lit < LIT_LL and p1 is True:
        violations.append(('I-4', f'LIT101={lit:.1f} < {LIT_LL} but P101=ON'))

    # I-5: If LIT101 < LL, MV101 should open (refill)
    if lit is not None and lit < LIT_LL and mv is False:
        violations.append(('I-5', f'LIT101={lit:.1f} < {LIT_LL} but MV101=CLOSED'))

    # I-6: P101 and P102 cannot both be ON simultaneously (single active pump)
    if p1 is True and p2 is True:
        violations.append(('I-6', 'P101=ON and P102=ON simultaneously'))

    # I-7: If P101=OFF and MV101=CLOSED, FIT101 must be ~0 (no phantom flow)
    if p1 is False and mv is False and fit is not None and fit > FIT_MIN:
        violations.append(('I-7', f'P101=OFF MV101=CLOSED but FIT101={fit:.3f} > 0'))

    # I-8: FIT101 must never exceed physical pipe capacity
    if fit is not None and fit > 2.0:
        violations.append(('I-8', f'FIT101={fit:.3f} exceeds physical max (2.0 L/s)'))

    return violations


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--plc-ip',        required=True)
    ap.add_argument('--poll-interval', type=float, default=1.0)
    ap.add_argument('--flag-file',     default='/tmp/inv_flag')
    args = ap.parse_args()

    print(f"[*] Invariant Checker started  PLC={args.plc_ip}  interval={args.poll_interval}s")
    print(f"    Flag file: {args.flag_file}")

    tag_paths = list(TAGS.values())
    tag_names = list(TAGS.keys())

    cycle = 0
    while True:
        try:
            with LogixDriver(args.plc_ip) as plc:
                while True:
                    results = plc.read(*tag_paths)
                    if not isinstance(results, list):
                        results = [results]

                    state = {}
                    for name, r in zip(tag_names, results):
                        state[name] = r.value if r.error is None else None

                    violations = check_invariants(state)
                    inv_flag = 1 if violations else 0

                    with open(args.flag_file, 'w') as f:
                        f.write(str(inv_flag))

                    cycle += 1
                    ts = datetime.now().strftime('%H:%M:%S')
                    if violations:
                        print(f"[{ts}] cycle={cycle:5d}  *** INVARIANT VIOLATION ***")
                        for inv_id, msg in violations:
                            print(f"             {inv_id}: {msg}")
                    elif cycle % 10 == 0:
                        vals = {k: f"{v:.2f}" if isinstance(v, float) else str(v)
                                for k, v in state.items()}
                        print(f"[{ts}] cycle={cycle:5d}  OK  {vals}")

                    time.sleep(args.poll_interval)

        except PycommException as e:
            print(f"[!] EtherNet/IP error: {e} — reconnecting in 3s...")
            with open(args.flag_file, 'w') as f:
                f.write('0')
            time.sleep(3)

if __name__ == '__main__':
    main()
