#!/usr/bin/env python3
"""
invariant_checker.py  —  SWaT P1 Process Invariant Checker
Target: Allen-Bradley ControlLogix PLC1 via pylogix

Usage:
  python3 invariant_checker.py --plc-ip 192.168.1.10
"""

import argparse, time
from datetime import datetime
from pylogix import PLC

READ_TAGS = [
    'HMI_LIT101.Pv',
    'AI_FIT_101_FLOW',
    'HMI_MV101.Cmd',
    'HMI_P101.Auto',
    'HMI_P102.Auto',
]

LIT_HH  = 800.0
LIT_LL  = 250.0
FIT_MIN = 0.4


def check_invariants(state):
    lit = state.get('HMI_LIT101.Pv')
    fit = state.get('AI_FIT_101_FLOW')
    mv  = state.get('HMI_MV101.Cmd')      # 2=OPEN, 1=CLOSED
    p1  = state.get('HMI_P101.Auto')     # True=auto/running, False=manual/off
    p2  = state.get('HMI_P102.Auto')

    violations = []
    mv_open  = (mv == 2) if mv is not None else None
    mv_closed= (mv == 1) if mv is not None else None
    p1_on    = (p1 == True) if p1 is not None else None   # Auto=True → PLC running P101
    p2_on    = (p2 == True) if p2 is not None else None   # Auto=True → PLC running P102

    if mv_open and fit is not None and fit < FIT_MIN:
        violations.append(('I-1', f'MV101=OPEN but FIT101={fit:.3f} < {FIT_MIN}'))
    if p1_on and fit is not None and fit < FIT_MIN:
        violations.append(('I-2', f'P101=ON but FIT101={fit:.3f} < {FIT_MIN}'))
    if lit is not None and lit > LIT_HH and mv_open:
        violations.append(('I-3', f'LIT101={lit:.1f} > {LIT_HH} but MV101=OPEN'))
    if lit is not None and lit < LIT_LL and p1_on:
        violations.append(('I-4', f'LIT101={lit:.1f} < {LIT_LL} but P101=ON'))
    if lit is not None and lit < LIT_LL and mv_closed:
        violations.append(('I-5', f'LIT101={lit:.1f} < {LIT_LL} but MV101=CLOSED'))
    if p1_on and p2_on:
        violations.append(('I-6', 'P101=ON and P102=ON simultaneously'))
    if not p1_on and mv_closed and fit is not None and fit > FIT_MIN:
        violations.append(('I-7', f'P101=OFF MV101=CLOSED but FIT101={fit:.3f} > 0'))
    if fit is not None and fit > 2.0:
        violations.append(('I-8', f'FIT101={fit:.3f} exceeds max (2.0)'))
    # I-9: MV101=CLOSED and P101=OFF while level is in normal operating range
    # This is the key signature of a Phase 1 attack — both stopped simultaneously
    # I-9: MV101=CLOSED AND P101=ON (running) in normal operating range
    #       Valve closed while pump runs = tank actively draining with no refill
    #       This is the key Phase 1 attack signature — causes pump cavitation
    if mv_closed and p1_on and lit is not None and 300 < lit < 850:
        violations.append(('I-9', f'MV101=CLOSED but P101=ON — tank draining with no inflow, LIT101={lit:.1f}mm — Phase 1 attack signature'))
    return violations


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--plc-ip',        default='192.168.1.10')
    ap.add_argument('--poll-interval', type=float, default=1.0)
    ap.add_argument('--flag-file',     default='/tmp/inv_flag')
    args = ap.parse_args()

    print(f"[*] Invariant Checker  PLC={args.plc_ip}  interval={args.poll_interval}s")
    cycle = 0
    while True:
        try:
            with PLC() as plc:
                plc.IPAddress = args.plc_ip
                while True:
                    results = plc.Read(READ_TAGS)
                    if not isinstance(results, list):
                        results = [results]
                    state = {r.TagName: r.Value for r in results if r.Value is not None}
                    violations = check_invariants(state)
                    inv_flag = 1 if violations else 0
                    with open(args.flag_file, 'w') as f:
                        f.write(str(inv_flag))
                    cycle += 1
                    ts = datetime.now().strftime('%H:%M:%S')
                    if violations:
                        print(f"[{ts}] cycle={cycle:5d}  *** VIOLATION ***")
                        for inv_id, msg in violations:
                            print(f"             {inv_id}: {msg}")
                    elif cycle % 10 == 0:
                        print(f"[{ts}] cycle={cycle:5d}  OK  {state}")
                    time.sleep(args.poll_interval)
        except Exception as e:
            print(f"[!] Error: {e} — reconnecting in 3s...")
            with open(args.flag_file, 'w') as f:
                f.write('0')
            time.sleep(3)

if __name__ == '__main__':
    main()
