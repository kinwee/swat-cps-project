#!/usr/bin/env python3
"""
phase0_recon.py  —  SWaT Phase 0: Reconnaissance & Tag Database Building
Target: Allen-Bradley ControlLogix PLCs over EtherNet/IP (TCP port 44818)

What this does:
  1. NMAP SYN scan for EtherNet/IP port 44818 on the OT subnet
  2. Connects to each discovered PLC via pycomm3 and reads identity + P1 tags
  3. Continuously polls tags to build a timestamped value database
  4. Scapy-sniffs raw EtherNet/IP packets in parallel
  5. Saves: enip_db.pkl, recon_results.json, swat_capture.pcap

Usage:
  sudo python3 phase0_recon.py --subnet 192.168.0.0/24 --iface eth0 --duration 1800

Dependencies:
  pip install pycomm3 scapy
"""

import argparse, json, os, pickle, subprocess, time, threading
from collections import defaultdict
from datetime import datetime

from pycomm3 import LogixDriver, PycommException
from scapy.all import sniff, wrpcap, TCP, Raw

ENIP_PORT = 44818

# SWaT P1 ControlLogix tag paths (Studio 5000 / RSLogix 5000 naming)
# *** Confirm exact tag names with lab engineer before running ***
P1_TAGS = {
    'MV101' : 'HMI_MV101:O.Data',   # Motor valve 101 — BOOL output
    'P101'  : 'HMI_P101:O.Data',    # Pump 101 — BOOL output
    'P102'  : 'HMI_P102:O.Data',    # Pump 102 standby — BOOL output
    'LIT101': 'HMI_LIT101:I.Data',  # Level transmitter — REAL (mm)
    'FIT101': 'HMI_FIT101:I.Data',  # Flow transmitter — REAL (L/s)
}

captured_packets = []
tag_db = defaultdict(list)   # tag_name -> [(timestamp, value), ...]


def scan_enip_hosts(subnet):
    print(f"[*] Scanning {subnet} for EtherNet/IP (port {ENIP_PORT})...")
    result = subprocess.run(
        ['nmap', '-sS', '-p', str(ENIP_PORT), '--open', '-oG', '-', subnet],
        capture_output=True, text=True
    )
    hosts = []
    for line in result.stdout.splitlines():
        if 'open' in line and 'Host:' in line:
            ip = line.split()[1]
            hosts.append(ip)
            print(f"    [+] EtherNet/IP host: {ip}")
    if not hosts:
        print("    [-] No hosts found. Verify subnet and that SWaT is running.")
    return hosts


def read_plc_identity(ip):
    print(f"\n[*] Connecting to ControlLogix PLC at {ip}...")
    identity = {'ip': ip, 'tags': {}}
    try:
        with LogixDriver(ip) as plc:
            info = plc.info
            identity.update({
                'product_name': info.get('product_name'),
                'vendor'      : info.get('vendor'),
                'revision'    : info.get('revision'),
                'serial'      : info.get('serial'),
            })
            print(f"    Product : {identity['product_name']}")
            print(f"    Vendor  : {identity['vendor']}")
            print(f"    Revision: {identity['revision']}")

            print("    [*] Reading P1 tags...")
            for name, tag_path in P1_TAGS.items():
                try:
                    r = plc.read(tag_path)
                    identity['tags'][name] = {'path': tag_path, 'value': r.value, 'type': str(r.type)}
                    print(f"        {name:8s}: {r.value}  ({r.type})")
                    tag_db[name].append((time.time(), r.value))
                except Exception as e:
                    identity['tags'][name] = {'path': tag_path, 'error': str(e)}
                    print(f"        {name:8s}: ERROR — {e}")
    except PycommException as e:
        print(f"    [-] Connection failed: {e}")
        print(f"        Check: PLC IP correct? EtherNet/IP enabled? Slot number?")
    return identity


def packet_callback(pkt):
    if TCP in pkt and (pkt[TCP].dport == ENIP_PORT or pkt[TCP].sport == ENIP_PORT):
        captured_packets.append(pkt)
        if Raw in pkt:
            direction = "→PLC" if pkt[TCP].dport == ENIP_PORT else "←PLC"
            print(f"    [ENIP] {direction}  {len(pkt[Raw].load):4d}B  seq={pkt[TCP].seq}")


def sniff_thread_fn(iface, duration, pcap_file):
    print(f"\n[*] Sniffing EtherNet/IP on {iface} for {duration}s (tcp port {ENIP_PORT})...")
    sniff(iface=iface, filter=f"tcp port {ENIP_PORT}",
          prn=packet_callback, timeout=duration, store=False)
    if captured_packets:
        wrpcap(pcap_file, captured_packets)
        print(f"[+] {len(captured_packets)} packets saved to {pcap_file}")
    else:
        print("[-] No EtherNet/IP packets captured.")


def poll_tags(ip, duration, interval=1.0):
    print(f"\n[*] Polling tags on {ip} every {interval}s for {duration}s...")
    end_time = time.time() + duration
    n = 0
    try:
        with LogixDriver(ip) as plc:
            tag_paths = list(P1_TAGS.values())
            while time.time() < end_time:
                ts = time.time()
                try:
                    results = plc.read(*tag_paths)
                    if not isinstance(results, list):
                        results = [results]
                    for name, r in zip(P1_TAGS.keys(), results):
                        if r.error is None:
                            tag_db[name].append((ts, r.value))
                    n += 1
                    if n % 10 == 0:
                        snapshot = {k: tag_db[k][-1][1] for k in P1_TAGS if tag_db[k]}
                        print(f"    [poll {n:4d}] {snapshot}")
                except Exception as e:
                    print(f"    [!] Poll error: {e}")
                time.sleep(interval)
    except PycommException as e:
        print(f"[-] Connection lost: {e}")
    print(f"[+] {n} poll cycles, {sum(len(v) for v in tag_db.values())} total samples")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--subnet',   default='192.168.0.0/24')
    ap.add_argument('--plc-ip',   default=None, help='Skip scan, use this IP directly')
    ap.add_argument('--iface',    default='eth0')
    ap.add_argument('--duration', type=int, default=1800, help='Sniff/poll duration in seconds')
    ap.add_argument('--db',       default='enip_db.pkl')
    ap.add_argument('--pcap',     default='swat_capture.pcap')
    ap.add_argument('--no-sniff', action='store_true')
    args = ap.parse_args()

    print("=" * 60)
    print("  SWaT Phase 0  —  EtherNet/IP Recon (Allen-Bradley)")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    plc_hosts = [args.plc_ip] if args.plc_ip else scan_enip_hosts(args.subnet)
    if not plc_hosts:
        return

    recon_results = [read_plc_identity(ip) for ip in plc_hosts]

    # Sniff in background, poll in foreground
    if not args.no_sniff:
        t = threading.Thread(target=sniff_thread_fn,
                             args=(args.iface, args.duration, args.pcap), daemon=True)
        t.start()

    poll_tags(plc_hosts[0], args.duration)

    if not args.no_sniff:
        t.join()

    # Save outputs
    with open(args.db, 'wb') as f:
        pickle.dump(dict(tag_db), f)
    print(f"\n[+] Tag DB saved: {args.db}  ({len(tag_db)} tags)")

    for r in recon_results:
        for v in r.get('tags', {}).values():
            v['value'] = str(v.get('value'))
    with open('recon_results.json', 'w') as f:
        json.dump(recon_results, f, indent=2)
    print(f"[+] Recon JSON saved: recon_results.json")

    print("\n[*] Tag value ranges observed:")
    for name, samples in tag_db.items():
        vals = [v for _, v in samples if v is not None]
        if vals:
            try:    print(f"    {name:8s}: min={min(vals):.3f}  max={max(vals):.3f}  n={len(vals)}")
            except: print(f"    {name:8s}: {vals[:3]}  n={len(vals)}")

if __name__ == '__main__':
    main()
