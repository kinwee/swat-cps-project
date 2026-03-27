#!/usr/bin/env python3
"""
phase0_recon.py  —  SWaT Phase 0: Reconnaissance & Tag Database Building
Target: Allen-Bradley ControlLogix PLCs via pylogix (EtherNet/IP port 44818)

Usage:
  sudo python3 phase0_recon.py --plc-ip 192.168.1.10 --iface eth0 --duration 1800
"""

import argparse, json, pickle, subprocess, time, threading
from collections import defaultdict
from datetime import datetime
from pylogix import PLC
from scapy.all import sniff, wrpcap, TCP, Raw

ENIP_PORT = 44818

# Real SWaT P1 tag names (confirmed from lab reference script)
P1_TAGS = [
    'HMI_LIT101.Pv',      # Level transmitter (mm)
    'AI_FIT_101_FLOW',     # Flow transmitter (L/s)
    'HMI_MV101.Cmd',       # Motorised valve command
    'HMI_MV101.Auto',      # Valve auto mode
    'HMI_P101.Auto',       # Pump 101 auto mode
    'HMI_P102.Auto',       # Pump 102 auto mode
]

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
    return hosts


def read_plc_identity(ip):
    print(f"\n[*] Connecting to PLC at {ip} via pylogix...")
    identity = {'ip': ip, 'tags': {}}
    try:
        with PLC() as plc:
            plc.IPAddress = ip
            for tag in P1_TAGS:
                ret = plc.Read(tag)
                identity['tags'][tag] = {'value': ret.Value, 'status': str(ret.Status)}
                print(f"    {tag:30s}: {ret.Value}  [{ret.Status}]")
                if ret.Value is not None:
                    tag_db[tag].append((time.time(), ret.Value))
    except Exception as e:
        print(f"    [-] Connection failed: {e}")
    return identity


def packet_callback(pkt):
    if TCP in pkt and (pkt[TCP].dport == ENIP_PORT or pkt[TCP].sport == ENIP_PORT):
        captured_packets.append(pkt)
        if Raw in pkt:
            direction = "->PLC" if pkt[TCP].dport == ENIP_PORT else "<-PLC"
            print(f"    [ENIP] {direction}  {len(pkt[Raw].load):4d}B")


def sniff_thread_fn(iface, duration, pcap_file):
    print(f"\n[*] Sniffing EtherNet/IP on {iface} for {duration}s...")
    sniff(iface=iface, filter=f"tcp port {ENIP_PORT}",
          prn=packet_callback, timeout=duration, store=False)
    if captured_packets:
        wrpcap(pcap_file, captured_packets)
        print(f"[+] {len(captured_packets)} packets -> {pcap_file}")


def poll_tags(ip, duration, interval=1.0):
    print(f"\n[*] Polling tags on {ip} every {interval}s for {duration}s...")
    end_time = time.time() + duration
    n = 0
    with PLC() as plc:
        plc.IPAddress = ip
        while time.time() < end_time:
            ts = time.time()
            results = plc.Read(P1_TAGS)
            if not isinstance(results, list):
                results = [results]
            for r in results:
                if r.Value is not None:
                    tag_db[r.TagName].append((ts, r.Value))
            n += 1
            if n % 10 == 0:
                snapshot = {r.TagName: r.Value for r in results}
                print(f"    [poll {n:4d}] {snapshot}")
            time.sleep(interval)
    print(f"[+] {n} poll cycles")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--subnet',   default='192.168.1.0/24')
    ap.add_argument('--plc-ip',   default='192.168.1.10')
    ap.add_argument('--iface',    default='eth0')
    ap.add_argument('--duration', type=int, default=1800)
    ap.add_argument('--db',       default='enip_db.pkl')
    ap.add_argument('--pcap',     default='swat_capture.pcap')
    ap.add_argument('--no-sniff', action='store_true')
    args = ap.parse_args()

    print("=" * 60)
    print("  SWaT Phase 0  —  Recon (pylogix / Allen-Bradley)")
    print(f"  PLC: {args.plc_ip}   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    read_plc_identity(args.plc_ip)

    if not args.no_sniff:
        t = threading.Thread(target=sniff_thread_fn,
                             args=(args.iface, args.duration, args.pcap), daemon=True)
        t.start()

    poll_tags(args.plc_ip, args.duration)

    if not args.no_sniff:
        t.join()

    with open(args.db, 'wb') as f:
        pickle.dump(dict(tag_db), f)
    print(f"\n[+] Tag DB saved: {args.db}  ({len(tag_db)} tags, "
          f"{sum(len(v) for v in tag_db.values())} samples)")

    with open('recon_results.json', 'w') as f:
        json.dump([{'ip': args.plc_ip, 'tags': {k: str(v[-1][1]) if v else None
                    for k, v in tag_db.items()}}], f, indent=2)
    print(f"[+] Recon JSON saved: recon_results.json")

if __name__ == '__main__':
    main()
