"""
recovery_agent.py — SWaT Shallow Recovery Orchestrator

Executes the 5-step shallow recovery pipeline when triggered by fusion.py:
    Step 1: Log incident + notify operator
    Step 2: Network isolation (iptables drop port 502, VLAN isolate attacker)
    Step 3: Write safe-state values to all PLC stages via Modbus
    Step 4: Trigger PLC1 hot-standby failover (EtherNet/IP)
    Step 5: Verify recovery — wait for 5 clean invariant cycles, then resume

Target recovery time: < 15 seconds

Usage:
    sudo python3 recovery_agent.py --plc-ip 192.168.1.10 --attacker-mac AA:BB:CC:DD:EE:FF

Safe State Table (SWaT all stages):
    P1: MV101=CLOSED, P101=OFF, P102=OFF
    P2: P201–P206=ALL OFF
    P3: MV301=CLOSED, P301=OFF, P302=OFF
    P4: UV401=OFF
    P6: P602=OFF

Author: SWaT CPS Security Project Team, SUTD 51.508
"""

import argparse
import json
import logging
import os
import subprocess
import time
from datetime import datetime

from pymodbus.client import ModbusTcpClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [RECOVERY] %(levelname)s %(message)s"
)
log = logging.getLogger("recovery_agent")

INCIDENT_LOG = "incident_log.json"
RECOVERY_LOG = "recovery_log.json"

# ── Safe State Register Map ────────────────────────────────────────────────────
# Format: (register_type, address, value)  value: 0=OFF/CLOSED, 1=ON/OPEN
# Fill addresses from Phase 0 recon output
SAFE_STATE = {
    # Stage P1
    "MV101": ("coil", 1, 0),   # CLOSED
    "P101":  ("coil", 2, 0),   # OFF
    "P102":  ("coil", 3, 0),   # OFF
    # Stage P2
    "P201":  ("coil", 10, 0),
    "P202":  ("coil", 11, 0),
    "P203":  ("coil", 12, 0),
    "P204":  ("coil", 13, 0),
    "P205":  ("coil", 14, 0),
    "P206":  ("coil", 15, 0),
    # Stage P3
    "MV301": ("coil", 20, 0),
    "P301":  ("coil", 21, 0),
    "P302":  ("coil", 22, 0),
    # Stage P4
    "UV401": ("coil", 30, 0),
    # Stage P6
    "P602":  ("coil", 50, 0),
}

# Invariant flag path (written by invariant_checker.py)
INV_FLAG_PATH = "/tmp/inv_flag"
VERIFY_CYCLES = 5       # clean cycles needed to declare recovery success
VERIFY_TIMEOUT = 60     # seconds before declaring recovery failure


def log_incident(attacker_ip, attacker_mac):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "event": "ATTACK_DETECTED",
        "attacker_ip":  attacker_ip,
        "attacker_mac": attacker_mac,
        "action": "recovery_initiated",
    }
    with open(INCIDENT_LOG, "a") as f:
        json.dump(entry, f)
        f.write("\n")
    log.error(f"INCIDENT LOGGED: attacker={attacker_ip} ({attacker_mac})")


def step1_notify(args):
    log.info("── STEP 1: Incident logging & operator notification ──")
    log_incident(args.attacker_ip, args.attacker_mac)
    # TODO: integrate with SIEM/email/SMS notification here
    log.info("  ✓ Incident logged")


def step2_isolate(args):
    log.info("── STEP 2: Network isolation ──")
    # Block Modbus port 502 ingress from attacker
    if args.attacker_ip:
        cmd = f"iptables -I INPUT -s {args.attacker_ip} -p tcp --dport 502 -j DROP"
        ret = subprocess.run(cmd, shell=True, capture_output=True)
        if ret.returncode == 0:
            log.info(f"  ✓ iptables: dropped port 502 from {args.attacker_ip}")
        else:
            log.warning(f"  ✗ iptables failed: {ret.stderr.decode().strip()}")

    # VLAN isolate attacker MAC (requires managed switch CLI — stub)
    if args.attacker_mac:
        log.info(f"  ⚠ VLAN isolation for {args.attacker_mac} — configure on managed switch")
        # TODO: SSH to switch and run: switchport access vlan <quarantine_vlan>


def step3_safe_state(client):
    log.info("── STEP 3: Writing safe-state values to PLCs ──")
    success = 0
    for actuator, (reg_type, addr, value) in SAFE_STATE.items():
        if reg_type == "coil":
            rr = client.write_coil(addr, bool(value), slave=1)
            if not rr.isError():
                log.info(f"  ✓ {actuator} → {'OPEN' if value else 'CLOSED/OFF'}")
                success += 1
            else:
                log.error(f"  ✗ Failed to write {actuator}")
        time.sleep(0.05)   # small delay between writes
    log.info(f"  Safe state: {success}/{len(SAFE_STATE)} actuators written")


def step4_failover(args):
    log.info("── STEP 4: PLC1 hot-standby failover ──")
    # EtherNet/IP failover: write ownership transfer to PLC1B
    # In Allen Bradley ControlLogix, the hot-standby partner takes over
    # when primary is declared faulted. This stub logs the action.
    # TODO: Use pylogix or pycomm3 to write Controller.OwnershipTransfer tag
    log.info(f"  ⚠ EtherNet/IP failover: PLC1A → PLC1B")
    log.info(f"    Requires pylogix: cl.Write('Program:MainProgram.OwnershipTransfer', 1)")
    log.info(f"    Standby PLC1B IP: {args.standby_plc_ip or 'NOT SET — configure --standby-plc-ip'}")


def step5_verify(interval=1.0):
    log.info("── STEP 5: Verifying recovery ──")
    clean = 0
    elapsed = 0.0
    while clean < VERIFY_CYCLES and elapsed < VERIFY_TIMEOUT:
        try:
            with open(INV_FLAG_PATH) as f:
                flag = int(f.read().strip())
        except Exception:
            flag = 1   # assume violated if unreadable

        if flag == 0:
            clean += 1
            log.info(f"  Clean cycle {clean}/{VERIFY_CYCLES}")
        else:
            clean = 0
            log.warning(f"  Invariant still violated — reset clean counter")

        time.sleep(interval)
        elapsed += interval

    if clean >= VERIFY_CYCLES:
        log.info("  ✓ RECOVERY SUCCESSFUL — all invariants pass")
        return True
    else:
        log.error("  ✗ RECOVERY FAILED — invariants still violated after timeout")
        return False


def main():
    parser = argparse.ArgumentParser(description="SWaT Shallow Recovery Agent")
    parser.add_argument("--plc-ip",        required=True)
    parser.add_argument("--plc-port",      type=int, default=502)
    parser.add_argument("--attacker-ip",   default="")
    parser.add_argument("--attacker-mac",  default="")
    parser.add_argument("--standby-plc-ip",default="")
    parser.add_argument("--interval",      type=float, default=1.0)
    args = parser.parse_args()

    t_start = time.time()
    log.error("═══════════════════════════════════════════════════")
    log.error("  RECOVERY PIPELINE INITIATED")
    log.error("═══════════════════════════════════════════════════")

    client = ModbusTcpClient(args.plc_ip, port=args.plc_port)
    if not client.connect():
        log.error(f"Cannot connect to PLC at {args.plc_ip}:{args.plc_port}")
        return

    try:
        step1_notify(args)
        step2_isolate(args)
        step3_safe_state(client)
        step4_failover(args)
        success = step5_verify(args.interval)
    finally:
        client.close()

    elapsed = time.time() - t_start
    result = {
        "timestamp": datetime.utcnow().isoformat(),
        "success": success,
        "elapsed_s": round(elapsed, 2),
        "attacker_ip":  args.attacker_ip,
        "attacker_mac": args.attacker_mac,
    }
    with open(RECOVERY_LOG, "w") as f:
        json.dump(result, f, indent=2)

    log.error(f"Recovery {'SUCCEEDED' if success else 'FAILED'} in {elapsed:.1f}s")


if __name__ == "__main__":
    main()
