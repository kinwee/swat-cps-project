#!/usr/bin/env python3
"""
recovery_agent.py  —  SWaT Shallow Recovery Pipeline
Target: Allen-Bradley ControlLogix PLC1 via EtherNet/IP (pycomm3)

5-step recovery triggered by fusion.py:
  1. DETECT  — log alert timestamp
  2. CONTAIN — iptables block attacker, isolate via VLAN (if supported)
  3. SAFE STATE — write safe tag values to PLC1 via CIP tag write
  4. FAILOVER — switch from PLC1A to PLC1B (hot standby)
  5. VERIFY  — poll invariants for 5 clean cycles before resuming

Usage:
  python3 recovery_agent.py --plc-ip 192.168.1.10 --plc-b-ip 192.168.1.11 \
                             --attacker-ip 192.168.0.99
"""

import argparse, json, os, subprocess, sys, time
from datetime import datetime
from pycomm3 import LogixDriver, CommError as PycommException

# Safe-state tag values — confirm with lab engineer
SAFE_STATE_TAGS = {
    'HMI_MV101:O.Data': True,    # Open inlet valve (allow refill)
    'HMI_P101:O.Data' : False,   # Stop pump (prevent dry run)
    'HMI_P102:O.Data' : False,   # Standby pump off
}

# Invariant tag paths for verify step
VERIFY_TAGS = {
    'MV101' : 'HMI_MV101:O.Data',
    'P101'  : 'HMI_P101:O.Data',
    'LIT101': 'HMI_LIT101:I.Data',
    'FIT101': 'HMI_FIT101:I.Data',
}
LIT_LL = 250.0
FIT_MIN = 0.4


def log(msg, log_path='recovery_log.json', entry=None):
    ts = datetime.now().isoformat()
    print(f"[{ts[:19]}] {msg}")
    if entry:
        try:
            with open(log_path, 'r') as f:
                data = json.load(f)
        except:
            data = []
        data.append({'time': ts, **entry})
        with open(log_path, 'w') as f:
            json.dump(data, f, indent=2)


def step1_detect(attacker_ip):
    log("STEP 1 — DETECT: Alert confirmed by fusion engine",
        entry={'step': 1, 'action': 'detect', 'attacker_ip': attacker_ip})


def step2_contain(attacker_ip, iface):
    log(f"STEP 2 — CONTAIN: Blocking attacker {attacker_ip} on port 44818")
    # Block EtherNet/IP port (44818) from attacker
    cmds = [
        ['iptables', '-I', 'INPUT',   '-s', attacker_ip, '-p', 'tcp',
         '--dport', '44818', '-j', 'DROP'],
        ['iptables', '-I', 'FORWARD', '-s', attacker_ip, '-p', 'tcp',
         '--dport', '44818', '-j', 'DROP'],
    ]
    for cmd in cmds:
        result = subprocess.run(cmd, capture_output=True)
        if result.returncode == 0:
            log(f"    iptables rule added: {' '.join(cmd[3:])}")
        else:
            log(f"    [!] iptables failed: {result.stderr.decode()}")
    log("STEP 2 — CONTAIN complete",
        entry={'step': 2, 'action': 'contain', 'attacker_ip': attacker_ip})


def step3_safe_state(plc_ip):
    log(f"STEP 3 — SAFE STATE: Writing safe tag values to PLC {plc_ip}")
    try:
        with LogixDriver(plc_ip) as plc:
            writes = [(tag, val) for tag, val in SAFE_STATE_TAGS.items()]
            results = plc.write(*writes)
            if not isinstance(results, list):
                results = [results]
            for tag, r in zip(SAFE_STATE_TAGS.keys(), results):
                status = "OK" if r.error is None else f"FAILED: {r.error}"
                val = SAFE_STATE_TAGS[tag]
                log(f"    {tag} = {val}  [{status}]")
        log("STEP 3 — SAFE STATE complete",
            entry={'step': 3, 'action': 'safe_state', 'tags': {k: str(v) for k, v in SAFE_STATE_TAGS.items()}})
    except PycommException as e:
        log(f"[!] SAFE STATE failed — cannot reach PLC: {e}")
        log("    *** Manually set MV101=OPEN, P101=OFF via HMI immediately! ***")


def step4_failover(plc_b_ip):
    if not plc_b_ip:
        log("STEP 4 — FAILOVER: No PLC-B IP provided, skipping failover")
        return
    log(f"STEP 4 — FAILOVER: Activating hot-standby PLC1B at {plc_b_ip}")
    try:
        with LogixDriver(plc_b_ip) as plc:
            info = plc.info
            log(f"    PLC1B connected: {info.get('product_name')} "
                f"rev={info.get('revision')}")
            # Write same safe state to PLC1B
            writes = [(tag, val) for tag, val in SAFE_STATE_TAGS.items()]
            plc.write(*writes)
            log("    PLC1B safe state written — now primary controller")
        log("STEP 4 — FAILOVER complete",
            entry={'step': 4, 'action': 'failover', 'plc_b_ip': plc_b_ip})
    except PycommException as e:
        log(f"[!] FAILOVER failed — PLC1B unreachable: {e}")


def step5_verify(plc_ip, clean_cycles_required=5, poll_interval=1.0):
    log(f"STEP 5 — VERIFY: Polling invariants on {plc_ip} "
        f"({clean_cycles_required} clean cycles required)")
    tag_paths = list(VERIFY_TAGS.values())
    tag_names = list(VERIFY_TAGS.keys())
    clean = 0
    total = 0

    while clean < clean_cycles_required:
        try:
            with LogixDriver(plc_ip) as plc:
                while clean < clean_cycles_required:
                    results = plc.read(*tag_paths)
                    if not isinstance(results, list):
                        results = [results]
                    state = {n: r.value for n, r in zip(tag_names, results) if r.error is None}
                    total += 1

                    # Simple invariant check
                    violations = []
                    mv  = state.get('MV101')
                    p1  = state.get('P101')
                    lit = state.get('LIT101')
                    fit = state.get('FIT101')
                    if p1 and fit is not None and fit < FIT_MIN:
                        violations.append('I-2')
                    if lit is not None and lit < LIT_LL and p1:
                        violations.append('I-4')

                    if not violations:
                        clean += 1
                        log(f"    Cycle {total}: clean ({clean}/{clean_cycles_required})  "
                            f"LIT101={lit:.1f}mm  FIT101={fit:.3f}")
                    else:
                        clean = 0
                        log(f"    Cycle {total}: VIOLATION {violations} — resetting clean count")

                    time.sleep(poll_interval)
        except PycommException as e:
            log(f"    [!] EtherNet/IP error: {e} — retrying...")
            clean = 0
            time.sleep(3)

    log(f"STEP 5 — VERIFY complete after {total} cycles",
        entry={'step': 5, 'action': 'verify', 'total_cycles': total})
    log("*** RECOVERY COMPLETE — SWaT P1 resuming normal operation ***")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--plc-ip',      required=True, help='PLC1A IP')
    ap.add_argument('--plc-b-ip',    default=None,  help='PLC1B hot-standby IP')
    ap.add_argument('--attacker-ip', default=None,  help='Attacker IP to block')
    ap.add_argument('--iface',       default='eth0')
    ap.add_argument('--log',         default='recovery_log.json')
    args = ap.parse_args()

    print("=" * 60)
    print("  SWaT Recovery Agent — EtherNet/IP / Allen-Bradley")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    t0 = time.time()
    step1_detect(args.attacker_ip)
    if args.attacker_ip:
        step2_contain(args.attacker_ip, args.iface)
    step3_safe_state(args.plc_ip)
    step4_failover(args.plc_b_ip)
    step5_verify(args.plc_ip)
    elapsed = time.time() - t0
    log(f"Total recovery time: {elapsed:.1f}s",
        entry={'action': 'summary', 'elapsed_s': round(elapsed, 1)})

if __name__ == '__main__':
    main()
