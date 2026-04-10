#!/usr/bin/env python3
"""
recovery_agent.py  —  SWaT Shallow Recovery Pipeline
Target: Allen-Bradley ControlLogix PLC1 + PLC2 via pylogix

5-Step Pipeline:
  1. DETECT    — log incident to recovery_log.json
  2. CONTAIN   — iptables block attacker IP on port 44818 (if --attacker-ip given)
  3. SAFE STATE— PLC1: MV101=OPEN, P101=ON (auto)
                 PLC2: MV201=CLOSED (auto) — restore from attack-opened state
  4. FAILOVER  — write safe state to PLC1B (192.168.1.11)
  5. VERIFY    — 5 consecutive clean invariant cycles on PLC1

Usage:
  python3 recovery_agent.py --plc-ip 192.168.1.10 --plc2-ip 192.168.1.20 \
      --plc-b-ip 192.168.1.11
"""

import argparse, json, os, subprocess, time
from datetime import datetime
from pylogix import PLC

# PLC1 safe state: MV101=OPEN, P101=ON
SAFE_STATE_PLC1 = [
    ('HMI_MV101.Auto', False),
    ('HMI_MV101.Cmd',  2),       # 2=OPEN — restore inlet valve
    ('HMI_MV101.Auto', True),    # return to auto
    ('HMI_P101.Auto',  False),
    ('HMI_P101.Cmd',   2),       # 2=ON — restore pump
    ('HMI_P101.Auto',  True),    # return to auto
]

# PLC2 safe state: MV201=CLOSED (attack opened it to force outflow to P2)
SAFE_STATE_PLC2 = [
    ('HMI_MV201.Auto', False),
    ('HMI_MV201.Cmd',  1),       # 1=CLOSE — stop forced outflow to P2
    ('HMI_MV201.Auto', True),    # return to auto
]

# Keep backward compat alias
SAFE_STATE = SAFE_STATE_PLC1

READ_TAGS  = ['HMI_LIT101.Pv', 'AI_FIT_101_FLOW', 'HMI_MV101.Cmd', 'HMI_P101.Auto']
LIT_LL     = 250.0
FIT_MIN    = 0.4
LOG_PATH   = 'recovery_log.json'


def log(msg, entry=None):
    ts = datetime.now().isoformat()
    print(f"[{ts[:19]}] {msg}")
    if entry:
        try:
            with open(LOG_PATH) as f: data = json.load(f)
        except: data = []
        data.append({'time': ts, **entry})
        with open(LOG_PATH, 'w') as f: json.dump(data, f, indent=2)


def write_tag(ip, tag, value):
    with PLC() as plc:
        plc.IPAddress = ip
        plc.Write(tag, value)


def step1_detect(attacker_ip):
    log("STEP 1 — DETECT", entry={'step': 1, 'action': 'detect', 'attacker_ip': attacker_ip})


def step2_contain(attacker_ip):
    log(f"STEP 2 — CONTAIN: blocking {attacker_ip} port 44818")
    for cmd in [
        ['iptables', '-I', 'INPUT',   '-s', attacker_ip, '-p', 'tcp', '--dport', '44818', '-j', 'DROP'],
        ['iptables', '-I', 'FORWARD', '-s', attacker_ip, '-p', 'tcp', '--dport', '44818', '-j', 'DROP'],
    ]:
        r = subprocess.run(cmd, capture_output=True)
        status = "OK" if r.returncode == 0 else r.stderr.decode()
        log(f"    {' '.join(cmd[3:])}: {status}")
    log("STEP 2 — CONTAIN complete", entry={'step': 2, 'action': 'contain'})


def step3_safe_state(plc_ip, plc2_ip):
    log(f"STEP 3 — SAFE STATE: PLC1={plc_ip}  PLC2={plc2_ip}")
    # Restore PLC1: MV101=OPEN, P101=ON
    try:
        with PLC() as plc:
            plc.IPAddress = plc_ip
            for tag, val in SAFE_STATE_PLC1:
                plc.Write(tag, val)
                log(f"    PLC1  {tag} = {val}")
        log("STEP 3a — PLC1 safe state written")
    except Exception as e:
        log(f"[!] PLC1 SAFE STATE failed: {e}")
        log("    *** Manually restore MV101=OPEN, P101=ON via HMI! ***")

    # Restore PLC2: MV201=CLOSED
    try:
        with PLC() as plc:
            plc.IPAddress = plc2_ip
            for tag, val in SAFE_STATE_PLC2:
                plc.Write(tag, val)
                log(f"    PLC2  {tag} = {val}")
        log("STEP 3b — PLC2 safe state written")
    except Exception as e:
        log(f"[!] PLC2 SAFE STATE failed: {e}")
        log("    *** Manually restore MV201=CLOSED via HMI! ***")

    log("STEP 3 — SAFE STATE complete", entry={'step': 3, 'action': 'safe_state',
        'plc1': plc_ip, 'plc2': plc2_ip})


def step4_failover(plc_b_ip):
    if not plc_b_ip:
        log("STEP 4 — FAILOVER: no PLC-B IP, skipping")
        return
    log(f"STEP 4 — FAILOVER -> PLC1B {plc_b_ip}")
    try:
        with PLC() as plc:
            plc.IPAddress = plc_b_ip
            for tag, val in SAFE_STATE:
                plc.Write(tag, val)
        log("STEP 4 — FAILOVER complete", entry={'step': 4, 'action': 'failover', 'plc_b': plc_b_ip})
    except Exception as e:
        log(f"[!] FAILOVER failed: {e}")


def step5_verify(plc_ip, clean_required=5, interval=1.0):
    log(f"STEP 5 — VERIFY: need {clean_required} clean cycles")
    clean = 0; total = 0
    while clean < clean_required:
        try:
            with PLC() as plc:
                plc.IPAddress = plc_ip
                while clean < clean_required:
                    results = plc.Read(READ_TAGS)
                    if not isinstance(results, list): results = [results]
                    state = {r.TagName: r.Value for r in results if r.Value is not None}
                    total += 1
                    violations = []
                    p1  = state.get('HMI_P101.Auto')
                    fit = state.get('AI_FIT_101_FLOW')
                    lit = state.get('HMI_LIT101.Pv')
                    if p1 and fit is not None and fit < FIT_MIN:
                        violations.append('I-2')
                    if lit is not None and lit < LIT_LL and p1:
                        violations.append('I-4')
                    if not violations:
                        clean += 1
                        log(f"    Cycle {total}: clean ({clean}/{clean_required})  LIT101={lit:.1f}mm")
                    else:
                        clean = 0
                        log(f"    Cycle {total}: VIOLATION {violations} — resetting")
                    time.sleep(interval)
        except Exception as e:
            log(f"    [!] {e} — retrying...")
            clean = 0; time.sleep(3)
    log(f"STEP 5 — VERIFY complete ({total} cycles)", entry={'step': 5, 'action': 'verify', 'cycles': total})
    log("*** RECOVERY COMPLETE — SWaT P1 resuming normal operation ***")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--plc-ip',      default='192.168.1.10', help='PLC1 IP (MV101, P101)')
    ap.add_argument('--plc2-ip',     default='192.168.1.20', help='PLC2 IP (MV201)')
    ap.add_argument('--plc-b-ip',    default='192.168.1.11', help='PLC1B redundant IP')
    ap.add_argument('--attacker-ip', default=None,           help='Attacker IP to block via iptables')
    ap.add_argument('--iface',       default='eth0')
    args = ap.parse_args()

    print("=" * 60)
    print("  SWaT Recovery Agent (pylogix / Allen-Bradley)")
    print(f"  PLC1: {args.plc_ip}  PLC2: {args.plc2_ip}  PLC1B: {args.plc_b_ip}")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    t0 = time.time()
    step1_detect(args.attacker_ip)
    if args.attacker_ip:
        step2_contain(args.attacker_ip)
    step3_safe_state(args.plc_ip, args.plc2_ip)
    step4_failover(args.plc_b_ip)
    step5_verify(args.plc_ip)
    log(f"Total recovery time: {time.time()-t0:.1f}s",
        entry={'action': 'summary', 'elapsed_s': round(time.time()-t0, 1)})

if __name__ == '__main__':
    main()
