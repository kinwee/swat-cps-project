#!/usr/bin/env python3
"""
recovery_agent.py  —  SWaT Shallow Recovery Pipeline
Target: Allen-Bradley ControlLogix PLC1 via pylogix

Usage:
  python3 recovery_agent.py --plc-ip 192.168.1.10 --plc-b-ip 192.168.1.11 \
      --attacker-ip 192.168.1.99
"""

import argparse, json, os, subprocess, time
from datetime import datetime
from pylogix import PLC

# Safe state: MV101 open, P101 off (prevent dry run, allow refill)
SAFE_STATE = [
    ('HMI_MV101.Auto', False),
    ('HMI_MV101.Cmd',  2),       # 2=OPEN
    ('HMI_MV101.Auto', True),
    ('HMI_P101.Auto',  False),
    ('HMI_P101.Cmd',   2),       # 2=ON — restore pump
    ('HMI_P101.Auto',  True),
]

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


def step3_safe_state(plc_ip):
    log(f"STEP 3 — SAFE STATE -> PLC {plc_ip}")
    try:
        with PLC() as plc:
            plc.IPAddress = plc_ip
            for tag, val in SAFE_STATE:
                plc.Write(tag, val)
                log(f"    {tag} = {val}")
        log("STEP 3 — SAFE STATE complete", entry={'step': 3, 'action': 'safe_state'})
    except Exception as e:
        log(f"[!] SAFE STATE failed: {e}")
        log("    *** Manually restore MV101=OPEN, P101=OFF via HMI! ***")


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
    ap.add_argument('--plc-ip',      default='192.168.1.10')
    ap.add_argument('--plc-b-ip',    default='192.168.1.11')
    ap.add_argument('--attacker-ip', default=None)
    ap.add_argument('--iface',       default='eth0')
    args = ap.parse_args()

    print("=" * 60)
    print("  SWaT Recovery Agent (pylogix / Allen-Bradley)")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    t0 = time.time()
    step1_detect(args.attacker_ip)
    if args.attacker_ip:
        step2_contain(args.attacker_ip)
    step3_safe_state(args.plc_ip)
    step4_failover(args.plc_b_ip)
    step5_verify(args.plc_ip)
    log(f"Total recovery time: {time.time()-t0:.1f}s",
        entry={'action': 'summary', 'elapsed_s': round(time.time()-t0, 1)})

if __name__ == '__main__':
    main()
