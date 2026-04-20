#!/usr/bin/env python3
"""
run_demo.py — SWaT One-Command Lab Demo Orchestrator

Runs the entire attack-defense-recovery demo in a single command:
  1. Pre-flight checks (PLC connectivity, model files, sim tags off)
  2. Starts defense layers (invariant checker, AE detector, fusion)
  3. Waits for clean baseline readings
  4. Launches Phase 1 + Phase 2 attack
  5. Waits for detection + recovery
  6. Collects all logs and evidence into a timestamped folder
  7. Generates a summary report

All output is captured to log files AND printed to terminal.

Usage:
    python3 run_demo.py --plc-ip 192.168.1.10 --duration 120
    python3 run_demo.py --plc-ip 192.168.1.10 --duration 60 --skip-phase2
    python3 run_demo.py --sim   # run against PLC simulator (no real PLC)

Output:
    evidence/demo_YYYYMMDD_HHMMSS/
    ├── summary.txt          ← human-readable demo summary
    ├── timeline.json        ← timestamped event log
    ├── invariant_checker.log
    ├── autoencoder.log
    ├── fusion.log
    ├── phase1.log
    ├── phase2.log
    ├── recovery.log
    ├── pre_attack_state.json
    ├── post_attack_state.json
    └── post_recovery_state.json

Author: SWaT CPS Security Project Team, SUTD 51.508
"""

import argparse, json, os, signal, subprocess, sys, time, threading
from datetime import datetime
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO      = os.path.dirname(os.path.abspath(__file__))
SCRIPTS   = os.path.join(REPO, 'scripts')
TWIN      = os.path.join(REPO, 'digital_twin')
AE_MODEL  = os.path.join(REPO, 'ae_model.npz')
ADV_MODEL = os.path.join(REPO, 'adv_model.npz')

# ── Globals ───────────────────────────────────────────────────────────────────
procs     = {}          # name → subprocess.Popen
timeline  = []          # event log
evidence_dir = None
stop_flag = False


def ts():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def event(name, detail=""):
    entry = {"time": ts(), "event": name, "detail": detail}
    timeline.append(entry)
    print(f"\033[1;36m[{ts()}] [{name}]\033[0m {detail}", flush=True)

def error(msg):
    print(f"\033[1;31m[{ts()}] [ERROR] {msg}\033[0m", flush=True)


# ── Process Management ────────────────────────────────────────────────────────

def start_process(name, cmd, log_name=None):
    """Start a subprocess, capture stdout/stderr to log file."""
    log_path = os.path.join(evidence_dir, log_name or f"{name}.log")
    log_fh   = open(log_path, 'w', buffering=1)

    # Write header
    log_fh.write(f"# {name}\n# Command: {' '.join(cmd)}\n# Started: {ts()}\n\n")

    proc = subprocess.Popen(
        cmd, stdout=log_fh, stderr=subprocess.STDOUT,
        cwd=REPO, preexec_fn=os.setsid if os.name != 'nt' else None
    )
    procs[name] = {'proc': proc, 'log_fh': log_fh, 'log_path': log_path, 'cmd': cmd}
    event(f"STARTED {name}", f"PID={proc.pid}  cmd={' '.join(cmd)}")
    return proc


def stop_process(name):
    """Gracefully stop a subprocess."""
    if name not in procs:
        return
    p = procs[name]
    proc = p['proc']
    if proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            proc.terminate()
        proc.wait(timeout=5)
    p['log_fh'].close()
    event(f"STOPPED {name}", f"exit={proc.returncode}")


def stop_all():
    for name in list(procs.keys()):
        stop_process(name)


def read_plc_state(plc_ip, use_sim=False):
    """Read current PLC state via pylogix (or simulator)."""
    try:
        if use_sim:
            sys.path.insert(0, TWIN)
            from plc_simulator import TAG_STORE
            return {
                'HMI_LIT101.Pv': TAG_STORE.get('HMI_LIT101.Pv'),
                'AI_FIT_101_FLOW': TAG_STORE.get('AI_FIT_101_FLOW'),
                'HMI_MV101.Cmd': TAG_STORE.get('HMI_MV101.Cmd'),
                'HMI_P101.Auto': TAG_STORE.get('HMI_P101.Auto'),
                'HMI_LIT101.Sim': TAG_STORE.get('HMI_LIT101.Sim', False),
            }
        from pylogix import PLC
        tags = ['HMI_LIT101.Pv', 'AI_FIT_101_FLOW', 'HMI_MV101.Cmd',
                'HMI_P101.Auto', 'HMI_LIT101.Sim']
        with PLC() as plc:
            plc.IPAddress = plc_ip
            results = plc.Read(tags)
            if not isinstance(results, list):
                results = [results]
            return {r.TagName: r.Value for r in results if r.Value is not None}
    except Exception as e:
        error(f"PLC read failed: {e}")
        return {}


def save_state(plc_ip, filename, use_sim=False):
    """Save PLC state snapshot to JSON."""
    state = read_plc_state(plc_ip, use_sim)
    state['_timestamp'] = ts()
    path = os.path.join(evidence_dir, filename)
    with open(path, 'w') as f:
        json.dump(state, f, indent=2)
    event(f"STATE SAVED", f"{filename}: LIT101={state.get('HMI_LIT101.Pv', '?')}mm  MV101={state.get('HMI_MV101.Cmd', '?')}")
    return state


def wait_for_flag(flag_path, expected, timeout=30, label="flag"):
    """Wait for a flag file to reach expected value."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with open(flag_path) as f:
                val = int(f.read().strip())
            if val == expected:
                return True
        except:
            pass
        time.sleep(0.5)
    return False


# ── Pre-Flight Checks ────────────────────────────────────────────────────────

# Expected safe baseline state for SWaT P1
BASELINE_CHECKS = [
    # (tag, description, check_fn, fix_value_or_None, severity)
    ('HMI_LIT101.Pv',    'Tank level in normal range (300-850mm)',
     lambda v: v is not None and 300 <= v <= 850, None, 'CRITICAL'),
    ('AI_FIT_101_FLOW',  'Flow sensor reading valid (≥ 0 L/s)',
     lambda v: v is not None and v >= 0, None, 'WARNING'),
    ('HMI_MV101.Cmd',    'Inlet valve MV101 = OPEN (Cmd=2)',
     lambda v: v == 2, 2, 'CRITICAL'),
    ('HMI_MV101.Auto',   'MV101 in auto mode (Auto=True)',
     lambda v: v == True, True, 'CRITICAL'),
    ('HMI_P101.Auto',    'Pump P101 in auto mode (Auto=True)',
     lambda v: v == True, True, 'WARNING'),
    ('HMI_LIT101.Sim',   'LIT101 simulation OFF (Sim=False)',
     lambda v: v in (False, 0, None), False, 'CRITICAL'),
]

# Extended tags to read for full state picture
ALL_PREFLIGHT_TAGS = [
    'HMI_LIT101.Pv', 'AI_FIT_101_FLOW',
    'HMI_MV101.Cmd', 'HMI_MV101.Auto',
    'HMI_P101.Auto', 'HMI_P101.Cmd',
    'HMI_P102.Auto',
    'HMI_LIT101.Sim',
    'HMI_FIT101.Sim' if not None else 'AI_FIT_101_FLOW.Sim',
]


def read_full_state(plc_ip, use_sim=False):
    """Read all relevant PLC tags for baseline validation."""
    try:
        if use_sim:
            sys.path.insert(0, TWIN)
            from plc_simulator import TAG_STORE
            return {tag: TAG_STORE.get(tag) for tag in ALL_PREFLIGHT_TAGS}
        from pylogix import PLC
        with PLC() as plc:
            plc.IPAddress = plc_ip
            results = plc.Read(ALL_PREFLIGHT_TAGS)
            if not isinstance(results, list):
                results = [results]
            return {r.TagName: r.Value for r in results}
    except Exception as e:
        error(f"PLC read failed: {e}")
        return {}


def validate_baseline(plc_ip, use_sim=False, auto_fix=True, max_wait=60):
    """
    Validate plant is in safe baseline state before starting demo.
    If auto_fix=True, attempt to write safe values for fixable tags.
    Waits up to max_wait seconds for the plant to reach safe state.
    Returns (ok, state_dict).
    """
    event("BASELINE CHECK", "Validating plant is in safe operating state")

    start = time.time()
    attempt = 0

    while time.time() - start < max_wait:
        attempt += 1
        state = read_full_state(plc_ip, use_sim)

        if not state:
            error("Cannot read PLC — check connectivity")
            time.sleep(3)
            continue

        all_ok = True
        issues = []
        fixes_applied = []

        for tag, desc, check_fn, fix_val, severity in BASELINE_CHECKS:
            val = state.get(tag)
            ok = check_fn(val)

            if ok:
                event("BASELINE OK", f"  ✓ {tag} = {val}  ({desc})")
            else:
                all_ok = False
                issues.append((tag, val, desc, fix_val, severity))
                if severity == 'CRITICAL':
                    error(f"  ✗ {tag} = {val}  EXPECTED: {desc}")
                else:
                    event("BASELINE WARN", f"  ⚠ {tag} = {val}  EXPECTED: {desc}")

        if all_ok:
            event("BASELINE CHECK", f"✓ ALL CHECKS PASSED (attempt {attempt})")

            # Run invariant check on the validated state
            sys.path.insert(0, os.path.join(REPO, 'scripts', 'defense'))
            try:
                from invariant_checker import check_invariants, READ_TAGS
                inv_state = {}
                from pylogix import PLC as PLC2
                with PLC2() as plc:
                    plc.IPAddress = plc_ip
                    results = plc.Read(READ_TAGS)
                    if not isinstance(results, list):
                        results = [results]
                    inv_state = {r.TagName: r.Value for r in results if r.Value is not None}
                violations = check_invariants(inv_state)
                if violations:
                    event("BASELINE WARN", f"  Invariant violations in baseline: {[v[0] for v in violations]}")
                    event("BASELINE WARN", f"  This may indicate residual state — consider manual reset")
                    for inv_id, msg in violations:
                        event("BASELINE WARN", f"    {inv_id}: {msg}")
                else:
                    event("BASELINE CHECK", "  ✓ All invariants pass on baseline state")
            except Exception as e:
                event("BASELINE WARN", f"  Could not run invariant pre-check: {e}")

            return True, state

        # Attempt auto-fix for tags that have a fix value
        if auto_fix and attempt <= 3:
            fixable = [(tag, fix_val) for tag, val, desc, fix_val, sev in issues if fix_val is not None]
            if fixable:
                event("BASELINE FIX", f"Attempting to fix {len(fixable)} tags...")
                try:
                    from pylogix import PLC as PLC3
                    with PLC3() as plc:
                        plc.IPAddress = plc_ip
                        for tag, fix_val in fixable:
                            ret = plc.Write(tag, fix_val)
                            fixes_applied.append(tag)
                            event("BASELINE FIX", f"  → Wrote {tag} = {fix_val}  [{ret.Status}]")
                except Exception as e:
                    error(f"  Auto-fix failed: {e}")

                event("BASELINE FIX", f"Waiting 5s for PLC to settle...")
                time.sleep(5)
                continue  # re-check after fix

        # Report unfixable issues
        unfixable = [(tag, val, desc) for tag, val, desc, fix_val, sev in issues if fix_val is None]
        if unfixable:
            print()
            error("═" * 60)
            error("  PLANT NOT IN SAFE STATE — Cannot proceed")
            error("═" * 60)
            for tag, val, desc in unfixable:
                error(f"  {tag} = {val}")
                error(f"    Expected: {desc}")
                error(f"    Action: Fix manually on the HMI/PLC before re-running")
            error("═" * 60)
            print()

        time.sleep(3)

    error(f"Baseline validation failed after {max_wait}s")
    return False, state


def preflight(plc_ip, use_sim=False):
    event("PREFLIGHT", "Running pre-flight checks")
    checks = []

    # Check model files
    for model, name in [(AE_MODEL, 'ae_model.npz'), (ADV_MODEL, 'adv_model.npz')]:
        exists = os.path.exists(model)
        checks.append(('Model ' + name, exists))
        event("CHECK", f"{name}: {'FOUND' if exists else 'MISSING'}")

    # Check PLC connectivity
    state = read_plc_state(plc_ip, use_sim)
    plc_ok = bool(state) and state.get('HMI_LIT101.Pv') is not None
    checks.append(('PLC connectivity', plc_ok))
    if plc_ok:
        event("CHECK", f"PLC OK: LIT101={state['HMI_LIT101.Pv']:.1f}mm  MV101={state.get('HMI_MV101.Cmd')}")
    else:
        event("CHECK", "PLC UNREACHABLE")

    # Check flag files writable
    for path in ['/tmp/inv_flag', '/tmp/ae_flag']:
        try:
            with open(path, 'w') as f:
                f.write('0')
            checks.append((f'{path} writable', True))
        except:
            checks.append((f'{path} writable', False))

    all_ok = all(v for _, v in checks)
    event("PREFLIGHT", f"{'ALL CHECKS PASSED' if all_ok else 'SOME CHECKS FAILED'}")
    for name, ok in checks:
        if not ok:
            error(f"  FAILED: {name}")
    return all_ok


# ── Main Demo ─────────────────────────────────────────────────────────────────

def run_demo(args):
    global evidence_dir, stop_flag

    demo_ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    evidence_dir = os.path.join(REPO, 'evidence', f'demo_{demo_ts}')
    os.makedirs(evidence_dir, exist_ok=True)

    print()
    print("=" * 70)
    print("  SWaT Lab Demo — One-Command Orchestrator")
    print(f"  PLC: {args.plc_ip}  Duration: {args.duration}s  Mode: {'SIMULATOR' if args.sim else 'LIVE PLC'}")
    print(f"  Evidence: {evidence_dir}")
    print(f"  Started: {ts()}")
    print("=" * 70)
    print()

    event("DEMO START", f"plc={args.plc_ip}  duration={args.duration}s  sim={args.sim}")

    # ── 1. Pre-flight ─────────────────────────────────────────────────────
    if not preflight(args.plc_ip, args.sim):
        if not args.sim:
            error("Pre-flight failed. Fix issues and retry.")
            return False

    # ── 1b. Baseline validation ───────────────────────────────────────────
    if not args.sim:
        baseline_ok, baseline_state = validate_baseline(
            args.plc_ip, use_sim=False, auto_fix=True, max_wait=60)
        if not baseline_ok:
            error("Plant not in safe baseline state. Fix issues and retry.")
            return False
        event("BASELINE", "Plant in safe operating state — ready for demo")
    else:
        event("BASELINE", "Simulator mode — skipping baseline validation")

    # ── 2. Save pre-attack state ──────────────────────────────────────────
    save_state(args.plc_ip, 'pre_attack_state.json', args.sim)

    # ── 3. Start defense layers ───────────────────────────────────────────
    event("PHASE", "Starting defense layers")

    start_process('invariant_checker', [
        sys.executable, os.path.join(SCRIPTS, 'defense', 'invariant_checker.py'),
        '--plc-ip', args.plc_ip
    ], 'invariant_checker.log')

    start_process('autoencoder', [
        sys.executable, os.path.join(SCRIPTS, 'defense', 'autoencoder_detector.py'),
        'monitor', '--plc-ip', args.plc_ip, '--model', AE_MODEL
    ], 'autoencoder.log')

    start_process('fusion', [
        sys.executable, os.path.join(SCRIPTS, 'defense', 'fusion.py'),
        '--recovery-script', os.path.join(SCRIPTS, 'recovery', 'recovery_agent.py')
    ], 'fusion.log')

    # Wait for defense to stabilise
    event("WAITING", "Defense layers initialising (15s baseline)...")
    time.sleep(15)

    # Verify clean baseline
    inv_clean = wait_for_flag('/tmp/inv_flag', 0, timeout=10, label="inv_flag")
    ae_clean  = wait_for_flag('/tmp/ae_flag',  0, timeout=10, label="ae_flag")
    if inv_clean and ae_clean:
        event("BASELINE", "Defense layers report clean — ready for attack")
    else:
        event("WARNING", "Defense not fully clean — proceeding anyway")

    # ── 4. Launch attack ──────────────────────────────────────────────────
    event("PHASE", f"Launching attack ({'SINGLE-SHOT' if args.once else f'CONTINUOUS {args.duration}s'})")

    phase1_cmd = [
        sys.executable, os.path.join(SCRIPTS, 'attack', 'phase1_inject.py'),
        '--plc-ip', args.plc_ip
    ]
    if args.once:
        phase1_cmd.append('--once')
    else:
        phase1_cmd.extend(['--duration', str(args.duration)])

    start_process('phase1', phase1_cmd, 'phase1.log')

    if not args.skip_phase2 and not args.once:
        time.sleep(2)  # slight delay so Phase 1 takes effect first
        start_process('phase2', [
            sys.executable, os.path.join(SCRIPTS, 'attack', 'phase2_spoof.py'),
            'attack', '--plc-ip', args.plc_ip, '--model', ADV_MODEL,
            '--duration', str(args.duration)
        ], 'phase2.log')

    if args.once:
        # Single-shot: wait for attack to complete (writes once, exits)
        event("WAITING", "Single-shot attack — waiting for commands to be written...")
        time.sleep(5)
        save_state(args.plc_ip, 'post_attack_state.json', args.sim)

        # Now monitor for detection and recovery
        event("MONITORING", "Attack written. Watching for detection and recovery...")
        detection_time = None
        recovery_detected = False
        monitor_start = time.time()
        monitor_end = monitor_start + args.duration

        while time.time() < monitor_end and not stop_flag:
            try:
                with open('/tmp/inv_flag') as f:
                    inv = int(f.read().strip())
                if inv == 1 and detection_time is None:
                    detection_time = time.time() - monitor_start
                    event("DETECTED", f"Invariant violation at T+{detection_time:.1f}s")
                if inv == 0 and detection_time is not None and not recovery_detected:
                    recovery_time = time.time() - monitor_start
                    event("RECOVERED", f"Invariants clean again at T+{recovery_time:.1f}s")
                    recovery_detected = True
                    # Save state right after recovery
                    save_state(args.plc_ip, 'post_recovery_state.json', args.sim)
            except:
                pass

            elapsed = time.time() - monitor_start
            if abs(elapsed - 30) < 1:
                save_state(args.plc_ip, 'mid_recovery_state.json', args.sim)

            time.sleep(1)

            # If recovery completed, wait a few more seconds then stop
            if recovery_detected and (time.time() - monitor_start) > detection_time + 30:
                event("PHASE", "Recovery verified — ending monitoring")
                break

        if not recovery_detected:
            save_state(args.plc_ip, 'post_recovery_state.json', args.sim)

    else:
        # ── 5. Monitor attack progress (continuous mode) ──────────────────
        event("MONITORING", f"Attack running for {args.duration}s — watching for detection")

        detection_time = None
        attack_start   = time.time()
        attack_end     = attack_start + args.duration

        while time.time() < attack_end and not stop_flag:
            try:
                with open('/tmp/inv_flag') as f:
                    inv = int(f.read().strip())
                if inv == 1 and detection_time is None:
                    detection_time = time.time() - attack_start
                    event("DETECTED", f"Invariant violation at T+{detection_time:.1f}s")
            except:
                pass

            # Save mid-attack state snapshot
            elapsed = time.time() - attack_start
            if abs(elapsed - args.duration / 2) < 1:
                save_state(args.plc_ip, 'mid_attack_state.json', args.sim)

            time.sleep(1)

        # ── 6. Save post-attack state ─────────────────────────────────────
        save_state(args.plc_ip, 'post_attack_state.json', args.sim)

        # ── 7. Wait for recovery to complete ──────────────────────────────
        event("WAITING", "Waiting 30s for recovery to complete...")
        time.sleep(30)
        save_state(args.plc_ip, 'post_recovery_state.json', args.sim)

    # ── 8. Stop all processes ─────────────────────────────────────────────
    event("PHASE", "Stopping all processes")
    stop_all()

    # ── 9. Collect evidence ───────────────────────────────────────────────
    event("PHASE", "Collecting evidence")

    # Copy any fusion/recovery logs
    for src in ['fusion_log.json', 'recovery_log.json']:
        src_path = os.path.join(REPO, src)
        if os.path.exists(src_path):
            dst_path = os.path.join(evidence_dir, src)
            with open(src_path) as f:
                data = f.read()
            with open(dst_path, 'w') as f:
                f.write(data)
            event("EVIDENCE", f"Copied {src}")

    # Save timeline
    timeline_path = os.path.join(evidence_dir, 'timeline.json')
    with open(timeline_path, 'w') as f:
        json.dump(timeline, f, indent=2)

    # ── 10. Generate summary ──────────────────────────────────────────────
    summary = generate_summary(args, detection_time, demo_ts)
    summary_path = os.path.join(evidence_dir, 'summary.txt')
    with open(summary_path, 'w') as f:
        f.write(summary)

    print()
    print(summary)
    print()
    event("DEMO COMPLETE", f"Evidence saved to {evidence_dir}")
    return True


def generate_summary(args, detection_time, demo_ts):
    """Generate a human-readable summary of the demo."""
    # Read state files
    states = {}
    for name in ['pre_attack_state', 'post_attack_state', 'post_recovery_state']:
        path = os.path.join(evidence_dir, f'{name}.json')
        if os.path.exists(path):
            with open(path) as f:
                states[name] = json.load(f)

    pre  = states.get('pre_attack_state', {})
    post = states.get('post_attack_state', {})
    recv = states.get('post_recovery_state', {})

    # Count invariant violations from log
    inv_log = os.path.join(evidence_dir, 'invariant_checker.log')
    inv_violations = 0
    if os.path.exists(inv_log):
        with open(inv_log) as f:
            inv_violations = f.read().count('VIOLATION')

    lines = [
        "=" * 70,
        "  SWaT Lab Demo — Evidence Summary",
        "=" * 70,
        f"  Date:     {demo_ts}",
        f"  PLC:      {args.plc_ip}",
        f"  Mode:     {'SIMULATOR' if args.sim else 'LIVE PLC'}",
        f"  Duration: {args.duration}s",
        f"  Phase 2:  {'Enabled' if not args.skip_phase2 else 'Disabled'}",
        "",
        "── Plant State ──────────────────────────────────────────────────",
        f"  Pre-attack:     LIT101={pre.get('HMI_LIT101.Pv', '?')}mm  MV101={pre.get('HMI_MV101.Cmd', '?')}  P101={pre.get('HMI_P101.Auto', '?')}",
        f"  Post-attack:    LIT101={post.get('HMI_LIT101.Pv', '?')}mm  MV101={post.get('HMI_MV101.Cmd', '?')}  P101={post.get('HMI_P101.Auto', '?')}",
        f"  Post-recovery:  LIT101={recv.get('HMI_LIT101.Pv', '?')}mm  MV101={recv.get('HMI_MV101.Cmd', '?')}  P101={recv.get('HMI_P101.Auto', '?')}",
        "",
        "── Detection ────────────────────────────────────────────────────",
        f"  Time to detect:       {detection_time:.1f}s" if detection_time else "  Time to detect:       NOT DETECTED",
        f"  Invariant violations: {inv_violations}",
        "",
        "── Evidence Files ───────────────────────────────────────────────",
    ]

    for f in sorted(os.listdir(evidence_dir)):
        size = os.path.getsize(os.path.join(evidence_dir, f))
        lines.append(f"  {f:40s} {size:>8,} bytes")

    lines += [
        "",
        "── Timeline (first 20 events) ───────────────────────────────────",
    ]
    for e in timeline[:20]:
        lines.append(f"  {e['time']}  {e['event']:20s}  {e['detail']}")

    lines += ["", "=" * 70]
    return "\n".join(lines)


def signal_handler(sig, frame):
    global stop_flag
    print(f"\n\033[1;31m[{ts()}] Ctrl+C — stopping demo gracefully...\033[0m")
    stop_flag = True
    stop_all()
    if evidence_dir:
        timeline_path = os.path.join(evidence_dir, 'timeline.json')
        with open(timeline_path, 'w') as f:
            json.dump(timeline, f, indent=2)
    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, signal_handler)

    ap = argparse.ArgumentParser(description="SWaT One-Command Lab Demo")
    ap.add_argument('--plc-ip',      default='192.168.1.10', help='PLC1 IP address')
    ap.add_argument('--duration',    type=int, default=120,  help='Attack duration (seconds)')
    ap.add_argument('--skip-phase2', action='store_true',    help='Run Phase 1 only (no adversarial evasion)')
    ap.add_argument('--once',        action='store_true',    help='Single-shot attack: write once and let defence recover')
    ap.add_argument('--sim',         action='store_true',    help='Use PLC simulator instead of real PLC')
    args = ap.parse_args()

    success = run_demo(args)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
