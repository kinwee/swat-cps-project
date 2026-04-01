#!/usr/bin/env python3
"""
plc_simulator.py  —  SWaT PLC1 Simulator for pylogix
Simulates Allen-Bradley ControlLogix PLC1 behaviour locally.
Runs a mock pylogix server that responds to Read/Write calls.

How it works:
  - Patches pylogix.PLC so scripts think they're talking to a real PLC
  - Simulates P1 physics: LIT101 changes based on MV101/P101 states
  - Accepts Write commands (attack scripts can close MV101, stop P101)
  - Prints all reads/writes so you can see exactly what each script does

Usage:
  # Terminal 1: start simulator
  python3 digital_twin/plc_simulator.py

  # Terminal 2+: run any script as normal — it will hit the simulator
  python3 scripts/defense/invariant_checker.py --plc-ip 192.168.1.10
  python3 scripts/attack/phase1_inject.py --plc-ip 192.168.1.10 --duration 30
"""

import time, threading, sys, os
from datetime import datetime

# ── Simulated PLC tag store ───────────────────────────────────────────────────
# Initial values matching normal SWaT P1 operation
TAG_STORE = {
    'HMI_LIT101.Pv'     : 650.0,   # mm, tank level
    'AI_FIT_101_FLOW'   : 0.0,     # L/s, flow (updated by physics)
    'HMI_MV101.Cmd'     : 2,       # 2=OPEN, 1=CLOSED
    'HMI_MV101.Auto'    : True,
    'HMI_P101.Auto'     : True,
    'HMI_P101.Cmd'      : 2,       # 2=ON, 1=OFF
    'HMI_P102.Auto'     : False,
    'HMI_P102.Cmd'      : 1,
    'HMI_LIT101.Sim'    : False,
    'HMI_LIT101.Sim_PV' : 0.0,
    'HMI_FIT101.Sim'    : False,
    'HMI_FIT101.Sim_PV' : 0.0,
}

# Physics constants
A_TANK   = 1.5      # m²
Q_IN     = 2.0      # L/s when MV101 open
Q_OUT    = 1.8      # L/s when P101 on
DT       = 1.0      # seconds

lock = threading.Lock()
write_log = []

def physics_loop():
    """Continuously update LIT101 and FIT101 based on actuator states."""
    while True:
        with lock:
            mv_open = TAG_STORE.get('HMI_MV101.Cmd', 2) == 2
            p1_on   = TAG_STORE.get('HMI_P101.Cmd', 2) == 2

            flow_in  = Q_IN  if mv_open else 0.0
            flow_out = Q_OUT if p1_on   else 0.0
            dL = (flow_in - flow_out) / A_TANK * DT  # mm change

            # Update level (unless in simulation mode)
            if not TAG_STORE.get('HMI_LIT101.Sim', False):
                TAG_STORE['HMI_LIT101.Pv'] = max(0, min(1000,
                    TAG_STORE['HMI_LIT101.Pv'] + dL))
            else:
                TAG_STORE['HMI_LIT101.Pv'] = TAG_STORE['HMI_LIT101.Sim_PV']

            # Update flow (unless in simulation mode)
            if not TAG_STORE.get('HMI_FIT101.Sim', False):
                # Add some noise + model: flow ≈ Q_in when valve open
                base_flow = flow_in * 0.95 if mv_open else 0.0
                TAG_STORE['AI_FIT_101_FLOW'] = max(0, base_flow +
                    (0.05 * (0.5 - __import__('random').random())))
            else:
                TAG_STORE['AI_FIT_101_FLOW'] = TAG_STORE['HMI_FIT101.Sim_PV']

        time.sleep(DT)


class MockResult:
    def __init__(self, tag, value, error=None):
        self.TagName = tag
        self.Value   = value
        self.Status  = 'Success' if error is None else f'Error: {error}'
        self.error   = error
        self.type    = type(value).__name__


class MockPLC:
    """Drop-in replacement for pylogix.PLC that uses TAG_STORE."""

    def __init__(self):
        self.IPAddress = '192.168.1.10'

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def Read(self, *tags):
        results = []
        for tag in tags:
            with lock:
                if tag in TAG_STORE:
                    val = TAG_STORE[tag]
                    results.append(MockResult(tag, val))
                else:
                    results.append(MockResult(tag, None, f'Tag not found: {tag}'))
        return results if len(results) > 1 else results[0]

    def Write(self, tag, value):
        ts = datetime.now().strftime('%H:%M:%S')
        with lock:
            old_val = TAG_STORE.get(tag, 'N/A')
            TAG_STORE[tag] = value
            # Sync Auto with Cmd so invariant checker sees correct state
            if tag == 'HMI_P101.Cmd':
                TAG_STORE['HMI_P101.Auto'] = (value == 2)
            if tag == 'HMI_P102.Cmd':
                TAG_STORE['HMI_P102.Auto'] = (value == 2)
            write_log.append((ts, tag, old_val, value))
        print(f"\033[33m  [SIM WRITE {ts}] {tag}: {old_val} → {value}\033[0m", flush=True)
        return MockResult(tag, value)

    def get_tag_list(self):
        return [{'tag_name': k, 'data_type': type(v).__name__}
                for k, v in TAG_STORE.items()]


def patch_pylogix():
    """Replace pylogix.PLC with MockPLC in sys.modules."""
    import types
    mock_module = types.ModuleType('pylogix')
    mock_module.PLC = MockPLC
    sys.modules['pylogix'] = mock_module
    print("[SIM] pylogix patched — all PLC calls go to simulator")


def status_loop():
    """Print plant status every 5 seconds."""
    while True:
        time.sleep(5)
        with lock:
            lit  = TAG_STORE['HMI_LIT101.Pv']
            fit  = TAG_STORE['AI_FIT_101_FLOW']
            mv   = 'OPEN'   if TAG_STORE['HMI_MV101.Cmd'] == 2 else 'CLOSED'
            p1   = 'ON'     if TAG_STORE['HMI_P101.Cmd']  == 2 else 'OFF'
            sim  = ' [SIM]' if TAG_STORE['HMI_LIT101.Sim'] else ''
        ts = datetime.now().strftime('%H:%M:%S')
        lvl_bar = '█' * int(lit / 50) + '░' * (20 - int(lit / 50))
        color = '\033[31m' if lit < 250 or lit > 800 else '\033[32m'
        print(f"\033[90m[{ts}]\033[0m  "
              f"LIT101={color}{lit:6.1f}mm\033[0m {lvl_bar}{sim}  "
              f"FIT101={fit:.3f}L/s  MV101={mv}  P101={p1}", flush=True)


def run_standalone():
    """Run as a standalone mock server — patches pylogix then waits."""
    patch_pylogix()

    print("=" * 65)
    print("  SWaT PLC1 Simulator  —  192.168.1.10 (mocked)")
    print("  All pylogix Read/Write calls intercepted locally")
    print("=" * 65)
    print()
    print("  Initial state:")
    for k, v in TAG_STORE.items():
        print(f"    {k:30s} = {v}")
    print()
    print("  Now run your scripts in OTHER terminals:")
    print("  python3 scripts/defense/invariant_checker.py --plc-ip 192.168.1.10")
    print("  python3 scripts/attack/phase1_inject.py --plc-ip 192.168.1.10 --duration 30")
    print()
    print("  Writes will appear in \033[33myellow\033[0m below.")
    print("  Status updates every 5 seconds.")
    print("  Press Ctrl+C to stop.")
    print("-" * 65)

    threading.Thread(target=physics_loop, daemon=True).start()
    threading.Thread(target=status_loop,  daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[SIM] Stopped.")
        if write_log:
            print(f"\n[SIM] Write summary ({len(write_log)} writes):")
            for ts, tag, old, new in write_log[-20:]:
                print(f"  {ts}  {tag:35s}  {str(old):>10} → {new}")


if __name__ == '__main__':
    run_standalone()
