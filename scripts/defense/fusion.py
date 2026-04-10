"""
fusion.py — SWaT Hybrid Defense: Decision Fusion & Alert (Layer 3)

Reads flags from invariant_checker.py (/tmp/inv_flag) and
autoencoder_detector.py (/tmp/ae_flag), applies weighted fusion scoring,
and triggers the recovery pipeline when threshold is exceeded for 3+ cycles.

Fusion rule:
    score = 1.5 × inv_flag + 1.0 × ae_flag
    ALERT if score >= 1.5 for 3 consecutive cycles

Weighting rationale:
    - Invariants (×1.5): deterministic physics — higher confidence
    - Autoencoder (×1.0): statistical ML — lower confidence, catches evasion

Usage:
    python3 fusion.py [--interval 1.0] [--recovery-script ../recovery/recovery_agent.py]

Output:
    - Console alerts
    - fusion_log.json — timestamped score history
    - Triggers recovery_agent.py on sustained alert

Author: SWaT CPS Security Project Team, SUTD 51.508
"""

import argparse
import json
import logging
import os
import subprocess
import time
from datetime import datetime
from collections import deque

# ── Logging setup ─────────────────────────────────────────────────────────────
import os as _os
from datetime import datetime as _logdt
_LOG_DIR = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..', '..', 'logs')
_os.makedirs(_LOG_DIR, exist_ok=True)
LOG_FILE = _os.path.join(_LOG_DIR, f"fusion_{_logdt.now().strftime('%Y%m%d_%H%M%S')}.log")
_logfile = open(LOG_FILE, 'w', buffering=1)
_orig_print = print
def print(*args, **kwargs):
    msg = ' '.join(str(a) for a in args)
    ts  = _logdt.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{ts}] {msg}"
    _orig_print(line, **kwargs)
    _logfile.write(line + '\n')


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [FUSION] %(levelname)s %(message)s"
)
log = logging.getLogger("fusion")

INV_FLAG_PATH = "/tmp/inv_flag"
AE_FLAG_PATH  = "/tmp/ae_flag"
FUSION_LOG    = "fusion_log.json"

W_INV = 1.5
W_AE  = 1.0
ALERT_THRESHOLD   = 1.5
ALERT_WINDOW_SIZE = 3       # consecutive cycles needed to trigger recovery
RECOVERY_COOLDOWN = 30      # seconds before recovery can re-trigger


def read_flag(path: str) -> int:
    try:
        with open(path) as f:
            return int(f.read().strip())
    except Exception:
        return 0


def main():
    _orig_print(f"[LOG] Writing to {LOG_FILE}")
    parser = argparse.ArgumentParser(description="SWaT Decision Fusion Engine")
    parser.add_argument("--interval",         type=float, default=1.0)
    parser.add_argument("--recovery-script",  default="../recovery/recovery_agent.py",
                        help="Path to recovery_agent.py")
    args = parser.parse_args()

    score_window = deque(maxlen=ALERT_WINDOW_SIZE)
    fusion_log   = []
    last_recovery_time = 0.0
    recovery_triggered = False

    log.info("Fusion engine started. Waiting for flag files...")

    try:
        while True:
            inv_flag = read_flag(INV_FLAG_PATH)
            ae_flag  = read_flag(AE_FLAG_PATH)

            score = W_INV * inv_flag + W_AE * ae_flag
            score_window.append(score)

            alert = (
                len(score_window) == ALERT_WINDOW_SIZE and
                all(s >= ALERT_THRESHOLD for s in score_window)
            )

            entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "inv_flag":  inv_flag,
                "ae_flag":   ae_flag,
                "score":     round(score, 2),
                "alert":     alert,
            }
            fusion_log.append(entry)

            if alert:
                log.error(
                    f"⚠ ALERT: score={score:.1f} sustained {ALERT_WINDOW_SIZE} cycles "
                    f"(inv={inv_flag} ae={ae_flag})"
                )
                now = time.time()
                if not recovery_triggered or (now - last_recovery_time > RECOVERY_COOLDOWN):
                    log.error("→ Triggering RECOVERY PIPELINE")
                    try:
                        subprocess.Popen(
                            ["sudo", "python3", args.recovery_script],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                        last_recovery_time = now
                        recovery_triggered = True
                    except Exception as e:
                        log.error(f"Failed to launch recovery: {e}")
            else:
                if score > 0:
                    log.warning(
                        f"Partial signal: score={score:.1f} "
                        f"(inv={inv_flag} ae={ae_flag}) — window={list(score_window)}"
                    )
                else:
                    log.debug(f"All clear: score={score:.1f}")
                    recovery_triggered = False

            if len(fusion_log) % 60 == 0:
                with open(FUSION_LOG, "w") as f:
                    json.dump(fusion_log[-1000:], f, indent=2)

            time.sleep(args.interval)

    except KeyboardInterrupt:
        log.info("Fusion engine stopped.")
    finally:
        with open(FUSION_LOG, "w") as f:
            json.dump(fusion_log, f, indent=2)


if __name__ == "__main__":
    main()
