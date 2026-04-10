#!/bin/bash
# setup.sh — One-command environment setup for SWaT CPS project
# Works on HMI (Ubuntu) and Mac. Installs uv if missing, creates venv, installs deps.
#
# Usage:
#   bash setup.sh           # HMI: installs pylogix + numpy + pandas only
#   bash setup.sh --train   # Mac: also installs PyTorch + matplotlib for training

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================================"
echo "  SWaT CPS Project — Environment Setup"
echo "  $(date)"
echo "============================================================"
echo

# ── 1. Install uv if not present ─────────────────────────────────────────────
if ! command -v uv &> /dev/null; then
    echo "[*] Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # Add to PATH for this session
    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
    if ! command -v uv &> /dev/null; then
        echo "[!] uv install failed. Install manually: https://docs.astral.sh/uv/"
        exit 1
    fi
    echo "[+] uv installed: $(uv --version)"
else
    echo "[+] uv already installed: $(uv --version)"
fi

# ── 2. Create venv + install dependencies ─────────────────────────────────────
echo
echo "[*] Creating virtual environment and installing dependencies..."

if [[ "$1" == "--train" ]]; then
    echo "    Mode: TRAINING (includes PyTorch, matplotlib, scikit-learn)"
    uv sync --extra train
else
    echo "    Mode: HMI (pylogix + numpy + pandas only)"
    uv sync
fi

echo
echo "[+] Environment ready!"
echo

# ── 3. Verify ─────────────────────────────────────────────────────────────────
echo "[*] Verifying installation..."
uv run python3 -c "
import numpy, pandas, pylogix
print(f'  numpy:   {numpy.__version__}')
print(f'  pandas:  {pandas.__version__}')
print(f'  pylogix: {pylogix.__version__}')
print('  All OK')
"

# ── 4. Check model files ─────────────────────────────────────────────────────
echo
echo "[*] Checking model files..."
for f in ae_model.npz adv_model.npz; do
    if [ -f "$f" ]; then
        SIZE=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null)
        echo "  [+] $f ($SIZE bytes)"
    else
        echo "  [!] $f MISSING — copy from Mac or retrain"
    fi
done

echo
echo "============================================================"
echo "  Setup complete!"
echo
echo "  To run the demo:"
echo "    uv run python3 run_demo.py --plc-ip 192.168.1.10 --duration 120"
echo
echo "  To run locally (PLC simulator):"
echo "    uv run python3 run_demo.py --sim --duration 30"
echo
echo "  To retrain models (Mac only, needs --train):"
echo "    uv run python3 scripts/defense/autoencoder_detector.py train \\"
echo "        --data assets/19-Feb-2026_0930_1735.csv --save ae_model.npz"
echo "============================================================"
