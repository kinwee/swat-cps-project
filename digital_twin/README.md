# SWaT Digital Twin

Three complementary tools built from your real SWaT sensor data.

## Dependencies
```bash
pip install torch numpy pandas matplotlib scikit-learn
```

---

## 1. ODE-based P1 Twin (`ode_twin.py`)
Physics model for LIT101 using mass balance ODE:
`dL/dt = (Q_in - Q_out) / A_tank`

```bash
# Normal operation — compare ODE vs real LIT101
python3 ode_twin.py --data ../assets/19-Feb-2026_0930_1735.csv

# Inject simulated attack at sample 5000 for 300s
python3 ode_twin.py --data ../assets/19-Feb-2026_0930_1735.csv \
    --attack --attack-start 5000 --attack-duration 300

# Output: ode_twin_plot.png
```

---

## 2. LSTM Data-Driven Twin (`lstm_twin.py`)
Predicts next sensor values across all 6 stages using LSTM.

```bash
# Train (uses 24 analog sensors, window=30s)
python3 lstm_twin.py train \
    --data ../assets/19-Feb-2026_0930_1735.csv \
    --model lstm_twin.pt --epochs 50

# Predict on second day's data
python3 lstm_twin.py predict \
    --data ../assets/20-Feb-2026_0905_1710.csv \
    --model lstm_twin.pt

# Attack simulation — show divergence under injected attack
python3 lstm_twin.py attack \
    --data ../assets/19-Feb-2026_0930_1735.csv \
    --model lstm_twin.pt --attack-start 3000 --attack-duration 600
```

---

## 3. Live Dashboard (`dashboard.py`)
Animated replay of all 6 stages with gauges, trends, ODE twin, alarms.

```bash
# Normal replay at 5× speed
python3 dashboard.py --data ../assets/19-Feb-2026_0930_1735.csv --speed 5

# Inject attack at sample 5000 — watch LIT101 drop, ODE diverge
python3 dashboard.py --data ../assets/19-Feb-2026_0930_1735.csv \
    --speed 5 --attack 5000
```

---

## Typical workflow for demo
1. Run dashboard showing normal operation
2. Inject attack → watch LIT101 drop on gauge
3. ODE panel shows growing residual = anomaly signal
4. Run ode_twin.py --attack to generate report plot
