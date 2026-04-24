import { useState, useEffect, useRef } from "react";

const DARK = "#0a0e17";
const PANEL = "#111827";
const BORDER = "#1e293b";
const GREEN = "#10b981";
const RED = "#ef4444";
const AMBER = "#f59e0b";
const BLUE = "#3b82f6";
const CYAN = "#06b6d4";
const MUTED = "#64748b";
const TEXT = "#e2e8f0";
const DIM = "#94a3b8";

// Simulation phases
const PHASES = [
  { id: "idle", label: "STANDBY", duration: 2000 },
  { id: "baseline", label: "BASELINE VALIDATION", duration: 3000 },
  { id: "defense_start", label: "DEFENCE LAYERS ONLINE", duration: 2000 },
  { id: "baseline_monitor", label: "MONITORING BASELINE", duration: 4000 },
  { id: "attack_inject", label: "PHASE 1 — CIP INJECTION", duration: 1500 },
  { id: "attack_active", label: "ATTACK ACTIVE — TANK DRAINING", duration: 5000 },
  { id: "phase2_start", label: "PHASE 2 — SENSOR SPOOFING", duration: 3000 },
  { id: "invariant_fire", label: "I-2 + I-9 FIRED — CYCLE 1", duration: 1500 },
  { id: "ae_detect", label: "AE ANOMALY — MSE > THRESHOLD", duration: 2000 },
  { id: "fusion_alert", label: "FUSION ALERT — SCORE 2.5", duration: 2000 },
  { id: "recovery_start", label: "RECOVERY INITIATED", duration: 1500 },
  { id: "recovery_write", label: "SAFE STATE CIP WRITES", duration: 2000 },
  { id: "recovery_verify", label: "VERIFYING — 5 CLEAN CYCLES", duration: 3000 },
  { id: "recovered", label: "PLANT RECOVERED", duration: 4000 },
];

const INVARIANTS = [
  { id: "I-1", desc: "MV101=OPEN → FIT101>0.4", status: "pass" },
  { id: "I-2", desc: "P101=ON → FIT201>0.4", status: "pass" },
  { id: "I-3", desc: "LIT101>800 → MV101≠OPEN", status: "pass" },
  { id: "I-4", desc: "LIT101<250 → P101≠ON", status: "pass" },
  { id: "I-5", desc: "LIT101<250 → MV101≠CLOSED", status: "pass" },
  { id: "I-6", desc: "P101∧P102 not both ON", status: "pass" },
  { id: "I-7", desc: "P101=OFF∧MV101=CL → FIT<0.4", status: "pass" },
  { id: "I-8", desc: "FIT101 ≤ 2.0 L/s", status: "pass" },
  { id: "I-9", desc: "MV101=CL∧P101=ON → ATTACK", status: "pass" },
];

function Sparkline({ data, color, height = 40, width = 200 }) {
  if (!data.length) return null;
  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;
  const points = data
    .map((v, i) => {
      const x = (i / (data.length - 1)) * width;
      const y = height - ((v - min) / range) * (height - 4) - 2;
      return `${x},${y}`;
    })
    .join(" ");
  return (
    <svg width={width} height={height} style={{ display: "block" }}>
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function GaugeBar({ label, value, max, unit, color, warn }) {
  const pct = Math.min((value / max) * 100, 100);
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: DIM, marginBottom: 3 }}>
        <span>{label}</span>
        <span style={{ color: warn ? RED : color, fontFamily: "'JetBrains Mono', monospace", fontWeight: 600 }}>
          {typeof value === "number" ? value.toFixed(1) : value}{unit}
        </span>
      </div>
      <div style={{ height: 4, background: BORDER, borderRadius: 2 }}>
        <div
          style={{
            height: "100%",
            width: `${pct}%`,
            background: warn ? RED : color,
            borderRadius: 2,
            transition: "width 0.5s ease, background 0.3s",
          }}
        />
      </div>
    </div>
  );
}

function StatusDot({ color, pulse }) {
  return (
    <span
      style={{
        display: "inline-block",
        width: 8,
        height: 8,
        borderRadius: "50%",
        background: color,
        marginRight: 6,
        boxShadow: pulse ? `0 0 8px ${color}` : "none",
        animation: pulse ? "pulse 1s ease-in-out infinite" : "none",
      }}
    />
  );
}

function Panel({ title, children, accent, style }) {
  return (
    <div
      style={{
        background: PANEL,
        border: `1px solid ${BORDER}`,
        borderTop: `2px solid ${accent || BORDER}`,
        borderRadius: 6,
        padding: "12px 14px",
        ...style,
      }}
    >
      <div style={{ fontSize: 10, fontWeight: 700, color: accent || MUTED, letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 8 }}>
        {title}
      </div>
      {children}
    </div>
  );
}

function TimelineEvent({ time, text, type }) {
  const colors = { info: CYAN, attack: RED, detect: AMBER, recover: GREEN, phase: BLUE };
  const c = colors[type] || MUTED;
  return (
    <div style={{ display: "flex", gap: 8, marginBottom: 6, fontSize: 11 }}>
      <span style={{ color: MUTED, fontFamily: "'JetBrains Mono', monospace", minWidth: 50, flexShrink: 0 }}>{time}</span>
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: c, marginTop: 4, flexShrink: 0 }} />
      <span style={{ color: TEXT }}>{text}</span>
    </div>
  );
}

export default function SWaTDashboard() {
  const [phase, setPhase] = useState(0);
  const [tick, setTick] = useState(0);
  const [running, setRunning] = useState(false);
  const [litHistory, setLitHistory] = useState([650]);
  const [mseHistory, setMseHistory] = useState([0.00003]);
  const [fusionHistory, setFusionHistory] = useState([0]);
  const [events, setEvents] = useState([]);
  const [invStates, setInvStates] = useState(INVARIANTS.map((i) => ({ ...i })));
  const timerRef = useRef(null);
  const phaseStartRef = useRef(0);
  const eventsEndRef = useRef(null);

  // Plant state
  const [mv101, setMv101] = useState("OPEN");
  const [p101, setP101] = useState("AUTO");
  const [mv201, setMv201] = useState("CLOSED");
  const [lit101, setLit101] = useState(650);
  const [fit101, setFit101] = useState(1.88);
  const [sim, setSim] = useState(false);
  const [fusionScore, setFusionScore] = useState(0);
  const [mse, setMse] = useState(0.00003);
  const [spoofedLit, setSpoofedLit] = useState(null);

  const currentPhase = PHASES[phase] || PHASES[0];

  const addEvent = (text, type = "info") => {
    const t = `T+${tick}s`;
    setEvents((prev) => [...prev.slice(-30), { time: t, text, type }]);
  };

  useEffect(() => {
    if (eventsEndRef.current) {
      eventsEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [events]);

  const resetAll = () => {
    setPhase(0);
    setTick(0);
    setLitHistory([650]);
    setMseHistory([0.00003]);
    setFusionHistory([0]);
    setEvents([]);
    setInvStates(INVARIANTS.map((i) => ({ ...i })));
    setMv101("OPEN");
    setP101("AUTO");
    setMv201("CLOSED");
    setLit101(650);
    setFit101(1.88);
    setSim(false);
    setFusionScore(0);
    setMse(0.00003);
    setSpoofedLit(null);
    setRunning(false);
    if (timerRef.current) clearInterval(timerRef.current);
  };

  const startDemo = () => {
    resetAll();
    setRunning(true);
    phaseStartRef.current = 0;

    let t = 0;
    let p = 0;
    let pStart = 0;
    let lit = 650;
    let currentMse = 0.00003;
    let currentFusion = 0;
    let spoof = null;
    let litHist = [650];
    let mseHist = [0.00003];
    let fusHist = [0];
    let evts = [];
    let invs = INVARIANTS.map((i) => ({ ...i }));
    let cleanCycles = 0;

    const addEvt = (text, type) => {
      evts = [...evts.slice(-30), { time: `T+${t}s`, text, type }];
      setEvents([...evts]);
    };

    timerRef.current = setInterval(() => {
      t++;
      setTick(t);
      const elapsed = t - pStart;
      const ph = PHASES[p];
      if (!ph) {
        clearInterval(timerRef.current);
        setRunning(false);
        return;
      }
      const phaseDur = ph.duration / 500;

      // Phase transitions
      if (elapsed >= phaseDur) {
        p++;
        pStart = t;
        if (p < PHASES.length) {
          setPhase(p);
          const next = PHASES[p];

          if (next.id === "baseline") addEvt("Validating plant baseline state...", "info");
          if (next.id === "defense_start") {
            addEvt("✓ Baseline OK — LIT101=650mm, MV101=OPEN", "info");
            addEvt("Starting invariant checker, AE detector, fusion engine", "phase");
          }
          if (next.id === "baseline_monitor") addEvt("Defence online — monitoring 15s baseline", "info");
          if (next.id === "attack_inject") {
            addEvt("⚡ PHASE 1 — CIP tag injection fired", "attack");
            addEvt("MV101.Auto=False, MV101.Cmd=1 (CLOSE)", "attack");
            addEvt("P101.Auto=False, P101.Cmd=2 (ON)", "attack");
            setMv101("CLOSED");
            setP101("MANUAL-ON");
            setMv201("OPEN");
            setFit101(0.02);
          }
          if (next.id === "phase2_start") {
            addEvt("⚡ PHASE 2 — Adversarial sensor spoofing active", "attack");
            addEvt("LIT101.Sim=True, Sim_PV=baseline±7mm", "attack");
            setSim(true);
            spoof = 650;
          }
          if (next.id === "invariant_fire") {
            addEvt("🔴 I-2 VIOLATION: P101=ON but FIT201<0.4", "detect");
            addEvt("🔴 I-9 VIOLATION: MV101=CLOSED + P101=ON in range", "detect");
            invs = invs.map((inv) =>
              inv.id === "I-2" || inv.id === "I-9" ? { ...inv, status: "fail" } : inv
            );
            setInvStates([...invs]);
          }
          if (next.id === "ae_detect") {
            addEvt("🟡 AE anomaly: MSE=0.014 > threshold 0.000738", "detect");
          }
          if (next.id === "fusion_alert") {
            addEvt("🔴 FUSION ALERT — score=2.5 for 3 consecutive cycles", "detect");
            addEvt("Recovery agent triggered automatically", "recover");
            currentFusion = 2.5;
            setFusionScore(2.5);
          }
          if (next.id === "recovery_start") {
            addEvt("Step 1: DETECT — fusion ALERT confirmed", "recover");
            addEvt("Step 2: CONTAIN — iptables block attacker IP", "recover");
          }
          if (next.id === "recovery_write") {
            addEvt("Step 3: SAFE STATE — writing CIP commands", "recover");
            addEvt("  PLC1: MV101=OPEN, P101=OFF", "recover");
            addEvt("  PLC2: MV201=CLOSED", "recover");
            addEvt("  LIT101.Sim=False, FIT101.Sim=False", "recover");
            setMv101("OPEN");
            setP101("AUTO");
            setMv201("CLOSED");
            setSim(false);
            setFit101(1.88);
            spoof = null;
            setSpoofedLit(null);
            currentFusion = 0.5;
            setFusionScore(0.5);
            currentMse = 0.0004;
          }
          if (next.id === "recovery_verify") {
            addEvt("Step 4: FAILOVER — safe state to PLC1B", "recover");
            addEvt("Step 5: VERIFY — waiting for 5 clean cycles", "recover");
            invs = invs.map((inv) => ({ ...inv, status: "pass" }));
            setInvStates([...invs]);
            cleanCycles = 0;
          }
          if (next.id === "recovered") {
            addEvt("✅ 5/5 clean invariant cycles — PLANT RECOVERED", "recover");
            addEvt("Evidence saved to evidence/demo_*/", "info");
            currentFusion = 0;
            setFusionScore(0);
            currentMse = 0.00004;
          }
        }
      }

      // Simulate sensor values
      const cp = PHASES[p];
      if (!cp) return;

      if (["attack_active", "phase2_start", "invariant_fire", "ae_detect", "fusion_alert", "recovery_start"].includes(cp.id)) {
        lit = Math.max(250, lit - 0.9);
        if (spoof !== null) setSpoofedLit(spoof + (Math.random() - 0.5) * 7);
        currentMse = Math.min(0.015, currentMse + 0.002);
      } else if (["recovery_write", "recovery_verify", "recovered"].includes(cp.id)) {
        lit = Math.min(800, lit + 1.2);
        currentMse = Math.max(0.00003, currentMse * 0.7);
        currentFusion = Math.max(0, currentFusion * 0.6);
        if (cp.id === "recovery_verify") {
          cleanCycles++;
          if (cleanCycles <= 5) addEvt(`Clean cycle ${cleanCycles}/5 ✓`, "recover");
        }
      } else {
        lit = lit + (Math.random() - 0.5) * 0.3;
        currentMse = 0.00003 + Math.random() * 0.00002;
        currentFusion = 0;
      }

      setLit101(lit);
      setMse(currentMse);
      setFusionScore(currentFusion);
      litHist = [...litHist.slice(-60), lit];
      mseHist = [...mseHist.slice(-60), currentMse];
      fusHist = [...fusHist.slice(-60), currentFusion];
      setLitHistory([...litHist]);
      setMseHistory([...mseHist]);
      setFusionHistory([...fusHist]);
    }, 500);
  };

  const isAttack = ["attack_inject", "attack_active", "phase2_start", "invariant_fire", "ae_detect", "fusion_alert"].includes(currentPhase.id);
  const isRecovery = ["recovery_start", "recovery_write", "recovery_verify", "recovered"].includes(currentPhase.id);
  const isDetect = ["invariant_fire", "ae_detect", "fusion_alert"].includes(currentPhase.id);

  const statusColor = isAttack ? RED : isRecovery ? GREEN : isDetect ? AMBER : CYAN;

  return (
    <div
      style={{
        background: DARK,
        minHeight: "100vh",
        color: TEXT,
        fontFamily: "'Segoe UI', system-ui, sans-serif",
        padding: 16,
      }}
    >
      <style>{`
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        @keyframes scanline { 0%{transform:translateY(-100%)} 100%{transform:translateY(100vh)} }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: ${DARK}; }
        ::-webkit-scrollbar-thumb { background: ${BORDER}; border-radius: 2px; }
      `}</style>

      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16, borderBottom: `1px solid ${BORDER}`, paddingBottom: 12 }}>
        <div>
          <div style={{ fontSize: 11, color: RED, fontWeight: 700, letterSpacing: 2, marginBottom: 2 }}>SWAT TESTBED</div>
          <div style={{ fontSize: 20, fontWeight: 700, letterSpacing: -0.5 }}>
            CPS Attack & Defence Dashboard
          </div>
          <div style={{ fontSize: 11, color: MUTED }}>51.508 Secure Cyber-Physical Systems · iTrust Lab, SUTD · Stage P1</div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <div style={{
            padding: "6px 16px",
            background: `${statusColor}15`,
            border: `1px solid ${statusColor}`,
            borderRadius: 4,
            fontSize: 12,
            fontWeight: 700,
            color: statusColor,
            letterSpacing: 1,
          }}>
            <StatusDot color={statusColor} pulse={running} />
            {currentPhase.label}
          </div>
          <button
            onClick={running ? resetAll : startDemo}
            style={{
              padding: "6px 20px",
              background: running ? RED : GREEN,
              border: "none",
              borderRadius: 4,
              color: "#fff",
              fontSize: 12,
              fontWeight: 700,
              cursor: "pointer",
              letterSpacing: 0.5,
            }}
          >
            {running ? "STOP" : "▶ START DEMO"}
          </button>
        </div>
      </div>

      {/* Main Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 280px", gap: 12, gridTemplateRows: "auto auto auto" }}>

        {/* P1 Schematic */}
        <Panel title="P1 Process Schematic" accent={CYAN} style={{ gridColumn: "1 / 3", gridRow: "1" }}>
          <svg viewBox="0 0 500 140" style={{ width: "100%", height: 130 }}>
            {/* Tank */}
            <rect x="200" y="20" width="100" height="100" rx="4" fill="none" stroke={CYAN} strokeWidth="1.5" />
            <rect
              x="202" y={120 - ((lit101 - 200) / 800) * 98}
              width="96"
              height={((lit101 - 200) / 800) * 98}
              fill={`${CYAN}30`}
              stroke="none"
            />
            <text x="250" y="75" textAnchor="middle" fill={TEXT} fontSize="14" fontWeight="700" fontFamily="monospace">
              {lit101.toFixed(0)}mm
            </text>
            <text x="250" y="90" textAnchor="middle" fill={sim ? RED : DIM} fontSize="9" fontFamily="monospace">
              {sim ? `SPOOFED: ${spoofedLit?.toFixed(0) || "—"}mm` : "LIT101"}
            </text>
            <text x="250" y="15" textAnchor="middle" fill={DIM} fontSize="10">T101</text>

            {/* MV101 Inlet */}
            <line x1="80" y1="50" x2="195" y2="50" stroke={mv101 === "OPEN" ? GREEN : RED} strokeWidth="2" />
            <rect x="50" y="40" width="30" height="20" rx="3" fill={mv101 === "OPEN" ? `${GREEN}30` : `${RED}30`} stroke={mv101 === "OPEN" ? GREEN : RED} strokeWidth="1.5" />
            <text x="65" y="54" textAnchor="middle" fill={mv101 === "OPEN" ? GREEN : RED} fontSize="8" fontWeight="700">MV101</text>
            <text x="65" y="72" textAnchor="middle" fill={mv101 === "OPEN" ? GREEN : RED} fontSize="9" fontWeight="700">{mv101}</text>

            {/* P101 Pump */}
            <line x1="305" y1="90" x2="380" y2="90" stroke={p101 !== "AUTO" ? RED : CYAN} strokeWidth="2" />
            <circle cx="400" cy="90" r="18" fill={p101 !== "AUTO" ? `${RED}30` : `${CYAN}20`} stroke={p101 !== "AUTO" ? RED : CYAN} strokeWidth="1.5" />
            <text x="400" y="87" textAnchor="middle" fill={p101 !== "AUTO" ? RED : CYAN} fontSize="8" fontWeight="700">P101</text>
            <text x="400" y="97" textAnchor="middle" fill={p101 !== "AUTO" ? RED : CYAN} fontSize="7">{p101}</text>

            {/* MV201 Outlet */}
            <line x1="422" y1="90" x2="470" y2="90" stroke={mv201 === "OPEN" ? RED : GREEN} strokeWidth="2" />
            <text x="460" y="82" fill={DIM} fontSize="8">→P2</text>
            <text x="460" y="105" fill={mv201 === "OPEN" ? RED : GREEN} fontSize="8" fontWeight="700">MV201:{mv201}</text>

            {/* FIT101 */}
            <text x="140" y="44" fill={DIM} fontSize="8">FIT101</text>
            <text x="140" y="55" fill={fit101 < 0.1 ? RED : GREEN} fontSize="10" fontWeight="700" fontFamily="monospace">{fit101.toFixed(2)}L/s</text>

            {/* Sim indicator */}
            {sim && (
              <g>
                <rect x="310" y="20" width="80" height="20" rx="3" fill={`${RED}30`} stroke={RED} strokeWidth="1" />
                <text x="350" y="34" textAnchor="middle" fill={RED} fontSize="9" fontWeight="700">SIM ACTIVE</text>
              </g>
            )}
          </svg>
        </Panel>

        {/* Sensor Gauges */}
        <Panel title="Sensor Readings" accent={BLUE} style={{ gridRow: "1" }}>
          <GaugeBar label="LIT101 (Tank Level)" value={lit101} max={1000} unit="mm" color={CYAN} warn={lit101 < 300 || lit101 > 800} />
          <GaugeBar label="FIT101 (Inlet Flow)" value={fit101} max={3} unit=" L/s" color={GREEN} warn={fit101 < 0} />
          <GaugeBar label="AE MSE" value={mse} max={0.02} unit="" color={mse > 0.000738 ? RED : GREEN} warn={mse > 0.000738} />
          <GaugeBar label="Fusion Score" value={fusionScore} max={3} unit="" color={fusionScore >= 1.5 ? RED : GREEN} warn={fusionScore >= 1.5} />
          <div style={{ marginTop: 8, fontSize: 10, color: DIM }}>
            AE Threshold: 0.000738 · Fusion Alert: ≥1.5
          </div>
        </Panel>

        {/* Timeline */}
        <Panel title="Event Timeline" accent={AMBER} style={{ gridColumn: "4", gridRow: "1 / 4", overflowY: "auto", maxHeight: 520 }}>
          {events.length === 0 && (
            <div style={{ color: MUTED, fontSize: 11, textAlign: "center", padding: 20 }}>
              Press START DEMO to begin
            </div>
          )}
          {events.map((e, i) => (
            <TimelineEvent key={i} time={e.time} text={e.text} type={e.type} />
          ))}
          <div ref={eventsEndRef} />
        </Panel>

        {/* Charts */}
        <Panel title="LIT101 Level History" accent={CYAN} style={{ gridColumn: "1" }}>
          <Sparkline data={litHistory} color={CYAN} height={60} width={320} />
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: DIM, marginTop: 4 }}>
            <span>LL=250mm</span>
            <span>HH=800mm</span>
          </div>
        </Panel>

        <Panel title="AE Reconstruction Error" accent={mse > 0.000738 ? RED : GREEN}>
          <Sparkline data={mseHistory} color={mse > 0.000738 ? RED : GREEN} height={60} width={320} />
          <div style={{ fontSize: 10, color: mse > 0.000738 ? RED : DIM, marginTop: 4 }}>
            {mse > 0.000738 ? "⚠ ABOVE THRESHOLD" : "Within normal range"}
          </div>
        </Panel>

        <Panel title="Fusion Score" accent={fusionScore >= 1.5 ? RED : GREEN}>
          <Sparkline data={fusionHistory} color={fusionScore >= 1.5 ? RED : GREEN} height={60} width={320} />
          <div style={{ fontSize: 10, color: fusionScore >= 1.5 ? RED : DIM, marginTop: 4 }}>
            {fusionScore >= 1.5 ? "🔴 ALERT — Recovery triggered" : "Score = 1.5×inv + 1.0×ae"}
          </div>
        </Panel>

        {/* Invariant Checker */}
        <Panel title="Invariant Checker (9 Rules)" accent={invStates.some((i) => i.status === "fail") ? RED : GREEN} style={{ gridColumn: "1 / 3" }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 4 }}>
            {invStates.map((inv) => (
              <div
                key={inv.id}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  padding: "4px 8px",
                  background: inv.status === "fail" ? `${RED}15` : `${GREEN}08`,
                  borderRadius: 3,
                  border: `1px solid ${inv.status === "fail" ? `${RED}40` : `${GREEN}20`}`,
                  fontSize: 10,
                }}
              >
                <StatusDot color={inv.status === "fail" ? RED : GREEN} pulse={inv.status === "fail"} />
                <span style={{ fontWeight: 700, color: inv.status === "fail" ? RED : GREEN, minWidth: 24 }}>{inv.id}</span>
                <span style={{ color: DIM, fontSize: 9 }}>{inv.desc}</span>
              </div>
            ))}
          </div>
        </Panel>

        {/* Recovery Pipeline */}
        <Panel title="Recovery Pipeline" accent={isRecovery ? GREEN : MUTED}>
          {["DETECT", "CONTAIN", "SAFE STATE", "FAILOVER", "VERIFY"].map((step, i) => {
            const stepPhases = ["recovery_start", "recovery_start", "recovery_write", "recovery_verify", "recovery_verify"];
            const phaseIdx = PHASES.findIndex((p) => p.id === stepPhases[i]);
            const active = phase >= phaseIdx && isRecovery;
            const done = phase > phaseIdx + (i < 2 ? 0 : 1);
            return (
              <div
                key={step}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  padding: "5px 8px",
                  marginBottom: 3,
                  background: active ? `${GREEN}15` : "transparent",
                  borderRadius: 3,
                  border: `1px solid ${active ? `${GREEN}30` : "transparent"}`,
                  fontSize: 11,
                }}
              >
                <span style={{ color: done ? GREEN : active ? AMBER : MUTED, fontSize: 13 }}>
                  {done ? "✓" : active ? "▶" : "○"}
                </span>
                <span style={{ fontWeight: 600, color: done ? GREEN : active ? TEXT : MUTED }}>
                  Step {i + 1}: {step}
                </span>
              </div>
            );
          })}
        </Panel>
      </div>
    </div>
  );
}
