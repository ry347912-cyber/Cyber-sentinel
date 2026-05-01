import { useState, useEffect, useRef, useCallback } from "react";
import { LineChart, Line, AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";

const ATTACK_TYPES = ["DDoS", "Port Scan", "SQL Injection", "Brute Force", "XSS", "ARP Spoof", "MITM", "DNS Flood"];
const PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "FTP", "SSH"];
const SEVERITY = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
const FAKE_IPS = ["192.168.1.", "10.0.0.", "172.16.0.", "203.0.113.", "198.51.100.", "185.220.101.", "45.33.32.", "104.21.14."];

function randIP() { return FAKE_IPS[Math.floor(Math.random() * FAKE_IPS.length)] + Math.floor(Math.random() * 254 + 1); }
function randItem(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

const SEV_COLOR = { LOW: "#22c55e", MEDIUM: "#f59e0b", HIGH: "#f97316", CRITICAL: "#ef4444" };

function genAlert() {
  return {
    id: Date.now() + Math.random(),
    time: new Date().toLocaleTimeString(),
    type: randItem(ATTACK_TYPES),
    srcIP: randIP(),
    dstIP: randIP(),
    protocol: randItem(PROTOCOLS),
    severity: randItem(SEVERITY),
    packets: randInt(100, 9999),
    port: randInt(1, 65535),
  };
}

function genTrafficPoint(label) {
  return { time: label, packets: randInt(200, 1200), attacks: randInt(0, 80), normal: randInt(150, 1100) };
}

const INIT_TRAFFIC = Array.from({ length: 20 }, (_, i) => genTrafficPoint(`${i}s`));
const INIT_ALERTS = Array.from({ length: 12 }, genAlert);

const PIE_DATA_BASE = [
  { name: "DDoS", value: 28 },
  { name: "Port Scan", value: 22 },
  { name: "Brute Force", value: 18 },
  { name: "SQL Injection", value: 15 },
  { name: "Other", value: 17 },
];
const PIE_COLORS = ["#ef4444", "#f97316", "#f59e0b", "#a855f7", "#6b7280"];

export default function IDSDashboard() {
  const [tab, setTab] = useState("dashboard");
  const [alerts, setAlerts] = useState(INIT_ALERTS);
  const [traffic, setTraffic] = useState(INIT_TRAFFIC);
  const [stats, setStats] = useState({ totalPackets: 847293, attacks: 1247, blocked: 1183, uptime: "3d 14h 22m" });
  const [live, setLive] = useState(true);
  const [filterSev, setFilterSev] = useState("ALL");
  const [filterType, setFilterType] = useState("ALL");
  const [searchIP, setSearchIP] = useState("");
  const [threshold, setThreshold] = useState(500);
  const [mlEnabled, setMlEnabled] = useState(true);
  const [deepInspect, setDeepInspect] = useState(false);
  const [autoBlock, setAutoBlock] = useState(true);
  const [chatMessages, setChatMessages] = useState([
    { role: "assistant", text: "Hello! I'm your IDS AI assistant. Ask me about attack types, network security, or any alerts." }
  ]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const chatEndRef = useRef(null);
  const tickRef = useRef(0);

  useEffect(() => {
    if (!live) return;
    const interval = setInterval(() => {
      tickRef.current++;
      const label = `${tickRef.current}s`;
      setTraffic(prev => [...prev.slice(-29), genTrafficPoint(label)]);
      setStats(prev => ({
        ...prev,
        totalPackets: prev.totalPackets + randInt(50, 400),
        attacks: prev.attacks + (Math.random() > 0.7 ? 1 : 0),
        blocked: prev.blocked + (Math.random() > 0.75 ? 1 : 0),
      }));
      if (Math.random() > 0.6) {
        setAlerts(prev => [genAlert(), ...prev].slice(0, 100));
      }
    }, 1200);
    return () => clearInterval(interval);
  }, [live]);

  useEffect(() => { chatEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [chatMessages]);

  const sendChat = useCallback(async (text) => {
    if (!text.trim()) return;
    const userMsg = { role: "user", text };
    setChatMessages(prev => [...prev, userMsg]);
    setChatInput("");
    setChatLoading(true);
    try {
      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1000,
          system: "You are an expert cybersecurity AI assistant embedded in a Network Intrusion Detection System (IDS) dashboard. Answer questions about network attacks, security threats, protocols, and IDS configurations. Be concise and technical but clear. Use bullet points when listing items.",
          messages: [
            ...chatMessages.filter(m => m.role !== "assistant" || chatMessages.indexOf(m) > 0).map(m => ({ role: m.role, content: m.text })),
            { role: "user", content: text }
          ],
        }),
      });
      const data = await res.json();
      const reply = data.content?.[0]?.text || "Sorry, I couldn't process that.";
      setChatMessages(prev => [...prev, { role: "assistant", text: reply }]);
    } catch {
      setChatMessages(prev => [...prev, { role: "assistant", text: "Connection error. Please try again." }]);
    }
    setChatLoading(false);
  }, [chatMessages]);

  const filteredAlerts = alerts.filter(a => {
    if (filterSev !== "ALL" && a.severity !== filterSev) return false;
    if (filterType !== "ALL" && a.type !== filterType) return false;
    if (searchIP && !a.srcIP.includes(searchIP) && !a.dstIP.includes(searchIP)) return false;
    return true;
  });

  const styles = {
    root: { background: "#0a0e1a", minHeight: "100vh", color: "#e2e8f0", fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace", fontSize: 13 },
    header: { background: "#0d1220", borderBottom: "1px solid #1e3a5f", padding: "0 24px", display: "flex", alignItems: "center", justifyContent: "space-between", height: 56 },
    logo: { display: "flex", alignItems: "center", gap: 10 },
    logoIcon: { width: 32, height: 32, background: "linear-gradient(135deg,#00d4ff,#0066ff)", borderRadius: 6, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16 },
    logoText: { fontSize: 16, fontWeight: 700, color: "#00d4ff", letterSpacing: "0.05em" },
    logoSub: { fontSize: 10, color: "#64748b", letterSpacing: "0.1em" },
    statusDot: { width: 8, height: 8, borderRadius: "50%", background: live ? "#22c55e" : "#ef4444", boxShadow: live ? "0 0 6px #22c55e" : "none" },
    nav: { display: "flex", gap: 2, padding: "0 24px", background: "#0d1220", borderBottom: "1px solid #1a2744" },
    navItem: (active) => ({ padding: "12px 16px", cursor: "pointer", fontSize: 12, letterSpacing: "0.08em", textTransform: "uppercase", borderBottom: active ? "2px solid #00d4ff" : "2px solid transparent", color: active ? "#00d4ff" : "#64748b", background: "none", border: "none", borderBottom: active ? "2px solid #00d4ff" : "2px solid transparent", fontFamily: "inherit" }),
    body: { padding: 20, maxWidth: 1400, margin: "0 auto" },
    grid4: { display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginBottom: 16 },
    grid2: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 },
    card: { background: "#0d1220", border: "1px solid #1e3a5f", borderRadius: 8, padding: 16 },
    statCard: { background: "#0d1220", border: "1px solid #1e3a5f", borderRadius: 8, padding: 16 },
    statLabel: { fontSize: 10, color: "#64748b", letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 6 },
    statValue: { fontSize: 28, fontWeight: 700, color: "#00d4ff" },
    statSub: { fontSize: 10, color: "#64748b", marginTop: 4 },
    cardTitle: { fontSize: 11, color: "#94a3b8", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 12, display: "flex", alignItems: "center", gap: 6 },
    alertRow: (sev) => ({
      display: "grid", gridTemplateColumns: "80px 90px 1fr 1fr 60px 80px 80px",
      gap: 8, padding: "7px 10px", borderRadius: 4, cursor: "pointer",
      borderLeft: `3px solid ${SEV_COLOR[sev]}`,
      marginBottom: 3,
      background: "#0a0e1a",
      fontSize: 11,
      alignItems: "center",
    }),
    sevBadge: (sev) => ({ background: SEV_COLOR[sev] + "22", color: SEV_COLOR[sev], padding: "2px 6px", borderRadius: 3, fontSize: 10, fontWeight: 700, letterSpacing: "0.05em", textAlign: "center" }),
    input: { background: "#0a0e1a", border: "1px solid #1e3a5f", borderRadius: 4, color: "#e2e8f0", padding: "6px 10px", fontSize: 12, fontFamily: "inherit", outline: "none", width: "100%" },
    select: { background: "#0a0e1a", border: "1px solid #1e3a5f", borderRadius: 4, color: "#e2e8f0", padding: "6px 10px", fontSize: 12, fontFamily: "inherit", outline: "none" },
    btn: (active) => ({ background: active ? "#00d4ff" : "transparent", color: active ? "#000" : "#00d4ff", border: "1px solid #00d4ff", borderRadius: 4, padding: "6px 14px", cursor: "pointer", fontSize: 11, fontFamily: "inherit", letterSpacing: "0.08em", fontWeight: active ? 700 : 400 }),
    chatBubble: (role) => ({ alignSelf: role === "user" ? "flex-end" : "flex-start", maxWidth: "82%", padding: "10px 14px", borderRadius: role === "user" ? "12px 12px 2px 12px" : "12px 12px 12px 2px", background: role === "user" ? "#1e3a5f" : "#131b2e", border: role === "user" ? "1px solid #00d4ff44" : "1px solid #1e3a5f", color: "#e2e8f0", fontSize: 12, lineHeight: 1.6, whiteSpace: "pre-wrap" }),
    toggle: (on) => ({ width: 36, height: 20, borderRadius: 10, background: on ? "#00d4ff" : "#1e3a5f", cursor: "pointer", position: "relative", border: "none", transition: "background 0.2s", flexShrink: 0 }),
    toggleDot: (on) => ({ position: "absolute", top: 3, left: on ? 17 : 3, width: 14, height: 14, borderRadius: "50%", background: on ? "#000" : "#64748b", transition: "left 0.2s" }),
    settingRow: { display: "flex", alignItems: "center", justifyContent: "space-between", padding: "14px 0", borderBottom: "1px solid #1a2744" },
  };

  const severityCounts = SEVERITY.reduce((a, s) => { a[s] = alerts.filter(x => x.severity === s).length; return a; }, {});

  return (
    <div style={styles.root}>
      {/* Header */}
      <div style={styles.header}>
        <div style={styles.logo}>
          <div style={styles.logoIcon}>🛡</div>
          <div>
            <div style={styles.logoText}>NETGUARD IDS</div>
            <div style={styles.logoSub}>NETWORK INTRUSION DETECTION SYSTEM</div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: "#64748b" }}>
            <div style={styles.statusDot} />
            {live ? "LIVE MONITORING" : "PAUSED"}
          </div>
          <button style={styles.btn(live)} onClick={() => setLive(v => !v)}>
            {live ? "⏸ PAUSE" : "▶ RESUME"}
          </button>
          <div style={{ fontSize: 11, color: "#64748b" }}>⏱ {stats.uptime}</div>
        </div>
      </div>

      {/* Nav */}
      <div style={styles.nav}>
        {[["dashboard","📊 Dashboard"],["attacks","⚡ Live Attacks"],["logs","📋 Logs"],["settings","⚙ Settings"],["chat","🤖 AI Assistant"]].map(([id, label]) => (
          <button key={id} style={styles.navItem(tab === id)} onClick={() => setTab(id)}>{label}</button>
        ))}
      </div>

      <div style={styles.body}>

        {/* ── DASHBOARD ── */}
        {tab === "dashboard" && (
          <>
            <div style={styles.grid4}>
              {[
                { label: "Total Packets", val: stats.totalPackets.toLocaleString(), sub: "+350/sec", color: "#00d4ff" },
                { label: "Attacks Detected", val: stats.attacks.toLocaleString(), sub: "Last 24h", color: "#ef4444" },
                { label: "Threats Blocked", val: stats.blocked.toLocaleString(), sub: `${Math.round(stats.blocked/stats.attacks*100)}% block rate`, color: "#22c55e" },
                { label: "Active Alerts", val: alerts.filter(a=>a.severity==="CRITICAL"||a.severity==="HIGH").length, sub: "Critical + High", color: "#f97316" },
              ].map(({ label, val, sub, color }) => (
                <div key={label} style={styles.statCard}>
                  <div style={styles.statLabel}>{label}</div>
                  <div style={{ ...styles.statValue, color }}>{val}</div>
                  <div style={styles.statSub}>{sub}</div>
                </div>
              ))}
            </div>

            <div style={{ marginBottom: 12, ...styles.card }}>
              <div style={styles.cardTitle}><span style={{ color: "#00d4ff" }}>◈</span> Live Network Traffic</div>
              <ResponsiveContainer width="100%" height={180}>
                <AreaChart data={traffic}>
                  <defs>
                    <linearGradient id="gNorm" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#00d4ff" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="gAtk" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1a2744" />
                  <XAxis dataKey="time" tick={{ fill: "#64748b", fontSize: 10 }} interval={4} />
                  <YAxis tick={{ fill: "#64748b", fontSize: 10 }} />
                  <Tooltip contentStyle={{ background: "#0d1220", border: "1px solid #1e3a5f", borderRadius: 6, fontSize: 11 }} />
                  <Area type="monotone" dataKey="packets" stroke="#00d4ff" fill="url(#gNorm)" strokeWidth={1.5} dot={false} name="Packets/s" />
                  <Area type="monotone" dataKey="attacks" stroke="#ef4444" fill="url(#gAtk)" strokeWidth={1.5} dot={false} name="Attacks/s" />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <div style={styles.grid2}>
              <div style={styles.card}>
                <div style={styles.cardTitle}><span style={{ color: "#a855f7" }}>◈</span> Attack Distribution</div>
                <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
                  <PieChart width={140} height={140}>
                    <Pie data={PIE_DATA_BASE} cx={65} cy={65} innerRadius={40} outerRadius={65} dataKey="value" stroke="none">
                      {PIE_DATA_BASE.map((_, i) => <Cell key={i} fill={PIE_COLORS[i]} />)}
                    </Pie>
                  </PieChart>
                  <div style={{ flex: 1 }}>
                    {PIE_DATA_BASE.map((d, i) => (
                      <div key={d.name} style={{ display: "flex", justifyContent: "space-between", padding: "3px 0", fontSize: 11 }}>
                        <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
                          <span style={{ width: 8, height: 8, borderRadius: 2, background: PIE_COLORS[i], display: "inline-block" }} />
                          {d.name}
                        </span>
                        <span style={{ color: PIE_COLORS[i], fontWeight: 700 }}>{d.value}%</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div style={styles.card}>
                <div style={styles.cardTitle}><span style={{ color: "#f97316" }}>◈</span> Severity Breakdown</div>
                <ResponsiveContainer width="100%" height={140}>
                  <BarChart data={SEVERITY.map(s => ({ name: s, count: severityCounts[s] || 0 }))}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1a2744" />
                    <XAxis dataKey="name" tick={{ fill: "#64748b", fontSize: 10 }} />
                    <YAxis tick={{ fill: "#64748b", fontSize: 10 }} />
                    <Tooltip contentStyle={{ background: "#0d1220", border: "1px solid #1e3a5f", borderRadius: 6, fontSize: 11 }} />
                    <Bar dataKey="count" radius={[3,3,0,0]}>
                      {SEVERITY.map((s) => <Cell key={s} fill={SEV_COLOR[s]} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Recent Alerts */}
            <div style={{ ...styles.card, marginTop: 12 }}>
              <div style={styles.cardTitle}><span style={{ color: "#ef4444" }}>◈</span> Recent Critical Alerts</div>
              <div style={{ display: "grid", gridTemplateColumns: "80px 90px 1fr 1fr 60px 80px 80px", gap: 8, padding: "4px 10px", marginBottom: 6, fontSize: 10, color: "#64748b", letterSpacing: "0.08em", textTransform: "uppercase" }}>
                <span>Time</span><span>Severity</span><span>Source IP</span><span>Destination</span><span>Protocol</span><span>Type</span><span>Packets</span>
              </div>
              {alerts.slice(0, 8).map(a => (
                <div key={a.id} style={styles.alertRow(a.severity)} onClick={() => setSelectedAlert(a)}>
                  <span style={{ color: "#64748b" }}>{a.time}</span>
                  <span style={styles.sevBadge(a.severity)}>{a.severity}</span>
                  <span style={{ color: "#00d4ff", fontFamily: "monospace" }}>{a.srcIP}</span>
                  <span style={{ color: "#94a3b8", fontFamily: "monospace" }}>{a.dstIP}</span>
                  <span style={{ color: "#a855f7" }}>{a.protocol}</span>
                  <span style={{ color: "#f97316" }}>{a.type}</span>
                  <span style={{ color: "#64748b" }}>{a.packets.toLocaleString()}</span>
                </div>
              ))}
            </div>
          </>
        )}

        {/* ── ATTACKS ── */}
        {tab === "attacks" && (
          <>
            <div style={{ display: "flex", gap: 10, marginBottom: 14, flexWrap: "wrap", alignItems: "center" }}>
              <div style={{ fontSize: 11, color: "#64748b", marginRight: 4 }}>FILTER:</div>
              {["ALL", ...SEVERITY].map(s => (
                <button key={s} onClick={() => setFilterSev(s)} style={{ ...styles.btn(filterSev === s), borderColor: s === "ALL" ? "#00d4ff" : SEV_COLOR[s] || "#00d4ff", color: filterSev === s ? "#000" : (SEV_COLOR[s] || "#00d4ff"), background: filterSev === s ? (SEV_COLOR[s] || "#00d4ff") : "transparent", fontSize: 10, padding: "4px 10px" }}>
                  {s}
                </button>
              ))}
              <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center" }}>
                <span style={{ color: "#ef4444", fontSize: 11, fontWeight: 700 }}>⚡ {filteredAlerts.filter(a => a.severity === "CRITICAL").length} CRITICAL</span>
                <span style={{ color: "#f97316", fontSize: 11 }}>▲ {filteredAlerts.filter(a => a.severity === "HIGH").length} HIGH</span>
              </div>
            </div>

            <div style={styles.card}>
              <div style={{ display: "grid", gridTemplateColumns: "80px 90px 1fr 1fr 60px 1fr 80px 80px", gap: 8, padding: "4px 10px", marginBottom: 8, fontSize: 10, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                <span>Time</span><span>Severity</span><span>Source IP</span><span>Dest IP</span><span>Proto</span><span>Attack Type</span><span>Port</span><span>Packets</span>
              </div>
              <div style={{ maxHeight: 480, overflowY: "auto" }}>
                {filteredAlerts.map(a => (
                  <div key={a.id} style={{ ...styles.alertRow(a.severity), gridTemplateColumns: "80px 90px 1fr 1fr 60px 1fr 80px 80px" }} onClick={() => setSelectedAlert(a)}>
                    <span style={{ color: "#64748b" }}>{a.time}</span>
                    <span style={styles.sevBadge(a.severity)}>{a.severity}</span>
                    <span style={{ color: "#00d4ff" }}>{a.srcIP}</span>
                    <span style={{ color: "#94a3b8" }}>{a.dstIP}</span>
                    <span style={{ color: "#a855f7" }}>{a.protocol}</span>
                    <span style={{ color: "#f97316" }}>{a.type}</span>
                    <span style={{ color: "#64748b" }}>:{a.port}</span>
                    <span style={{ color: "#64748b" }}>{a.packets.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}

        {/* ── LOGS ── */}
        {tab === "logs" && (
          <>
            <div style={{ display: "flex", gap: 10, marginBottom: 14, alignItems: "center" }}>
              <input style={{ ...styles.input, maxWidth: 200 }} placeholder="Search IP..." value={searchIP} onChange={e => setSearchIP(e.target.value)} />
              <select style={styles.select} value={filterType} onChange={e => setFilterType(e.target.value)}>
                <option value="ALL">All Types</option>
                {ATTACK_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
              <select style={styles.select} value={filterSev} onChange={e => setFilterSev(e.target.value)}>
                <option value="ALL">All Severity</option>
                {SEVERITY.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
              <span style={{ fontSize: 11, color: "#64748b", marginLeft: "auto" }}>{filteredAlerts.length} records</span>
            </div>
            <div style={styles.card}>
              <div style={{ fontFamily: "monospace", fontSize: 11, lineHeight: 1.5, maxHeight: 520, overflowY: "auto" }}>
                {filteredAlerts.map(a => (
                  <div key={a.id} style={{ padding: "5px 0", borderBottom: "1px solid #0d1220", display: "flex", gap: 10, alignItems: "center" }}>
                    <span style={{ color: "#64748b", minWidth: 70 }}>{a.time}</span>
                    <span style={styles.sevBadge(a.severity)}>{a.severity[0]}</span>
                    <span style={{ color: "#00d4ff", minWidth: 110 }}>{a.srcIP}</span>
                    <span style={{ color: "#64748b" }}>→</span>
                    <span style={{ color: "#94a3b8", minWidth: 110 }}>{a.dstIP}</span>
                    <span style={{ color: "#a855f7", minWidth: 50 }}>{a.protocol}</span>
                    <span style={{ color: "#f97316", minWidth: 110 }}>{a.type}</span>
                    <span style={{ color: "#64748b" }}>:{a.port}</span>
                    <span style={{ color: "#22c55e", marginLeft: "auto" }}>{a.packets.toLocaleString()} pkts</span>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}

        {/* ── SETTINGS ── */}
        {tab === "settings" && (
          <div style={{ maxWidth: 640 }}>
            <div style={styles.card}>
              <div style={styles.cardTitle}><span style={{ color: "#00d4ff" }}>◈</span> Detection Configuration</div>

              <div style={styles.settingRow}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>ML Detection Engine</div>
                  <div style={{ color: "#64748b", fontSize: 11, marginTop: 3 }}>Use scikit-learn model for anomaly detection</div>
                </div>
                <button style={styles.toggle(mlEnabled)} onClick={() => setMlEnabled(v => !v)}>
                  <div style={styles.toggleDot(mlEnabled)} />
                </button>
              </div>

              <div style={styles.settingRow}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>Deep Packet Inspection</div>
                  <div style={{ color: "#64748b", fontSize: 11, marginTop: 3 }}>Analyze packet payloads (higher CPU usage)</div>
                </div>
                <button style={styles.toggle(deepInspect)} onClick={() => setDeepInspect(v => !v)}>
                  <div style={styles.toggleDot(deepInspect)} />
                </button>
              </div>

              <div style={styles.settingRow}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>Auto-Block Threats</div>
                  <div style={{ color: "#64748b", fontSize: 11, marginTop: 3 }}>Automatically block CRITICAL and HIGH severity IPs</div>
                </div>
                <button style={styles.toggle(autoBlock)} onClick={() => setAutoBlock(v => !v)}>
                  <div style={styles.toggleDot(autoBlock)} />
                </button>
              </div>

              <div style={{ ...styles.settingRow, borderBottom: "none", flexDirection: "column", alignItems: "flex-start", gap: 10 }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>Packet Alert Threshold</div>
                  <div style={{ color: "#64748b", fontSize: 11, marginTop: 3 }}>Trigger alert when packets/sec exceeds this value</div>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 12, width: "100%" }}>
                  <input type="range" min={100} max={2000} step={50} value={threshold} onChange={e => setThreshold(Number(e.target.value))} style={{ flex: 1 }} />
                  <span style={{ color: "#00d4ff", minWidth: 50, fontWeight: 700 }}>{threshold} p/s</span>
                </div>
              </div>
            </div>

            <div style={{ ...styles.card, marginTop: 12 }}>
              <div style={styles.cardTitle}><span style={{ color: "#a855f7" }}>◈</span> System Status</div>
              {[
                { label: "IDS Engine", status: "RUNNING", color: "#22c55e" },
                { label: "ML Model", status: mlEnabled ? "ACTIVE" : "DISABLED", color: mlEnabled ? "#22c55e" : "#64748b" },
                { label: "Packet Capture (Scapy)", status: live ? "CAPTURING" : "PAUSED", color: live ? "#00d4ff" : "#f59e0b" },
                { label: "Database (MongoDB)", status: "CONNECTED", color: "#22c55e" },
                { label: "Cloud Sync (AWS)", status: "SYNCED", color: "#22c55e" },
                { label: "Auto-Block", status: autoBlock ? "ON" : "OFF", color: autoBlock ? "#22c55e" : "#64748b" },
              ].map(({ label, status, color }) => (
                <div key={label} style={{ display: "flex", justifyContent: "space-between", padding: "10px 0", borderBottom: "1px solid #0d1220", fontSize: 12 }}>
                  <span style={{ color: "#94a3b8" }}>{label}</span>
                  <span style={{ color, fontWeight: 700, fontSize: 11, letterSpacing: "0.08em" }}>● {status}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── AI CHAT ── */}
        {tab === "chat" && (
          <div style={{ maxWidth: 720 }}>
            <div style={{ ...styles.card, marginBottom: 12 }}>
              <div style={styles.cardTitle}><span style={{ color: "#a855f7" }}>◈</span> Quick Actions</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                {["What is a DDoS attack?", "Explain SQL Injection", "How does port scanning work?", "What is a MITM attack?", "How to prevent brute force?", "Explain ARP Spoofing"].map(q => (
                  <button key={q} onClick={() => sendChat(q)} style={{ background: "#131b2e", border: "1px solid #1e3a5f", borderRadius: 4, color: "#94a3b8", padding: "6px 12px", cursor: "pointer", fontSize: 11, fontFamily: "inherit" }}>
                    {q} ↗
                  </button>
                ))}
              </div>
            </div>
            <div style={{ ...styles.card, minHeight: 400 }}>
              <div style={{ display: "flex", flexDirection: "column", gap: 10, maxHeight: 400, overflowY: "auto", marginBottom: 14, padding: "4px 0" }}>
                {chatMessages.map((m, i) => (
                  <div key={i} style={styles.chatBubble(m.role)}>
                    {m.role === "assistant" && <div style={{ fontSize: 10, color: "#00d4ff", marginBottom: 4, letterSpacing: "0.08em" }}>🤖 NETGUARD AI</div>}
                    {m.text}
                  </div>
                ))}
                {chatLoading && (
                  <div style={styles.chatBubble("assistant")}>
                    <div style={{ fontSize: 10, color: "#00d4ff", marginBottom: 4 }}>🤖 NETGUARD AI</div>
                    <span style={{ color: "#64748b" }}>Analyzing...</span>
                  </div>
                )}
                <div ref={chatEndRef} />
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <input
                  style={{ ...styles.input, flex: 1 }}
                  placeholder="Ask about network security, attacks, or paste an alert..."
                  value={chatInput}
                  onChange={e => setChatInput(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && !chatLoading && sendChat(chatInput)}
                />
                <button style={{ ...styles.btn(true), whiteSpace: "nowrap" }} onClick={() => sendChat(chatInput)} disabled={chatLoading}>
                  SEND ↗
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Alert Detail Modal */}
      {selectedAlert && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100 }} onClick={() => setSelectedAlert(null)}>
          <div style={{ ...styles.card, width: 480, boxShadow: "0 0 40px #00d4ff22" }} onClick={e => e.stopPropagation()}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: "#00d4ff" }}>Alert Details</div>
              <button onClick={() => setSelectedAlert(null)} style={{ background: "none", border: "none", color: "#64748b", cursor: "pointer", fontSize: 16 }}>✕</button>
            </div>
            <div style={styles.sevBadge(selectedAlert.severity)}>{selectedAlert.severity}</div>
            {[
              ["Attack Type", selectedAlert.type],
              ["Source IP", selectedAlert.srcIP],
              ["Destination IP", selectedAlert.dstIP],
              ["Protocol", selectedAlert.protocol],
              ["Port", `:${selectedAlert.port}`],
              ["Packets", selectedAlert.packets.toLocaleString()],
              ["Time", selectedAlert.time],
            ].map(([k, v]) => (
              <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: "1px solid #0d1220", fontSize: 12 }}>
                <span style={{ color: "#64748b" }}>{k}</span>
                <span style={{ color: "#e2e8f0", fontFamily: "monospace" }}>{v}</span>
              </div>
            ))}
            <div style={{ display: "flex", gap: 8, marginTop: 14 }}>
              <button style={{ ...styles.btn(true), background: "#ef4444", borderColor: "#ef4444", flex: 1 }}>🚫 BLOCK IP</button>
              <button style={{ ...styles.btn(false), flex: 1 }} onClick={() => { setTab("chat"); sendChat(`Explain this attack: ${selectedAlert.type} from ${selectedAlert.srcIP} via ${selectedAlert.protocol} on port ${selectedAlert.port}`); setSelectedAlert(null); }}>🤖 ASK AI ↗</button>
            </div>
          </div>
        </div>
      )}

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: #0a0e1a; }
        ::-webkit-scrollbar-thumb { background: #1e3a5f; border-radius: 2px; }
        input::placeholder { color: #3a5070; }
      `}</style>
    </div>
  );
}
