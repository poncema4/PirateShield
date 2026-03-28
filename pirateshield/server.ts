import express from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { spawn } from "child_process";
import db from "./db.ts";
import {
  calculateRiskScore,
  calculateUnifiedRisk,
  scoreDeviceEvent,
  scoreNetworkRules,
  shouldGenerateNetworkAlert,
  getAlertSeverity,
  type UnifiedEvent,
  type DeviceEvent,
  type NetworkRiskBreakdown,
} from "./risk_scoring.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app  = express();
const PORT = 3000;

const PYTHON = fs.existsSync(path.join(__dirname, ".venv", "bin", "python3"))
  ? path.join(__dirname, ".venv", "bin", "python3")
  : fs.existsSync(path.join(__dirname, ".venv", "Scripts", "python.exe"))
    ? path.join(__dirname, ".venv", "Scripts", "python.exe")
    : "python";

export interface NetworkEvent {
  user_id: string;
  event_id: string;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  destination_port: number;
  lat: number;
  long: number;
  protocol: string;
  bytes_sent: number;
  bytes_received: number;
  device_id: string;
  user_known_devices: string[];
  event_type: string;
}

app.use(express.json());

function maybeCreateAlert(event: Partial<UnifiedEvent | DeviceEvent>, risk_score: number, breakdown?: NetworkRiskBreakdown) {
  const cat = (event as UnifiedEvent).event_category;
  if (cat === "network" && breakdown) {
    if (!shouldGenerateNetworkAlert(risk_score, breakdown)) return;
  } else {
    const severity = getAlertSeverity(risk_score);
    if (!severity) return;
  }
  const severity = getAlertSeverity(risk_score);
  if (!severity) return;
  const { reasons } = calculateUnifiedRisk(event as Partial<UnifiedEvent>);
  db.prepare(`
    INSERT INTO alerts (event_id, user_id, device_id, severity, reason, risk_score)
    VALUES (@event_id, @user_id, @device_id, @severity, @reason, @risk_score)
  `).run({
    event_id:  (event as any).event_id  ?? null,
    user_id:   (event as any).user_id   ?? (event as any).user ?? null,
    device_id: (event as any).device_id ?? null,
    severity,
    reason:    reasons.join("; ") || "Risk threshold exceeded",
    risk_score,
  });
}

function insertUnifiedEvent(event: Partial<UnifiedEvent>, risk_score: number, breakdown?: NetworkRiskBreakdown) {
  db.prepare(`
    INSERT OR IGNORE INTO unified_events
      (event_id, user_id, device_id, event_category, event_type, timestamp,
       source_ip, destination_ip, destination_port, protocol,
       bytes_sent, bytes_received, user_known_devices, lat, long, payload, risk_score)
    VALUES
      (@event_id, @user_id, @device_id, @event_category, @event_type, @timestamp,
       @source_ip, @destination_ip, @destination_port, @protocol,
       @bytes_sent, @bytes_received, @user_known_devices, @lat, @long, @payload, @risk_score)
  `).run({
    event_id:         event.event_id         ?? null,
    user_id:          event.user_id          ?? null,
    device_id:        event.device_id        ?? null,
    event_category:   event.event_category,
    event_type:       event.event_type       ?? null,
    timestamp:        event.timestamp        ?? new Date().toISOString(),
    source_ip:        (event as any).source_ip        ?? null,
    destination_ip:   (event as any).destination_ip   ?? null,
    destination_port: (event as any).destination_port ?? null,
    protocol:         (event as any).protocol         ?? null,
    bytes_sent:       (event as any).bytes_sent       ?? null,
    bytes_received:   (event as any).bytes_received   ?? null,
    user_known_devices: event.user_known_devices ? JSON.stringify(event.user_known_devices) : null,
    lat:              (event as any).lat  ?? null,
    long:             (event as any).long ?? null,
    payload:          JSON.stringify(event),
    risk_score,
  });
  maybeCreateAlert(event, risk_score, breakdown);
}

function readJson(fp: string): any[] {
  if (!fs.existsSync(fp)) return [];
  try { return JSON.parse(fs.readFileSync(fp, "utf-8").replace(/^\uFEFF/, "")); }
  catch { return []; }
}

function writeJson(fp: string, data: any[]) {
  fs.mkdirSync(path.dirname(fp), { recursive: true });
  fs.writeFileSync(fp, JSON.stringify(data, null, 2), { encoding: "utf8" });
}

function ingestDeviceEvent(e: any) {
  const norm: DeviceEvent = { ...e, user_id: e.user ?? e.user_id, usb_action: e.action ?? e.usb_action };
  const { score: risk_score } = scoreDeviceEvent(norm);
  const fp = path.join(__dirname, "data", "synthetic_events", "synthetic_device_events.json");
  const existing = readJson(fp);
  if (!existing.some((x: any) => x.event_id === e.event_id)) writeJson(fp, [...existing, e]);
  try {
    db.prepare(`
      INSERT OR IGNORE INTO device_events
        (event_id, user_id, device_id, device_type, event_type,
         process_name, process_path, suspicious,
         cpu_percent, baseline_cpu, duration_seconds,
         usb_id, usb_action, new_executable_started, exe_path,
         component, new_status, timestamp, payload, risk_score)
      VALUES
        (@event_id,@user_id,@device_id,@device_type,@event_type,
         @process_name,@process_path,@suspicious,
         @cpu_percent,@baseline_cpu,@duration_seconds,
         @usb_id,@usb_action,@new_executable_started,@exe_path,
         @component,@new_status,@timestamp,@payload,@risk_score)
    `).run({
      event_id: norm.event_id ?? null, user_id: norm.user_id ?? null,
      device_id: norm.device_id ?? null, device_type: norm.device_type ?? null,
      event_type: norm.event_type ?? null, process_name: norm.process_name ?? null,
      process_path: norm.process_path ?? null, suspicious: norm.suspicious ? 1 : 0,
      cpu_percent: norm.cpu_percent ?? null, baseline_cpu: norm.baseline_cpu ?? null,
      duration_seconds: norm.duration_seconds ?? null, usb_id: norm.usb_id ?? null,
      usb_action: norm.usb_action ?? null, new_executable_started: norm.new_executable_started ? 1 : 0,
      exe_path: norm.exe_path ?? null, component: norm.component ?? null,
      new_status: norm.new_status ?? null, timestamp: norm.timestamp ?? null,
      payload: JSON.stringify(e), risk_score,
    });
    insertUnifiedEvent({ ...norm, event_category: "device" }, risk_score);
  } catch (err) {
    console.error("Error inserting device event:", err);
  }
}

function ingestIdentityEvent(e: any) {
  const risk_score = e.risk_score ?? 0;
  const fp = path.join(__dirname, "data", "synthetic_events", "synthetic_identity_events.json");
  const existing = readJson(fp);
  const alreadyExists = existing.some((x: any) => x.event_id === e.event_id);
  if (!alreadyExists) writeJson(fp, [...existing, e]);

  try {
    db.prepare(`
      INSERT OR IGNORE INTO identity_events
        (event_id, user_id, device_id, event_type, login_success,
         login_attempts, new_device, os_change, user_known_devices,
         timestamp, payload, risk_score)
      VALUES
        (@event_id, @user_id, @device_id, @event_type, @login_success,
         @login_attempts, @new_device, @os_change, @user_known_devices,
         @timestamp, @payload, @risk_score)
    `).run({
      event_id:           e.event_id          ?? null,
      user_id:            e.user_id           ?? null,
      device_id:          e.device_id         ?? null,
      event_type:         e.event_type        ?? null,
      login_success:      e.login_success     ? 1 : 0,
      login_attempts:     e.login_attempts    ?? null,
      new_device:         e.new_device        ? 1 : 0,
      os_change:          e.os_change         ? 1 : 0,
      user_known_devices: e.user_known_devices ? JSON.stringify(e.user_known_devices) : null,
      timestamp:          e.timestamp         ?? null,
      payload:            JSON.stringify(e),
      risk_score:         e.risk_score        ?? 0,
    });
    insertUnifiedEvent({ ...e, event_category: "identity" }, risk_score);
  } catch (err) {
    console.error("Error inserting identity event:", err);
  }
}

const sharedStyles = `
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; max-width: 1200px; margin: 0 auto; padding: 24px 20px; background: #0d1117; color: #c9d1d9; }
  nav { display: flex; gap: 6px; margin-bottom: 26px; flex-wrap: wrap; padding: 10px 0; border-bottom: 1px solid #21262d; }
  nav a { padding: 8px 18px; border-radius: 6px; text-decoration: none; background: #21262d; color: #c9d1d9; font-size: 13px; font-weight: 500; transition: all 0.15s; }
  nav a:hover { background: #30363d; color: #f0f6fc; }
  nav a.active { background: #1f6feb; color: #ffffff; }
  h1 { margin-bottom: 4px; color: #f0f6fc; font-size: 24px; letter-spacing: -0.3px; }
  h2 { color: #f0f6fc; font-size: 18px; margin-top: 28px; margin-bottom: 12px; }
  .subtitle { color: #8b949e; font-size: 13px; margin-top: 0; margin-bottom: 20px; }
  .controls { margin: 14px 0; display: flex; gap: 8px; flex-wrap: wrap; }
  button { padding: 8px 16px; font-size: 13px; cursor: pointer; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-weight: 500; transition: all 0.15s; }
  .btn-green  { background: #238636; border-color: #238636; color: white; } .btn-green:hover  { background: #2ea043; }
  .btn-blue   { background: #1f6feb; border-color: #1f6feb; color: white; } .btn-blue:hover   { background: #388bfd; }
  .btn-red    { background: #da3633; border-color: #da3633; color: white; } .btn-red:hover    { background: #f85149; }
  .btn-orange { background: #d29922; border-color: #d29922; color: white; } .btn-orange:hover { background: #e3b341; }
  .btn-purple { background: #8957e5; border-color: #8957e5; color: white; } .btn-purple:hover { background: #a371f7; }
  .btn-gray   { background: #21262d; } .btn-gray:hover { background: #30363d; }
  button:disabled { opacity: 0.4; cursor: not-allowed; }
  .card { border: 1px solid #21262d; padding: 12px 16px; margin: 6px 0; border-radius: 8px; background: #161b22; font-size: 13px; line-height: 1.5; }
  .risk-critical { border-left: 4px solid #da3633; }
  .risk-high     { border-left: 4px solid #f85149; }
  .risk-medium   { border-left: 4px solid #d29922; }
  .risk-low      { border-left: 4px solid #3fb950; }
  .risk-none     { border-left: 4px solid #30363d; }
  .badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:600; color:white; margin-right:4px; }
  .badge-critical  { background:#da3633; }
  .badge-high      { background:#f85149; }
  .badge-medium    { background:#d29922; color:#1c1c1c; }
  .badge-low       { background:#3fb950; color:#1c1c1c; }
  .badge-none      { background:#30363d; color:#8b949e; }
  .badge-network   { background:#1f6feb; }
  .badge-identity  { background:#8957e5; }
  .badge-device    { background:#39d353; color:#1c1c1c; }
  .badge-suspicious{ background:#da3633; }
  .badge-clean     { background:#238636; }
  .status { padding:10px 14px; margin:10px 0; border-radius:6px; display:none; font-size:13px; }
  .status.show { display:block; }
  .status.success { background:#1a3a2a; color:#3fb950; border:1px solid #238636; }
  .status.error   { background:#3a1a1a; color:#f85149; border:1px solid #da3633; }
  .stat-row { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:18px; }
  .stat-box { background:#161b22; border:1px solid #21262d; border-radius:8px; padding:14px 20px; flex:1; min-width:110px; text-align:center; }
  .stat-box .num { font-size:28px; font-weight:700; color:#f0f6fc; }
  .stat-box .lbl { font-size:11px; color:#8b949e; text-transform:uppercase; letter-spacing:0.5px; margin-top:4px; }
  .ack-btn { padding:3px 9px; font-size:11px; background:#21262d; color:#c9d1d9; border:1px solid #30363d; border-radius:4px; cursor:pointer; margin-left:6px; }
  .ack-btn:hover { background:#30363d; }
  .alert-acked { opacity:0.35; }
  table { width:100%; border-collapse:collapse; font-size:12px; }
  th { background:#161b22; color:#8b949e; text-transform:uppercase; font-size:10px; letter-spacing:0.5px; padding:8px 10px; text-align:left; border-bottom:1px solid #21262d; }
  td { padding:7px 10px; border-bottom:1px solid #21262d; color:#c9d1d9; }
  tr:hover td { background:#161b22; }
  code { background:#21262d; padding:1px 5px; border-radius:4px; font-size:12px; color:#79c0ff; }
  a { color:#58a6ff; }
  .todo-card { border:2px dashed #30363d; padding:40px 30px; border-radius:12px; text-align:center; background:#161b22; margin-top:20px; }
  .todo-card h2 { color:#8b949e; margin:0 0 8px 0; }
  .todo-card p { color:#484f58; font-size:14px; margin:0; }
`;

const navBar = (active: string) => `<nav>
  <a href="/"                 ${active === "model"    ? 'class="active"' : ""}>Network Model</a>
  <a href="/identity-model"   ${active === "identity" ? 'class="active"' : ""}>Identity Model</a>
  <a href="/device-model"     ${active === "device"   ? 'class="active"' : ""}>Device Model</a>
  <a href="/alerts"           ${active === "alerts"   ? 'class="active"' : ""}>Alerts</a>
  <a href="/ingest"           ${active === "ingest"   ? 'class="active"' : ""}>Ingest</a>
</nav>`;

const statusScript = () => `
  <div id="status" class="status"></div>
  <script>
    function showStatus(msg, type) {
      const el = document.getElementById("status");
      el.textContent = msg;
      el.className = "status show " + type;
      setTimeout(() => { el.className = "status"; }, 3500);
    }
  </script>`;

// ===========================================================================
// Network Model Page (main page)
// ===========================================================================
app.get("/", (req, res) => {
  const scoresPath = path.join(__dirname, "data", "risk_scores", "network", "network_risk_scores.json");
  let results: any[] = [];
  if (fs.existsSync(scoresPath)) {
    try { results = JSON.parse(fs.readFileSync(scoresPath, "utf-8")); } catch {}
  }

  const fp = path.join(__dirname, "data", "synthetic_events", "synthetic_network_events.json");
  let rawEvents: NetworkEvent[] = [];
  if (fs.existsSync(fp)) rawEvents = readJson(fp);

  const total = results.length;
  const alertCount = results.filter((r: any) => r.alert).length;
  const criticalCount = results.filter((r: any) => r.risk_label === "CRITICAL").length;
  const highCount = results.filter((r: any) => r.risk_label === "HIGH").length;
  const avgScore = total > 0 ? (results.reduce((s: number, r: any) => s + r.risk_score, 0) / total).toFixed(1) : "---";

  const dbEvents = db.prepare("SELECT COUNT(*) as cnt FROM network_events").get() as any;
  const dbAlerts = db.prepare("SELECT COUNT(*) as cnt FROM alerts").get() as any;

  const rulesTable = `
    <table>
      <thead><tr><th>Rule</th><th>Name</th><th>Max</th><th>Description</th><th>Baseline</th></tr></thead>
      <tbody>
        <tr><td><strong>M01</strong></td><td>Excessive Outbound Traffic</td><td>+40</td><td>Bytes sent exceeds device baseline or absolute threshold (&gt;5MB = +40, &gt;1MB = +25)</td><td>14-day rolling</td></tr>
        <tr><td><strong>M02</strong></td><td>VPN / Proxy Destination</td><td>+25</td><td>Destination IP in known suspicious list (+15) or port in VPN/proxy list (+15)</td><td>---</td></tr>
        <tr><td><strong>M03</strong></td><td>Abnormal Connection Burst</td><td>+35</td><td>Unique destination IPs per source exceeds threshold (&gt;100 = +35, &gt;50 = +25)</td><td>14-day rolling</td></tr>
        <tr><td><strong>M04</strong></td><td>High-Risk Port Access</td><td>+30</td><td>Connection to high-risk ports (4444/1337/6667 = +30, 22/23/3389/5900 = +25)</td><td>14-day rolling</td></tr>
        <tr><td><strong>M05</strong></td><td>Suspicious Protocol</td><td>+20</td><td>RAW protocol = +20, ICMP = +10</td><td>---</td></tr>
        <tr><td><strong>M06</strong></td><td>Unknown Device</td><td>+15</td><td>Device ID not in user's known device list</td><td>---</td></tr>
        <tr><td><strong>M07</strong></td><td>C2 Beaconing Detection</td><td>+40</td><td>Low inter-arrival time variance for src/dst pair indicates periodic callbacks</td><td>Variance analysis</td></tr>
        <tr><td><strong>M08</strong></td><td>Threat Event Classification</td><td>+40</td><td>c2_beacon/malware = +40, data_exfil/brute_force/lateral_movement = +35, port_scan = +20</td><td>---</td></tr>
      </tbody>
    </table>`;

  const resultsRows = results.slice(-20).map((r: any) => {
    const lvl = r.risk_score >= 85 ? "critical" : r.risk_score >= 60 ? "high" : r.risk_score >= 35 ? "medium" : r.risk_score >= 15 ? "low" : "none";
    return `<tr>
      <td>${r.event_type ?? "---"}</td>
      <td>${r.source_ip ?? "---"}</td>
      <td>${r.destination_ip ?? "---"}</td>
      <td>${r.m01_score ?? 0}</td><td>${r.m02_score ?? 0}</td><td>${r.m03_score ?? 0}</td><td>${r.m04_score ?? 0}</td>
      <td>${r.m05_score ?? 0}</td><td>${r.m06_score ?? 0}</td><td>${r.m07_score ?? 0}</td><td>${r.m08_score ?? 0}</td>
      <td><strong><span class="badge badge-${lvl}">${r.risk_score}</span></strong></td>
      <td>${r.risk_label}</td>
      <td>${r.alert ? '<span style="color:#da3633">YES</span>' : '<span style="color:#8b949e">no</span>'}</td>
    </tr>`;
  }).join("");

  const sampleRows = rawEvents.slice(-20).map((e: any) => {
    const breakdown = scoreNetworkRules(e);
    const s = breakdown.composite;
    const lvl = s >= 85 ? "critical" : s >= 60 ? "high" : s >= 35 ? "medium" : s >= 15 ? "low" : "none";
    return `<tr>
      <td><code>${e.event_id?.slice(0,8)}...</code></td>
      <td>${e.user_id}</td>
      <td>${e.event_type}</td>
      <td>${e.source_ip}</td>
      <td>${e.destination_ip}:${e.destination_port}</td>
      <td>${e.protocol}</td>
      <td>${e.device_id}</td>
      <td>${(e.bytes_sent ?? 0).toLocaleString()}</td>
      <td><span class="badge badge-${lvl}">${s}</span></td>
    </tr>`;
  }).join("");

  res.send(`<!DOCTYPE html><html><head><title>PirateShield - Network Model</title><style>${sharedStyles}
    .model-header { background: linear-gradient(135deg, #161b22 0%, #0d1117 100%); border: 1px solid #21262d; border-radius: 12px; padding: 24px 28px; margin-bottom: 24px; }
    .model-header h2 { margin: 0 0 8px 0; font-size: 20px; }
    .model-header p { margin: 0; color: #8b949e; font-size: 13px; line-height: 1.6; }
    .formula-box { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 16px 20px; margin: 16px 0; font-family: 'Courier New', monospace; font-size: 13px; color: #79c0ff; line-height: 1.8; }
    .section { margin-top: 32px; }
    .section-title { font-size: 14px; text-transform: uppercase; letter-spacing: 1px; color: #8b949e; margin-bottom: 12px; border-bottom: 1px solid #21262d; padding-bottom: 6px; }
    table th { position: sticky; top: 0; }
    .run-output { background: #0d1117; border: 1px solid #21262d; border-radius: 8px; padding: 16px; margin-top: 12px; font-family: monospace; font-size: 12px; white-space: pre-wrap; max-height: 400px; overflow-y: auto; display: none; color: #c9d1d9; }
    .run-output.show { display: block; }
    #chart-container { margin-top:16px; text-align:center; }
    #chart-container img { max-width:100%; border-radius:8px; border:1px solid #21262d; }
  </style></head><body>
    <h1>PirateShield</h1>
    <p class="subtitle">Network Threat Detection for K-12 Environments</p>
    ${navBar("model")}${statusScript()}

    <div class="model-header">
      <h2>Network Anomaly Detection Model</h2>
      <p>Rule-based risk scoring engine implementing rules M01-M08. Produces composite risk scores on a 0-100 scale.
         Alerts are generated when composite score &gt;= 60 OR any single rule raw score &gt;= 80% of its maximum.
         The model supports batch analysis with 14-day rolling baselines and C2 beaconing detection via inter-arrival time variance.</p>
    </div>

    <div class="stat-row">
      <div class="stat-box"><div class="num">${rawEvents.length}</div><div class="lbl">Raw Events</div></div>
      <div class="stat-box"><div class="num">${total}</div><div class="lbl">Scored</div></div>
      <div class="stat-box"><div class="num">${avgScore}</div><div class="lbl">Avg Score</div></div>
      <div class="stat-box"><div class="num" style="color:#da3633">${criticalCount}</div><div class="lbl">Critical</div></div>
      <div class="stat-box"><div class="num" style="color:#f85149">${highCount}</div><div class="lbl">High</div></div>
      <div class="stat-box"><div class="num" style="color:#d29922">${alertCount}</div><div class="lbl">Alerts</div></div>
      <div class="stat-box"><div class="num">${dbEvents.cnt}</div><div class="lbl">DB Events</div></div>
      <div class="stat-box"><div class="num">${dbAlerts.cnt}</div><div class="lbl">DB Alerts</div></div>
    </div>

    <div class="section">
      <div class="section-title">Composite Formula</div>
      <div class="formula-box">
        composite = min(100, M01 + M02 + M03 + M04 + M05 + M06 + M07 + M08)<br><br>
        Alert Condition: composite &gt;= 60 OR any rule_raw &gt;= rule_max * 0.8<br><br>
        Severity:  NONE [0-14]  |  LOW [15-34]  |  MEDIUM [35-59]  |  HIGH [60-84]  |  CRITICAL [85-100]
      </div>
    </div>

    <div class="section">
      <div class="section-title">Rule Definitions (M01 - M08)</div>
      ${rulesTable}
    </div>

    <div class="section">
      <div class="section-title">Run Model</div>
      <div class="controls">
        <button class="btn-green" onclick="addNet()">Add 5 Network Events</button>
        <button class="btn-blue" id="run-btn" onclick="runModel()">Run Network Model</button>
        <button class="btn-gray" onclick="location.reload()">Refresh</button>
        <button class="btn-red" onclick="resetAll()">Reset All Network Data</button>
      </div>
      <div id="run-output" class="run-output"></div>
      <div id="chart-container"></div>
    </div>

    <div class="section">
      <div class="section-title">Sample Data (${rawEvents.length} events - last 20 shown)</div>
      ${rawEvents.length === 0
        ? '<p style="color:#8b949e">No events yet. Click "Add 5 Network Events" to generate sample data for testing.</p>'
        : `<div style="overflow-x:auto">
          <table>
            <thead><tr>
              <th>Event ID</th><th>User</th><th>Event Type</th><th>Src IP</th>
              <th>Dst IP:Port</th><th>Protocol</th><th>Device</th><th>Bytes Sent</th><th>RT Score</th>
            </tr></thead>
            <tbody>${sampleRows}</tbody>
          </table>
        </div>`}
    </div>

    <div class="section">
      <div class="section-title">Scored Results (${total} events - last 20 shown)</div>
      ${total === 0
        ? '<p style="color:#8b949e">No results yet. Click "Run Network Model" to score current network events.</p>'
        : `<div style="overflow-x:auto">
          <table>
            <thead><tr>
              <th>Event Type</th><th>Src IP</th><th>Dst IP</th>
              <th>M01</th><th>M02</th><th>M03</th><th>M04</th><th>M05</th><th>M06</th><th>M07</th><th>M08</th>
              <th>Score</th><th>Severity</th><th>Alert</th>
            </tr></thead>
            <tbody>${resultsRows}</tbody>
          </table>
        </div>`}
    </div>

    <script>
      async function addNet() {
        const btn = event.target; btn.disabled = true; btn.textContent = "Generating...";
        const r = await fetch("/api/add", { method:"POST" });
        const d = await r.json();
        if (d.success) {
          showStatus("Added 5 network events", "success");
          if (d.chart) {
            document.getElementById("chart-container").innerHTML = '<img src="data:image/png;base64,' + d.chart + '" alt="Event Distribution Chart"/>';
          }
          setTimeout(() => location.reload(), 1200);
        }
        else { showStatus("Failed: " + d.message, "error"); btn.disabled = false; btn.textContent = "Add 5 Network Events"; }
      }
      async function resetAll() {
        if (!confirm("Delete all network data (events, scores, alerts)? This cannot be undone.")) return;
        const r = await fetch("/api/reset", { method:"POST" });
        const d = await r.json();
        if (d.success) { showStatus("All network data cleared", "success"); setTimeout(() => location.reload(), 900); }
      }
      async function runModel() {
        const btn = document.getElementById("run-btn");
        btn.disabled = true; btn.textContent = "Running...";
        const out = document.getElementById("run-output");
        out.className = "run-output show";
        out.textContent = "Executing network model (network_model.py)...\\n";
        try {
          const r = await fetch("/api/run-network-model", { method: "POST" });
          const d = await r.json();
          if (d.success) {
            out.textContent += d.output || ("Scored " + d.count + " events. " + d.alerts + " alerts generated.\\n");
            showStatus("Model run complete", "success");
            setTimeout(() => location.reload(), 2000);
          } else {
            out.textContent += "ERROR: " + (d.message || "Unknown error") + "\\n";
            showStatus("Model run failed", "error");
          }
        } catch(err) {
          out.textContent += "ERROR: " + err.message + "\\n";
          showStatus("Model run failed", "error");
        }
        btn.disabled = false; btn.textContent = "Run Network Model";
      }
    </script>
  </body></html>`);
});

// ===========================================================================
// Identity Model Page
// ===========================================================================
app.get("/identity-model", (req, res) => {
  res.send(`<!DOCTYPE html><html><head><title>PirateShield - Identity Model</title><style>${sharedStyles}
    .todo-container { background: linear-gradient(135deg, #161b22 0%, #0d1117 100%); border: 1px solid #21262d; border-radius: 12px; padding: 40px; margin-top: 24px; text-align: center; }
    .todo-container h2 { margin: 0 0 16px 0; font-size: 22px; color: #a371f7; }
    .todo-container p { color: #8b949e; font-size: 14px; line-height: 1.8; max-width: 600px; margin: 0 auto; }
    .todo-list { text-align: left; max-width: 500px; margin: 24px auto 0; }
    .todo-list li { color: #c9d1d9; font-size: 13px; margin-bottom: 10px; line-height: 1.5; }
    .todo-list li span { color: #8b949e; }
  </style></head><body>
    <h1>PirateShield</h1>
    <p class="subtitle">Network Threat Detection for K-12 Environments</p>
    ${navBar("identity")}

    <div class="todo-container">
      <h2>Identity &amp; User Behavior Model</h2>
      <p>This section is under construction. The identity model will detect authentication and user behavior anomalies.</p>
      <ul class="todo-list">
        <li>Build identity event ingestion pipeline <span>- accept login, authentication, and session events</span></li>
        <li>Implement risk scoring rules <span>- failed logins, brute force, new devices, impossible travel</span></li>
        <li>Create identity event dashboard <span>- table view with login stats and suspicious flags</span></li>
        <li>Generate synthetic identity events <span>- Python script to simulate realistic login patterns</span></li>
        <li>Integrate with unified alerts system <span>- fire alerts when identity risk score exceeds threshold</span></li>
      </ul>
    </div>
  </body></html>`);
});

// ===========================================================================
// Device Model Page
// ===========================================================================
app.get("/device-model", (req, res) => {
  res.send(`<!DOCTYPE html><html><head><title>PirateShield - Device Model</title><style>${sharedStyles}
    .todo-container { background: linear-gradient(135deg, #161b22 0%, #0d1117 100%); border: 1px solid #21262d; border-radius: 12px; padding: 40px; margin-top: 24px; text-align: center; }
    .todo-container h2 { margin: 0 0 16px 0; font-size: 22px; color: #39d353; }
    .todo-container p { color: #8b949e; font-size: 14px; line-height: 1.8; max-width: 600px; margin: 0 auto; }
    .todo-list { text-align: left; max-width: 500px; margin: 24px auto 0; }
    .todo-list li { color: #c9d1d9; font-size: 13px; margin-bottom: 10px; line-height: 1.5; }
    .todo-list li span { color: #8b949e; }
  </style></head><body>
    <h1>PirateShield</h1>
    <p class="subtitle">Network Threat Detection for K-12 Environments</p>
    ${navBar("device")}

    <div class="todo-container">
      <h2>Device Anomaly Detection Model</h2>
      <p>This section is under construction. The device model will detect endpoint-level threats on student and staff devices.</p>
      <ul class="todo-list">
        <li>Build device event ingestion pipeline <span>- accept process, CPU, USB, and security change events</span></li>
        <li>Implement risk scoring rules <span>- suspicious processes, CPU spikes, USB executables, disabled security</span></li>
        <li>Create device event dashboard <span>- table view with filtering and stats</span></li>
        <li>Generate synthetic device events <span>- Python script to simulate realistic endpoint activity</span></li>
        <li>Integrate with unified alerts system <span>- fire alerts when device risk score exceeds threshold</span></li>
      </ul>
    </div>
  </body></html>`);
});

// ===========================================================================
// Alerts Page
// ===========================================================================
app.get("/alerts", (req, res) => {
  const alerts = db.prepare("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 200").all() as any[];
  const counts = { critical:0, high:0, medium:0, low:0, unacked:0 };
  for (const a of alerts) {
    if (a.severity in counts) counts[a.severity as keyof typeof counts]++;
    if (!a.acknowledged) counts.unacked++;
  }

  res.send(`<!DOCTYPE html><html><head><title>PirateShield - Alerts</title><style>${sharedStyles}</style></head><body>
    <h1>PirateShield</h1>
    <p class="subtitle">Network Threat Detection for K-12 Environments</p>
    ${navBar("alerts")}${statusScript()}
    <div class="controls">
      <button class="btn-green" onclick="ackAll()">Acknowledge All</button>
      <button class="btn-gray"   onclick="location.reload()">Refresh</button>
    </div>
    <div class="stat-row">
      <div class="stat-box"><div class="num">${alerts.length}</div><div class="lbl">Total Alerts</div></div>
      <div class="stat-box"><div class="num">${counts.unacked}</div><div class="lbl">Unacknowledged</div></div>
      <div class="stat-box"><div class="num" style="color:#da3633">${counts.critical}</div><div class="lbl">Critical</div></div>
      <div class="stat-box"><div class="num" style="color:#f85149">${counts.high}</div><div class="lbl">High</div></div>
      <div class="stat-box"><div class="num" style="color:#d29922">${counts.medium}</div><div class="lbl">Medium</div></div>
      <div class="stat-box"><div class="num" style="color:#3fb950">${counts.low}</div><div class="lbl">Low</div></div>
    </div>

    ${alerts.length === 0
      ? '<p style="color:#8b949e">No alerts yet. Add network events or use the Ingest page to generate alerts.</p>'
      : `<div style="overflow-x:auto">
        <table>
          <thead><tr><th>ID</th><th>Severity</th><th>User</th><th>Device</th><th>Score</th><th>Reason</th><th>Event ID</th><th>Time</th><th>Status</th></tr></thead>
          <tbody>${alerts.map((a: any) => {
            const lvl = a.severity;
            return `<tr class="${a.acknowledged ? "alert-acked" : ""}">
              <td>${a.id}</td>
              <td><span class="badge badge-${lvl}">${lvl.toUpperCase()}</span></td>
              <td>${a.user_id ?? "---"}</td>
              <td>${a.device_id ?? "---"}</td>
              <td><strong>${a.risk_score}</strong></td>
              <td style="max-width:350px;word-wrap:break-word">${a.reason}</td>
              <td><code>${a.event_id ? a.event_id.slice(0,8) + "..." : "---"}</code></td>
              <td style="white-space:nowrap">${a.created_at}</td>
              <td>${!a.acknowledged
                ? '<button class="ack-btn" onclick="ack(' + a.id + ')">Ack</button>'
                : '<span style="color:#8b949e;font-size:11px">Acked</span>'}</td>
            </tr>`;
          }).join("")}</tbody>
        </table>
      </div>`}

    <script>
      async function ack(id) {
        await fetch("/api/alerts/"+id+"/ack",{method:"POST"});
        showStatus("Acknowledged","success");
        setTimeout(()=>location.reload(),700);
      }
      async function ackAll() {
        await fetch("/api/alerts/ack-all",{method:"POST"});
        showStatus("All acknowledged","success");
        setTimeout(()=>location.reload(),700);
      }
    </script>
  </body></html>`);
});

// ===========================================================================
// Ingest page
// ===========================================================================
app.get("/ingest", (req, res) => {
  res.send(`<!DOCTYPE html><html><head><title>PirateShield - Ingest</title><style>${sharedStyles}
    .fg{display:flex;flex-direction:column;gap:4px}
    .fgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px 20px}
    label{font-size:10px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.5px}
    input,select{padding:7px 10px;border:1px solid #30363d;border-radius:6px;font-size:13px;width:100%;box-sizing:border-box;background:#0d1117;color:#c9d1d9}
    input:focus,select:focus{outline:none;border-color:#1f6feb;box-shadow:0 0 0 2px rgba(31,111,235,.2)}
    .rbox{margin-top:12px;padding:11px 14px;border-radius:6px;font-size:13px;display:none}
    .rbox.show{display:block} .rbox.ok{background:#1a3a2a;color:#3fb950;border:1px solid #238636}
    .rbox.err{background:#3a1a1a;color:#f85149;border:1px solid #da3633}
    .score-slider{display:flex;align-items:center;gap:12px}
    .score-slider input[type=range]{flex:1}
    .score-val{font-size:28px;font-weight:700;color:#f0f6fc;min-width:50px;text-align:center}
    .tabs{display:flex;gap:0;margin-bottom:20px;border-bottom:2px solid #30363d}
    .tab{padding:10px 24px;cursor:pointer;font-size:14px;font-weight:600;color:#8b949e;border:none;background:none;border-bottom:2px solid transparent;margin-bottom:-2px;transition:color .15s,border-color .15s}
    .tab:hover{color:#c9d1d9}
    .tab.active{color:#58a6ff;border-bottom-color:#58a6ff}
    .tab-content{display:none}
    .tab-content.active{display:block}
    .todo-box{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:40px;max-width:500px;text-align:center}
    .todo-box h3{color:#8b949e;font-size:18px;margin:0 0 8px 0}
    .todo-box p{color:#484f58;font-size:14px;margin:0}
  </style></head><body>
    <h1>PirateShield</h1>
    <p class="subtitle">Network Threat Detection for K-12 Environments</p>
    ${navBar("ingest")}
    <h2 style="margin-bottom:4px">Manual Event Ingest</h2>
    <p style="color:#8b949e;font-size:13px;margin-top:0;margin-bottom:18px">
      Select an event type and set a risk score (0-100). The event is ingested through the model system, written to DB and scored results.
    </p>

    <div class="tabs">
      <button class="tab active" onclick="switchTab('network')">Network</button>
      <button class="tab" onclick="switchTab('identity')">Identity</button>
      <button class="tab" onclick="switchTab('device')">Device</button>
    </div>

    <div id="tab-network" class="tab-content active">
      <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:26px;max-width:500px">
        <div class="fgrid">
          <div class="fg" style="grid-column:1/-1">
            <label>Event Type</label>
            <select id="n-etype">
              <option value="network_connection">network_connection</option>
              <option value="dns_lookup">dns_lookup</option>
              <option value="file_transfer">file_transfer</option>
              <option value="vpn_connection">vpn_connection</option>
              <option value="unusual_login">unusual_login</option>
              <option value="port_scan">port_scan</option>
              <option value="brute_force">brute_force</option>
              <option value="data_exfil">data_exfil</option>
              <option value="malware">malware</option>
              <option value="lateral_movement">lateral_movement</option>
              <option value="c2_beacon">c2_beacon</option>
            </select>
          </div>
          <div class="fg" style="grid-column:1/-1">
            <label>Risk Score</label>
            <div class="score-slider">
              <input type="range" id="n-score" min="0" max="100" value="50" oninput="document.getElementById('score-display').textContent=this.value"/>
              <span id="score-display" class="score-val">50</span>
            </div>
          </div>
        </div>
        <div style="margin-top:16px"><button class="btn-blue" onclick="submitNetwork()">Submit Event</button></div>
        <div id="n-result" class="rbox"></div>
      </div>
    </div>

    <div id="tab-identity" class="tab-content">
      <div class="todo-box">
        <h3>Identity Ingest</h3>
        <p>TODO</p>
      </div>
    </div>

    <div id="tab-device" class="tab-content">
      <div class="todo-box">
        <h3>Device Ingest</h3>
        <p>TODO</p>
      </div>
    </div>

    <script>
      function switchTab(name){
        document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
        document.getElementById('tab-'+name).classList.add('active');
        document.querySelector('.tab[onclick="switchTab(\\''+name+'\\')"]').classList.add('active');
      }

      function res(id,msg,ok){const el=document.getElementById(id);el.textContent=msg;el.className='rbox show '+(ok?'ok':'err');}

      async function submitNetwork(){
        const payload={
          event_type: document.getElementById('n-etype').value,
          risk_score: parseInt(document.getElementById('n-score').value)
        };
        try{
          const r=await fetch('/ingest',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
          const d=await r.json();
          if(r.ok){res('n-result','Score: '+d.risk_score+' | Rules: M01='+d.rules.m01+' M02='+d.rules.m02+' M03='+d.rules.m03+' M04='+d.rules.m04+' M05='+d.rules.m05+' M06='+d.rules.m06+' M07='+d.rules.m07+' M08='+d.rules.m08+' | Saved. Redirecting...', true);
            setTimeout(()=>window.location.href='/',1500);
          } else{res('n-result','Error: '+(d.error||JSON.stringify(d)),false);}
        }catch(e){res('n-result','Error: '+e.message,false);}
      }
    </script>
  </body></html>`);
});

// ===========================================================================
// API endpoints
// ===========================================================================
app.post("/ingest", (req, res) => {
  const body = req.body;
  if (!body || typeof body !== "object") return res.status(400).json({ error: "Invalid payload" });

  const eventType = body.event_type;
  const userScore = typeof body.risk_score === "number" ? Math.max(0, Math.min(100, body.risk_score)) : null;

  const scriptPath = path.join(__dirname, "scripts", "network_model", "generate_network_events.py");
  const python = spawn(PYTHON, [scriptPath, "--count", "1", "--event-type", eventType], { cwd: __dirname });
  let stdout = "";
  let stderr = "";
  python.stdout.on("data", (d: Buffer) => { stdout += d.toString(); });
  python.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });
  python.on("close", (code) => {
    if (code !== 0) return res.status(500).json({ error: stderr || "Python script failed" });
    const fp = path.join(__dirname, "data", "synthetic_events", "synthetic_network_events.json");
    try {
      const all: NetworkEvent[] = JSON.parse(fs.readFileSync(fp, "utf-8"));
      const event = all[all.length - 1];

      const breakdown = scoreNetworkRules(event);
      const risk_score = userScore !== null ? userScore : breakdown.composite;

      // When user manually sets a score, zero out all rule metrics and only set m08
      if (userScore !== null) {
        breakdown.m01 = 0;
        breakdown.m02 = 0;
        breakdown.m03 = 0;
        breakdown.m04 = 0;
        breakdown.m05 = 0;
        breakdown.m06 = 0;
        breakdown.m07 = 0;
        breakdown.m08 = userScore;
        breakdown.composite = userScore;
        breakdown.reasons = [`M08: Manual score ${userScore}`];
      }

      db.prepare(`
        INSERT OR IGNORE INTO network_events
          (event_id,user_id,timestamp,source_ip,destination_ip,destination_port,
           protocol,bytes_sent,bytes_received,device_id,event_type,payload,risk_score)
        VALUES
          (@event_id,@user_id,@timestamp,@source_ip,@destination_ip,@destination_port,
           @protocol,@bytes_sent,@bytes_received,@device_id,@event_type,@payload,@risk_score)
      `).run({
        ...event,
        payload: JSON.stringify({ ...event, rules: { m01: breakdown.m01, m02: breakdown.m02, m03: breakdown.m03, m04: breakdown.m04, m05: breakdown.m05, m06: breakdown.m06, m07: breakdown.m07, m08: breakdown.m08 } }),
        risk_score,
      });

      insertUnifiedEvent({ ...(event as any), event_category: "network" }, risk_score, breakdown);

      const scoresPath = path.join(__dirname, "data", "risk_scores", "network", "network_risk_scores.json");
      const existingScores = readJson(scoresPath);
      const riskLabel = risk_score >= 85 ? "CRITICAL" : risk_score >= 60 ? "HIGH" : risk_score >= 35 ? "MEDIUM" : risk_score >= 15 ? "LOW" : "NONE";
      existingScores.push({
        event_id: event.event_id,
        event_type: event.event_type,
        source_ip: event.source_ip,
        destination_ip: event.destination_ip,
        m01_score: breakdown.m01,
        m02_score: breakdown.m02,
        m03_score: breakdown.m03,
        m04_score: breakdown.m04,
        m05_score: breakdown.m05,
        m06_score: breakdown.m06,
        m07_score: breakdown.m07,
        m08_score: breakdown.m08,
        risk_score,
        risk_label: riskLabel,
        alert: risk_score >= 60,
      });
      writeJson(scoresPath, existingScores);

      res.status(201).json({ message: "Event ingested", risk_score, rules: { m01: breakdown.m01, m02: breakdown.m02, m03: breakdown.m03, m04: breakdown.m04, m05: breakdown.m05, m06: breakdown.m06, m07: breakdown.m07, m08: breakdown.m08 } });
    } catch (err) {
      console.error("Error ingesting event:", err);
      res.status(500).json({ error: "Failed to ingest event" });
    }
  });
  python.on("error", (err) => res.status(500).json({ error: (err as Error).message }));
});

app.post("/ingest-unified", (req, res) => {
  const event: Partial<UnifiedEvent> = req.body;
  if (!event || !event.event_category) return res.status(400).json({ error: "event_category required" });

  const { score: risk_score } = calculateUnifiedRisk(event);

  if (event.event_category === "identity") {
    ingestIdentityEvent({ ...event, risk_score });
  } else if (event.event_category === "device") {
    ingestDeviceEvent({ ...event, risk_score });
  } else {
    const fp = path.join(__dirname, "data", "synthetic_events", "synthetic_network_events.json");
    const existing = readJson(fp);
    if (!existing.some((x: any) => x.event_id === event.event_id)) writeJson(fp, [...existing, event]);
    const breakdown = scoreNetworkRules(event as Partial<NetworkEvent>);
    insertUnifiedEvent({ ...event, event_category: "network" }, breakdown.composite, breakdown);
  }

  res.status(201).json({ message: "Unified event ingested", risk_score });
});

// --- Run network model ---
app.post("/api/run-network-model", (req, res) => {
  const writeDb = req.query.db === "1";
  const args = [
    path.join(__dirname, "scripts", "network_model", "network_model.py"),
    "--json",
  ];
  if (writeDb) args.push("--db");

  const python = spawn(PYTHON, args, { cwd: __dirname });
  let stdout = "";
  let stderr = "";
  python.stdout.on("data", (d: Buffer) => { stdout += d.toString(); });
  python.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });
  python.on("close", (code) => {
    if (code !== 0) {
      return res.status(500).json({ success: false, message: stderr || "Model execution failed" });
    }
    try {
      const results = JSON.parse(stdout);
      const outPath = path.join(__dirname, "data", "risk_scores", "network", "network_risk_scores.json");
      fs.mkdirSync(path.dirname(outPath), { recursive: true });
      fs.writeFileSync(outPath, JSON.stringify(results, null, 2));

      const alertCount = results.filter((r: any) => r.alert).length;
      res.json({
        success: true,
        count: results.length,
        alerts: alertCount,
        output: `Scored ${results.length} events. ${alertCount} alerts generated.`,
      });
    } catch {
      res.json({ success: true, output: stdout, count: 0, alerts: 0 });
    }
  });
  python.on("error", (err: Error) => res.status(500).json({ success: false, message: err.message }));
});

// --- Risk by entity ---
app.get("/api/risk/:entity", (req, res) => {
  const entity = req.params.entity;

  const networkEvents = db.prepare(
    "SELECT * FROM network_events WHERE user_id = ? OR device_id = ? OR source_ip = ? ORDER BY created_at DESC LIMIT 50"
  ).all(entity, entity, entity) as any[];

  const unifiedEvents = db.prepare(
    "SELECT * FROM unified_events WHERE user_id = ? OR device_id = ? ORDER BY created_at DESC LIMIT 50"
  ).all(entity, entity) as any[];

  const alerts = db.prepare(
    "SELECT * FROM alerts WHERE user_id = ? OR device_id = ? ORDER BY created_at DESC LIMIT 50"
  ).all(entity, entity) as any[];

  const scores = networkEvents.map((e: any) => e.risk_score).filter((s: any) => s != null);
  const avgScore = scores.length > 0 ? Math.round(scores.reduce((a: number, b: number) => a + b, 0) / scores.length) : 0;
  const maxScore = scores.length > 0 ? Math.max(...scores) : 0;

  res.json({
    entity,
    summary: {
      total_events: networkEvents.length + unifiedEvents.length,
      network_events: networkEvents.length,
      unified_events: unifiedEvents.length,
      alerts: alerts.length,
      avg_risk_score: avgScore,
      max_risk_score: maxScore,
      severity: maxScore >= 85 ? "critical" : maxScore >= 60 ? "high" : maxScore >= 35 ? "medium" : maxScore >= 15 ? "low" : "none",
    },
    network_events: networkEvents,
    alerts,
  });
});

// --- GET /api/alerts (JSON) ---
app.get("/api/alerts", (req, res) => res.json(db.prepare("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 200").all()));

// --- Other API endpoints ---
app.post("/api/add", (req, res) => {
  const scriptPath = path.join(__dirname, "scripts", "network_model", "generate_network_events.py");
  const python = spawn(PYTHON, [scriptPath, "--chart"], { cwd: __dirname });
  let stdout = "";
  let stderr = "";
  python.stdout.on("data", (d: Buffer) => { stdout += d.toString(); });
  python.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });
  python.on("close", (code) => {
    if (code !== 0) return res.status(500).json({ success:false, message: stderr || "Python script failed" });
    const fp = path.join(__dirname, "data", "synthetic_events", "synthetic_network_events.json");
    try {
      const all: NetworkEvent[] = JSON.parse(fs.readFileSync(fp, "utf-8"));
      const newest = all.slice(-5);
      const stmt = db.prepare(`
        INSERT INTO network_events
          (event_id,user_id,timestamp,source_ip,destination_ip,destination_port,
           protocol,bytes_sent,bytes_received,device_id,event_type,payload,risk_score)
        VALUES
          (@event_id,@user_id,@timestamp,@source_ip,@destination_ip,@destination_port,
           @protocol,@bytes_sent,@bytes_received,@device_id,@event_type,@payload,@risk_score)
      `);
      for (const e of newest) {
        const breakdown = scoreNetworkRules(e);
        const risk_score = breakdown.composite;
        stmt.run({ ...e, payload:JSON.stringify(e), risk_score });
        insertUnifiedEvent({ ...(e as any), event_category:"network" }, risk_score, breakdown);
      }

      let chart: string | null = null;
      const chartMatch = stdout.match(/CHART_BASE64:(.+)/);
      if (chartMatch) chart = chartMatch[1].trim();

      res.json({ success:true, message:"Events generated and ingested", chart });
    } catch { res.status(500).json({ success:false, message:"Failed to ingest" }); }
  });
  python.on("error", (err) => res.status(500).json({ success:false, message:(err as Error).message }));
});

app.post("/api/reset", (req, res) => {
  const fp = path.join(__dirname, "data", "synthetic_events", "synthetic_network_events.json");
  const scoresPath = path.join(__dirname, "data", "risk_scores", "network", "network_risk_scores.json");
  try {
    fs.writeFileSync(fp, JSON.stringify([], null, 2));
    if (fs.existsSync(scoresPath)) fs.writeFileSync(scoresPath, JSON.stringify([], null, 2));
    db.prepare("DELETE FROM alerts WHERE event_id IN (SELECT event_id FROM network_events)").run();
    db.prepare("DELETE FROM network_events").run();
    db.prepare("DELETE FROM unified_events WHERE event_category = 'network'").run();
    try { db.prepare("DELETE FROM sqlite_sequence WHERE name IN ('network_events','alerts','unified_events')").run(); } catch {}
    res.json({ success:true });
  } catch { res.status(500).json({ success:false, message:"Reset failed" }); }
});

app.post("/api/alerts/:id/ack", (req, res) => {
  db.prepare("UPDATE alerts SET acknowledged = 1 WHERE id = ?").run(req.params.id);
  res.json({ success:true });
});

app.post("/api/alerts/ack-all", (req, res) => {
  db.prepare("UPDATE alerts SET acknowledged = 1").run();
  res.json({ success:true });
});

app.get("/api/db-events",    (req, res) => res.json(db.prepare("SELECT * FROM network_events ORDER BY created_at DESC LIMIT 100").all()));
app.get("/api/device-events",(req, res) => res.json(db.prepare("SELECT * FROM device_events  ORDER BY created_at DESC LIMIT 200").all()));
app.get("/api/unified",      (req, res) => res.json(db.prepare("SELECT * FROM unified_events ORDER BY created_at DESC LIMIT 200").all()));

app.post("/api/add-device", (req, res) => {
  const scriptPath = path.join(__dirname, "scripts", "device_model", "generate_device_events.py");
  const python = spawn(PYTHON, [scriptPath, "5"], { cwd: __dirname });
  python.on("close", (code) => {
    if (code !== 0) return res.status(500).json({ success: false, message: "Script failed" });
    try {
      const all = readJson(path.join(__dirname, "data", "synthetic_events", "synthetic_device_events.json"));
      for (const e of all.slice(-5)) ingestDeviceEvent(e);
      res.json({ success: true });
    } catch { res.status(500).json({ success: false, message: "Failed to ingest" }); }
  });
  python.on("error", (err: Error) => res.status(500).json({ success: false, message: err.message }));
});

app.post("/api/reset-device", (req, res) => {
  try {
    fs.writeFileSync(path.join(__dirname, "data", "synthetic_events", "synthetic_device_events.json"), "[]", { encoding: "utf8" });
    db.prepare("DELETE FROM alerts WHERE event_id IN (SELECT event_id FROM device_events)").run();
    db.prepare("DELETE FROM device_events").run();
    db.prepare("DELETE FROM unified_events WHERE event_category = 'device'").run();
    try { db.prepare("DELETE FROM sqlite_sequence WHERE name IN ('device_events','unified_events')").run(); } catch {}
    res.json({ success: true });
  } catch { res.status(500).json({ success: false, message: "Reset failed" }); }
});

app.post("/api/reset-identity", (req, res) => {
  try {
    fs.writeFileSync(path.join(__dirname, "data", "synthetic_events", "synthetic_identity_events.json"), "[]", { encoding: "utf8" });
    db.prepare("DELETE FROM alerts WHERE event_id IN (SELECT event_id FROM identity_events)").run();
    db.prepare("DELETE FROM identity_events").run();
    db.prepare("DELETE FROM unified_events WHERE event_category = 'identity'").run();
    try { db.prepare("DELETE FROM sqlite_sequence WHERE name IN ('identity_events','unified_events')").run(); } catch {}
    res.json({ success: true });
  } catch { res.status(500).json({ success: false, message: "Reset failed" }); }
});

app.listen(PORT, () => {
  console.log(`PirateShield running at http://localhost:${PORT}`);
  console.log(`  Network Model:    http://localhost:${PORT}/`);
  console.log(`  Identity Model:   http://localhost:${PORT}/identity-model`);
  console.log(`  Device Model:     http://localhost:${PORT}/device-model`);
  console.log(`  Alerts:           http://localhost:${PORT}/alerts`);
  console.log(`  Ingest:           http://localhost:${PORT}/ingest`);
  console.log(`  APIs:`);
  console.log(`    GET  /api/alerts`);
  console.log(`    GET  /api/risk/:entity`);
  console.log(`    POST /api/run-network-model`);
  console.log(`    POST /api/add`);
  console.log(`    POST /api/reset`);
  console.log(`    POST /ingest`);
  console.log(`  Python: ${PYTHON}`);
});