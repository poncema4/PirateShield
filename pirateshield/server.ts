import express from "express";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { spawn } from "child_process";
import db from "./db.ts";
import {
  calculateRiskScore,
  calculateUnifiedRisk,
  scoreDeviceEvent,
  getAlertSeverity,
  type UnifiedEvent,
  type DeviceEvent,
} from "./risk_scoring.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app  = express();
const PORT = 3000;

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

function maybeCreateAlert(event: Partial<UnifiedEvent | DeviceEvent>, risk_score: number) {
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

function insertUnifiedEvent(event: Partial<UnifiedEvent>, risk_score: number) {
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
  maybeCreateAlert(event, risk_score);
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
  const fp = path.join(__dirname, "data", "synthetic_device_events.json");
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
  const fp = path.join(__dirname, "data", "synthetic_identity_events.json");
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
  body { font-family: Arial, sans-serif; max-width: 1100px; margin: 40px auto; padding: 20px; background: #f8f9fa; }
  nav { display: flex; gap: 10px; margin-bottom: 26px; flex-wrap: wrap; }
  nav a { padding: 8px 16px; border-radius: 6px; text-decoration: none; background: #007bff; color: white; font-size: 14px; }
  nav a:hover { background: #0056b3; }
  nav a.active { background: #343a40; }
  h1 { margin-bottom: 6px; }
  .controls { margin: 14px 0; display: flex; gap: 10px; flex-wrap: wrap; }
  button { padding: 8px 16px; font-size: 14px; cursor: pointer; border: none; border-radius: 5px; color: white; }
  .btn-green  { background: #28a745; } .btn-green:hover  { background: #218838; }
  .btn-blue   { background: #007bff; } .btn-blue:hover   { background: #0056b3; }
  .btn-red    { background: #dc3545; } .btn-red:hover    { background: #c82333; }
  .btn-orange { background: #fd7e14; } .btn-orange:hover { background: #e8680d; }
  .btn-purple { background: #6610f2; } .btn-purple:hover { background: #520dc2; }
  button:disabled { opacity: 0.55; cursor: not-allowed; }
  .card { border: 1px solid #ddd; padding: 13px 16px; margin: 8px 0; border-radius: 6px; background: white; font-size: 13px; }
  .risk-critical { border-left: 5px solid #6f0000; }
  .risk-high     { border-left: 5px solid #dc3545; }
  .risk-medium   { border-left: 5px solid #ffc107; }
  .risk-low      { border-left: 5px solid #28a745; }
  .risk-none     { border-left: 5px solid #ced4da; }
  .badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:bold; color:white; margin-left:5px; }
  .badge-critical  { background:#6f0000; }
  .badge-high      { background:#dc3545; }
  .badge-medium    { background:#ffc107; color:#333; }
  .badge-low       { background:#28a745; }
  .badge-none      { background:#adb5bd; color:#333; }
  .badge-network   { background:#007bff; }
  .badge-identity  { background:#6610f2; }
  .badge-device    { background:#17a2b8; }
  .badge-suspicious{ background:#dc3545; }
  .badge-clean     { background:#28a745; }
  .status { padding:10px; margin:10px 0; border-radius:5px; display:none; }
  .status.show { display:block; }
  .status.success { background:#d4edda; color:#155724; }
  .status.error   { background:#f8d7da; color:#721c24; }
  .stat-row { display:flex; gap:14px; flex-wrap:wrap; margin-bottom:18px; }
  .stat-box { background:white; border:1px solid #ddd; border-radius:8px; padding:12px 20px; flex:1; min-width:120px; text-align:center; }
  .stat-box .num { font-size:26px; font-weight:bold; }
  .stat-box .lbl { font-size:12px; color:#666; }
  .ack-btn { padding:3px 9px; font-size:11px; background:#6c757d; color:white; border:none; border-radius:4px; cursor:pointer; margin-left:6px; }
  .ack-btn:hover { background:#545b62; }
  .alert-acked { opacity:0.42; }
`;

const navBar = (active: string) => `<nav>
  <a href="/"            ${active === "net"      ? 'class="active"' : ""}>Network Events</a>
  <a href="/devices"     ${active === "dev"      ? 'class="active"' : ""}>Device Events</a>
  <a href="/unified"     ${active === "unified"  ? 'class="active"' : ""}>Unified Stream</a>
  <a href="/alerts"      ${active === "alerts"   ? 'class="active"' : ""}>Alerts</a>
  <a href="/ingest"   ${active === "ingest"   ? 'class="active"' : ""}>Ingest</a>
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

function riskCard(score: number, catBadge: string, main: string, sub: string) {
  const lvl = score >= 85 ? "critical" : score >= 60 ? "high" : score >= 35 ? "medium" : score >= 15 ? "low" : "none";
  return `<div class="card risk-${lvl}">
    <span class="badge badge-${lvl}">Risk: ${score}</span>
    <span class="badge badge-${catBadge}">${catBadge}</span>
    ${main}<br><span style="color:#666">${sub}</span>
  </div>`;
}

app.get("/", (req, res) => {
  const fp = path.join(__dirname, "data", "synthetic_network_events.json");
  let events: NetworkEvent[] = [];
  if (fs.existsSync(fp)) events = readJson(fp);

  res.send(`<!DOCTYPE html><html><head><title>PirateShield</title><style>${sharedStyles}</style></head><body>
    <h1>PirateShield</h1>${navBar("net")}${statusScript()}
    <div class="controls">
      <button class="btn-green" onclick="addNet()">Add 5 Network Events</button>
      <button class="btn-orange"  onclick="location.reload()">Refresh</button>
      <button class="btn-red"   onclick="resetAll()">Reset All Data</button>
    </div>
    <p><strong>Total Network Events:</strong> ${events.length}</p>
    ${events.length === 0
      ? `<p style="color:#999">No events yet. Click "Add 5 Network Events" to generate data.</p>`
      : events.map(e => {
          const s = calculateRiskScore(e);
          const lvl = s >= 60 ? "high" : s >= 30 ? "medium" : "none";
          return `<div class="card risk-${lvl}">
            <span class="badge badge-${s >= 60 ? "high" : s >= 30 ? "medium" : "none"}">Risk: ${s}</span>
            <span class="badge badge-network">network</span>
            <strong> ${e.user_id}</strong> | <code>${e.event_id}</code> &mdash; ${e.timestamp}<br>
            <span style="color:#666">${e.source_ip} &rarr; ${e.destination_ip}:${e.destination_port} (${e.protocol}) &nbsp;|&nbsp;
            Device: <strong>${e.device_id}</strong> &nbsp;|&nbsp;
            Sent: ${e.bytes_sent.toLocaleString()} B &nbsp;|&nbsp; Rcvd: ${e.bytes_received.toLocaleString()} B</span>
          </div>`;
        }).join("")}
    <script>
      async function addNet() {
        const btn = event.target; btn.disabled = true; btn.textContent = "Generating...";
        const r = await fetch("/api/add", { method:"POST" });
        const d = await r.json();
        if (d.success) { showStatus("Added 5 network events!", "success"); setTimeout(() => location.reload(), 900); }
        else { showStatus("Failed: " + d.message, "error"); btn.disabled = false; btn.textContent = "Add 5 Network Events"; }
      }
      async function resetAll() {
        if (!confirm("Delete all network events? This cannot be undone.")) return;
        const r = await fetch("/api/reset", { method:"POST" });
        const d = await r.json();
        if (d.success) { showStatus("All network events cleared", "error"); setTimeout(() => location.reload(), 900); }
      }
    </script>
  </body></html>`);
});

app.get("/devices", (req, res) => {
  const raw = readJson(path.join(__dirname, "data", "synthetic_device_events.json"));
  const events: DeviceEvent[] = raw.map((e: any) => ({
    ...e,
    user_id:    e.user    ?? e.user_id,
    usb_action: e.action  ?? e.usb_action,
  }));

  res.send(`<!DOCTYPE html><html><head><title>PirateShield</title><style>${sharedStyles}</style></head><body>
    <h1>PirateShield</h1>${navBar("dev")}${statusScript()}
    <div class="controls">
      <button class="btn-green" onclick="addDevice()">Add 5 Device Events</button>
      <button class="btn-orange" onclick="location.reload()">Refresh</button>
      <button class="btn-red"   onclick="resetDevice()">Reset All Data</button>
    </div>
    <p><strong>Total Device Events:</strong> ${events.length}</p>
    ${events.length === 0
      ? `<p style="color:#999">No events yet. Click "Add 5 Device Events" to generate data.</p>`
      : events.map(e => {
          const { score, reasons } = scoreDeviceEvent(e);
          const lvl = score >= 85 ? "critical" : score >= 60 ? "high" : score >= 35 ? "medium" : score >= 15 ? "low" : "none";
          let detail = "";
          if (e.event_type === "process_start")
            detail = `Process: <strong>${e.process_name}</strong> (${e.process_path})`;
          else if (e.event_type === "cpu_spike")
            detail = `CPU: <strong>${e.cpu_percent}%</strong> vs baseline ${e.baseline_cpu}% for ${e.duration_seconds}s`;
          else if (e.event_type === "usb_event")
            detail = `USB: <strong>${(e as any).usb_id}</strong> &mdash; ${(e as any).action ?? e.usb_action}${e.new_executable_started ? " &nbsp;<strong style='color:red'>EXE LAUNCHED</strong>" : ""}`;
          else if (e.event_type === "security_change")
            detail = `Security: <strong>${e.component}</strong> changed to <strong>${e.new_status}</strong>`;

          return `<div class="card risk-${lvl}">
            <span class="badge badge-${lvl}">Risk: ${score}</span>
            <span class="badge badge-device">device</span>
            ${e.suspicious ? '<span class="badge badge-suspicious">SUSPICIOUS</span>' : '<span class="badge badge-clean">clean</span>'}
            <strong> ${e.user_id ?? (e as any).user}</strong> | <code>${e.event_id}</code> &mdash; ${e.timestamp}<br>
            <span style="color:#666">Device: <strong>${e.device_id}</strong> (${e.device_type}) &nbsp;|&nbsp; ${detail}</span>
            ${reasons.length > 0 ? `<br><span style="color:#c00;font-size:12px">&#9888; ${reasons.join(" &nbsp;&bull;&nbsp; ")}</span>` : ""}
          </div>`;
        }).join("")}
    <script>
      async function addDevice() {
        const btn = event.target; btn.disabled = true; btn.textContent = "Generating...";
        try {
          const r = await fetch("/api/add-device", { method: "POST" });
          const d = await r.json();
          if (d.success) { showStatus("Added 5 device events!", "success"); setTimeout(() => location.reload(), 900); }
          else { showStatus("Failed: " + d.message, "error"); btn.disabled = false; btn.textContent = "Add 5 Device Events"; }
        } catch(err) { showStatus("Error: " + err.message, "error"); btn.disabled = false; btn.textContent = "Add 5 Device Events"; }
      }
      async function resetDevice() {
        if (!confirm("Delete all device events? This cannot be undone.")) return;
        try {
          const r = await fetch("/api/reset-device", { method: "POST" });
          const d = await r.json();
          if (d.success) { showStatus("All device events cleared", "error"); setTimeout(() => location.reload(), 900); }
        } catch(err) { showStatus("Error: " + err.message, "error"); }
      }
    </script>
  </body></html>`);
});

app.get("/unified", (req, res) => {
  const events = db.prepare("SELECT * FROM unified_events ORDER BY created_at DESC LIMIT 200").all() as any[];
  const counts = { network:0, identity:0, device:0 };
  for (const e of events) if (e.event_category in counts) counts[e.event_category as keyof typeof counts]++;

  res.send(`<!DOCTYPE html><html><head><title>PirateShield</title><style>${sharedStyles}</style></head><body>
    <h1>PirateShield</h1>${navBar("unified")}${statusScript()}
    <div class="controls">
      <button class="btn-green"  onclick="inject('identity')">Inject Identity Event</button>
      <button class="btn-orange" onclick="location.reload()">Refresh</button>
    </div>
    <div class="stat-row">
      <div class="stat-box"><div class="num">${events.length}</div><div class="lbl">Total</div></div>
      <div class="stat-box"><div class="num" style="color:#007bff">${counts.network}</div><div class="lbl">Network</div></div>
      <div class="stat-box"><div class="num" style="color:#6610f2">${counts.identity}</div><div class="lbl">Identity</div></div>
      <div class="stat-box"><div class="num" style="color:#17a2b8">${counts.device}</div><div class="lbl">Device</div></div>
    </div>
    ${events.length === 0
      ? `<p style="color:#999">No unified events yet. Add network events or load device events.</p>`
      : events.map((e: any) => {
          const s = e.risk_score;
          const lvl = s >= 85 ? "critical" : s >= 60 ? "high" : s >= 35 ? "medium" : s >= 15 ? "low" : "none";
          return `<div class="card risk-${lvl}">
            <span class="badge badge-${lvl}">Risk: ${s}</span>
            <span class="badge badge-${e.event_category}">${e.event_category}</span>
            <span class="badge" style="background:#555">${e.event_type ?? "n/a"}</span>
            <strong> ${e.user_id ?? "—"}</strong> | Device: ${e.device_id ?? "—"} &mdash; <span style="color:#666">${e.timestamp ?? e.created_at}</span>
            ${e.source_ip ? `<br><span style="color:#666">${e.source_ip} &rarr; ${e.destination_ip}:${e.destination_port} (${e.protocol})</span>` : ""}
          </div>`;
        }).join("")}
    <script>
      const ID_SAMPLES = [
        {event_category:"identity",event_type:"failed_login",user_id:"student1",device_id:"host-A",user_known_devices:["host-A","host-B"],login_success:false,login_attempts:1},
        {event_category:"identity",event_type:"brute_force_login",user_id:"teacher2",device_id:"unknown-device-99",user_known_devices:["host-B","host-C"],login_success:false,login_attempts:8,new_device:true},
        {event_category:"identity",event_type:"new_device_login",user_id:"it_staff3",device_id:"host-X",user_known_devices:["host-C","host-D"],login_success:true,new_device:true}
      ];
      async function inject(cat) {
        const pool = cat === "identity" ? ID_SAMPLES : [];
        const s = {...pool[Math.floor(Math.random()*pool.length)], event_id: crypto.randomUUID(), timestamp: new Date().toISOString()};
        const r = await fetch("/ingest-unified",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(s)});
        const d = await r.json();
        showStatus("Injected! Risk: " + d.risk_score, "success");
        setTimeout(() => location.reload(), 900);
      }
    </script>
  </body></html>`);
});

app.get("/alerts", (req, res) => {
  const alerts = db.prepare("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 200").all() as any[];
  const counts = { critical:0, high:0, medium:0, low:0, unacked:0 };
  for (const a of alerts) {
    if (a.severity in counts) counts[a.severity as keyof typeof counts]++;
    if (!a.acknowledged) counts.unacked++;
  }

  res.send(`<!DOCTYPE html><html><head><title>PirateShield</title><style>${sharedStyles}</style></head><body>
    <h1>PirateShield</h1>${navBar("alerts")}${statusScript()}
    <div class="controls">
      <button class="btn-green" onclick="ackAll()">Acknowledge All</button>
      <button class="btn-orange"   onclick="location.reload()">Refresh</button>
    </div>
    <div class="stat-row">
      <div class="stat-box"><div class="num">${counts.unacked}</div><div class="lbl">Unacknowledged</div></div>
      <div class="stat-box"><div class="num" style="color:#6f0000">${counts.critical}</div><div class="lbl">Critical</div></div>
      <div class="stat-box"><div class="num" style="color:#dc3545">${counts.high}</div><div class="lbl">High</div></div>
      <div class="stat-box"><div class="num" style="color:#856404">${counts.medium}</div><div class="lbl">Medium</div></div>
      <div class="stat-box"><div class="num" style="color:#155724">${counts.low}</div><div class="lbl">Low</div></div>
    </div>
    ${alerts.length === 0
      ? `<p style="color:#999">No alerts yet. Events scoring &ge; 15 appear here automatically.</p>`
      : alerts.map((a: any) => {
          const lvl = a.severity;
          return `<div class="card risk-${lvl} ${a.acknowledged ? "alert-acked" : ""}">
            <span class="badge badge-${lvl}">${lvl.toUpperCase()}</span>
            <strong> ${a.user_id ?? "unknown"}</strong> | Device: ${a.device_id ?? "—"}
            ${!a.acknowledged
              ? `<button class="ack-btn" onclick="ack(${a.id})">&#10003; Acknowledge</button>`
              : `<span style="font-size:11px;color:#999;margin-left:8px">&#10003; Acknowledged</span>`}
            <br><strong>Reason:</strong> ${a.reason}
            <br><strong>Score:</strong> ${a.risk_score} &nbsp;|&nbsp; ${a.created_at}
            ${a.event_id ? `<br><code style="font-size:11px">${a.event_id}</code>` : ""}
          </div>`;
        }).join("")}
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

app.get("/ingest", (req, res) => {
  res.send(`<!DOCTYPE html><html><head><title>PirateShield – Ingest</title><style>${sharedStyles}
    .itabs{display:flex;gap:0;margin-bottom:0}
    .itab{background:#e9ecef;color:#333;border:1px solid #ced4da;border-bottom:none;border-radius:6px 6px 0 0;padding:9px 22px;font-size:14px;cursor:pointer;margin-right:4px}
    .itab.active{background:#343a40;color:white;border-color:#343a40}
    .ipanel{display:none;background:white;border:1px solid #ced4da;border-radius:0 6px 6px 6px;padding:26px}
    .ipanel.active{display:block}
    .fg{display:flex;flex-direction:column;gap:4px}
    .fgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px 20px}
    .full{grid-column:1/-1}
    label{font-size:11px;font-weight:bold;color:#555;text-transform:uppercase;letter-spacing:.4px}
    input,select{padding:7px 10px;border:1px solid #ced4da;border-radius:4px;font-size:13px;width:100%;box-sizing:border-box}
    input:focus,select:focus{outline:none;border-color:#007bff;box-shadow:0 0 0 2px rgba(0,123,255,.15)}
    .rbox{margin-top:12px;padding:11px 14px;border-radius:6px;font-size:13px;display:none}
    .rbox.show{display:block} .rbox.ok{background:#d4edda;color:#155724;border:1px solid #c3e6cb}
    .rbox.err{background:#f8d7da;color:#721c24;border:1px solid #f5c6cb}
  </style></head><body>
    <h1>PirateShield</h1>${navBar("ingest")}
    <h2 style="margin-bottom:4px">Manual Event Ingest</h2>
    <p style="color:#666;font-size:13px;margin-top:0;margin-bottom:18px">
      Every submission writes to <strong>4 destinations</strong>:
      type-specific DB table &rarr; <code>unified_events</code> &rarr; <code>alerts</code> (if score &ge; 15) &rarr; matching <code>.json</code> file.
    </p>

    <div class="itabs">
      <button class="itab active" onclick="switchTab('network',this)">&#127760; Network</button>
      <button class="itab"        onclick="switchTab('identity',this)">&#128100; Identity</button>
      <button class="itab"        onclick="switchTab('device',this)">&#128187; Device</button>
    </div>

    <!-- NETWORK -->
    <div id="tab-network" class="ipanel active">
      <div class="fgrid">
        <div class="fg"><label>User ID</label><input id="n-uid" placeholder="e.g. student1"/></div>
        <div class="fg"><label>Device ID</label><input id="n-did" placeholder="e.g. host-A"/></div>
        <div class="fg"><label>Source IP</label><input id="n-sip" placeholder="e.g. 192.168.1.10"/></div>
        <div class="fg"><label>Destination IP</label><input id="n-dip" placeholder="e.g. 10.0.0.5"/></div>
        <div class="fg"><label>Destination Port</label><input id="n-dport" type="number" placeholder="e.g. 443"/></div>
        <div class="fg"><label>Protocol</label>
          <select id="n-proto"><option>TCP</option><option>UDP</option><option>ICMP</option><option>RAW</option></select>
        </div>
        <div class="fg"><label>Event Type</label>
          <select id="n-etype">
            <option value="normal_traffic">normal_traffic</option><option value="vpn_connection">vpn_connection</option>
            <option value="port_scan">port_scan</option><option value="brute_force">brute_force</option>
            <option value="data_exfil">data_exfil</option><option value="malware">malware</option>
            <option value="lateral_movement">lateral_movement</option><option value="c2_beacon">c2_beacon</option>
          </select>
        </div>
        <div class="fg"><label>Bytes Sent</label><input id="n-bsent" type="number" value="1024"/></div>
        <div class="fg"><label>Bytes Received</label><input id="n-brecv" type="number" value="2048"/></div>
        <div class="fg"><label>Latitude</label><input id="n-lat" type="number" placeholder="40.71"/></div>
        <div class="fg"><label>Longitude</label><input id="n-long" type="number" placeholder="-74.00"/></div>
        <div class="fg full"><label>Known Devices (comma-separated)</label><input id="n-kd" placeholder="host-A,host-B"/></div>
      </div>
      <div style="margin-top:16px"><button class="btn-blue" onclick="submitNetwork()">&#8679; Submit Network Event</button></div>
      <div id="n-result" class="rbox"></div>
    </div>

    <!-- IDENTITY -->
    <div id="tab-identity" class="ipanel">
      <div class="fgrid">
        <div class="fg"><label>User ID</label><input id="i-uid" placeholder="e.g. teacher2"/></div>
        <div class="fg"><label>Device ID</label><input id="i-did" placeholder="e.g. host-B"/></div>
        <div class="fg"><label>Event Type</label>
          <select id="i-etype">
            <option value="failed_login">failed_login</option><option value="brute_force_login">brute_force_login</option>
            <option value="new_device_login">new_device_login</option><option value="successful_login">successful_login</option>
            <option value="password_change">password_change</option><option value="account_locked">account_locked</option>
          </select>
        </div>
        <div class="fg"><label>Login Success</label>
          <select id="i-success"><option value="false">No (failed)</option><option value="true">Yes</option></select>
        </div>
        <div class="fg"><label>Login Attempts</label><input id="i-attempts" type="number" value="1" min="1"/></div>
        <div class="fg"><label>New / Unknown Device?</label>
          <select id="i-newdev"><option value="false">No</option><option value="true">Yes</option></select>
        </div>
        <div class="fg"><label>OS Change?</label>
          <select id="i-oschg"><option value="false">No</option><option value="true">Yes</option></select>
        </div>
        <div class="fg full"><label>Known Devices (comma-separated)</label><input id="i-kd" placeholder="host-A,host-B"/></div>
      </div>
      <div style="margin-top:16px"><button class="btn-purple" onclick="submitIdentity()">&#8679; Submit Identity Event</button></div>
      <div id="i-result" class="rbox"></div>
    </div>

    <!-- DEVICE -->
    <div id="tab-device" class="ipanel">
      <div class="fgrid">
        <div class="fg"><label>User ID</label><input id="d-uid" placeholder="e.g. it_staff3"/></div>
        <div class="fg"><label>Device ID</label><input id="d-did" placeholder="e.g. host-C"/></div>
        <div class="fg"><label>Device Type</label>
          <select id="d-dtype"><option value="laptop">laptop</option><option value="desktop">desktop</option><option value="server">server</option></select>
        </div>
        <div class="fg"><label>Event Type</label>
          <select id="d-etype" onchange="toggleDevFields(this.value)">
            <option value="process_start">process_start</option><option value="cpu_spike">cpu_spike</option>
            <option value="usb_event">usb_event</option><option value="security_change">security_change</option>
          </select>
        </div>
      </div>
      <div id="df-process" style="margin-top:12px"><div class="fgrid">
        <div class="fg"><label>Process Name</label><input id="d-pname" placeholder="e.g. nmap"/></div>
        <div class="fg"><label>Process Path</label><input id="d-ppath" placeholder="e.g. /usr/bin/nmap"/></div>
        <div class="fg"><label>Flagged Suspicious?</label><select id="d-susp"><option value="false">No</option><option value="true">Yes</option></select></div>
      </div></div>
      <div id="df-cpu" style="display:none;margin-top:12px"><div class="fgrid">
        <div class="fg"><label>CPU %</label><input id="d-cpu" type="number" placeholder="95"/></div>
        <div class="fg"><label>Baseline CPU %</label><input id="d-bcpu" type="number" placeholder="20"/></div>
        <div class="fg"><label>Duration (s)</label><input id="d-dur" type="number" placeholder="720"/></div>
      </div></div>
      <div id="df-usb" style="display:none;margin-top:12px"><div class="fgrid">
        <div class="fg"><label>USB ID</label><input id="d-usbid" placeholder="USB001"/></div>
        <div class="fg"><label>USB Action</label><select id="d-usbact"><option value="inserted">inserted</option><option value="removed">removed</option></select></div>
        <div class="fg"><label>New Executable Started?</label><select id="d-newexe"><option value="false">No</option><option value="true">Yes</option></select></div>
        <div class="fg"><label>Exe Path</label><input id="d-exepath" placeholder="/media/usb/run.exe"/></div>
      </div></div>
      <div id="df-sec" style="display:none;margin-top:12px"><div class="fgrid">
        <div class="fg"><label>Component</label><input id="d-comp" placeholder="firewall"/></div>
        <div class="fg"><label>New Status</label><select id="d-nstatus"><option value="disabled">disabled</option><option value="enabled">enabled</option></select></div>
      </div></div>
      <div style="margin-top:16px"><button style="background:#17a2b8;color:white;padding:8px 16px;border:none;border-radius:5px;font-size:14px;cursor:pointer" onclick="submitDevice()">&#8679; Submit Device Event</button></div>
      <div id="d-result" class="rbox"></div>
    </div>

    <script>
      function switchTab(name,btn){
        document.querySelectorAll('.ipanel').forEach(p=>p.classList.remove('active'));
        document.querySelectorAll('.itab').forEach(b=>b.classList.remove('active'));
        document.getElementById('tab-'+name).classList.add('active'); btn.classList.add('active');
      }
      function toggleDevFields(type){
        ['process','cpu','usb','sec'].forEach(k=>document.getElementById('df-'+k).style.display='none');
        const map={process_start:'process',cpu_spike:'cpu',usb_event:'usb',security_change:'sec'};
        if(map[type]) document.getElementById('df-'+map[type]).style.display='block';
      }
      function res(id,msg,ok){const el=document.getElementById(id);el.textContent=msg;el.className='rbox show '+(ok?'ok':'err');}
      const v=id=>document.getElementById(id)?.value??'';
      const num=id=>{const n=parseFloat(v(id));return isNaN(n)?null:n;};
      const bool=id=>v(id)==='true';

      async function submitNetwork(){
        const payload={event_id:crypto.randomUUID(),timestamp:new Date().toISOString(),
          user_id:v('n-uid')||'unknown',device_id:v('n-did')||null,
          source_ip:v('n-sip')||null,destination_ip:v('n-dip')||null,
          destination_port:num('n-dport'),protocol:v('n-proto'),event_type:v('n-etype'),
          bytes_sent:num('n-bsent')??0,bytes_received:num('n-brecv')??0,
          lat:num('n-lat'),long:num('n-long'),
          user_known_devices:v('n-kd').split(',').map(s=>s.trim()).filter(Boolean)};
        try{const r=await fetch('/ingest',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
          const d=await r.json();
          r.ok?res('n-result','✓ Risk: '+d.risk_score+' — network_events + unified_events + alerts + .json',true)
              :res('n-result','✗ '+(d.error||JSON.stringify(d)),false);
        }catch(e){res('n-result','✗ '+e.message,false);}
      }

      async function submitIdentity(){
        const payload={event_id:crypto.randomUUID(),timestamp:new Date().toISOString(),
          event_category:'identity',user_id:v('i-uid')||'unknown',device_id:v('i-did')||null,
          event_type:v('i-etype'),login_success:bool('i-success'),
          login_attempts:num('i-attempts')??1,new_device:bool('i-newdev'),os_change:bool('i-oschg'),
          user_known_devices:v('i-kd').split(',').map(s=>s.trim()).filter(Boolean)};
        try{const r=await fetch('/ingest-unified',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
          const d=await r.json();
          r.ok?res('i-result','✓ Risk: '+d.risk_score+' — identity_events + unified_events + alerts + .json',true)
              :res('i-result','✗ '+(d.error||JSON.stringify(d)),false);
        }catch(e){res('i-result','✗ '+e.message,false);}
      }

      async function submitDevice(){
        const etype=v('d-etype');
        const payload={event_id:crypto.randomUUID(),timestamp:new Date().toISOString(),
          event_category:'device',user_id:v('d-uid')||'unknown',device_id:v('d-did')||null,
          device_type:v('d-dtype'),event_type:etype,
          ...(etype==='process_start'?{process_name:v('d-pname'),process_path:v('d-ppath'),suspicious:bool('d-susp')}:{}),
          ...(etype==='cpu_spike'?{cpu_percent:num('d-cpu'),baseline_cpu:num('d-bcpu'),duration_seconds:num('d-dur')}:{}),
          ...(etype==='usb_event'?{usb_id:v('d-usbid'),usb_action:v('d-usbact'),new_executable_started:bool('d-newexe'),exe_path:v('d-exepath')||null}:{}),
          ...(etype==='security_change'?{component:v('d-comp'),new_status:v('d-nstatus')}:{})};
        try{const r=await fetch('/ingest-unified',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
          const d=await r.json();
          r.ok?res('d-result','✓ Risk: '+d.risk_score+' — device_events + unified_events + alerts + .json',true)
              :res('d-result','✗ '+(d.error||JSON.stringify(d)),false);
        }catch(e){res('d-result','✗ '+e.message,false);}
      }
    </script>
  </body></html>`);
});

app.post("/ingest", (req, res) => {
  const event: Partial<NetworkEvent> = req.body;
  if (!event || typeof event !== "object") return res.status(400).json({ error: "Invalid payload" });

  const fp = path.join(__dirname, "data", "synthetic_network_events.json");
  const existing = readJson(fp);
  if (!existing.some((x: any) => x.event_id === event.event_id)) writeJson(fp, [...existing, event]);

  const risk_score = calculateRiskScore(event);
  try {
    db.prepare(`
      INSERT OR IGNORE INTO network_events
        (event_id,user_id,timestamp,source_ip,destination_ip,destination_port,
         protocol,bytes_sent,bytes_received,device_id,event_type,payload,risk_score)
      VALUES
        (@event_id,@user_id,@timestamp,@source_ip,@destination_ip,@destination_port,
         @protocol,@bytes_sent,@bytes_received,@device_id,@event_type,@payload,@risk_score)
    `).run({ ...event, payload: JSON.stringify(event), risk_score });
  } catch (err) {
    console.error("Error inserting network event:", err);
  }

  insertUnifiedEvent({ ...(event as any), event_category: "network" }, risk_score);
  res.status(201).json({ message: "Event ingested", risk_score });
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
    const fp = path.join(__dirname, "data", "synthetic_network_events.json");
    const existing = readJson(fp);
    if (!existing.some((x: any) => x.event_id === event.event_id)) writeJson(fp, [...existing, event]);
    insertUnifiedEvent({ ...event, event_category: "network" }, risk_score);
  }

  res.status(201).json({ message: "Unified event ingested", risk_score });
});

app.post("/api/load-device-events", (req, res) => {
  const fp = path.join(__dirname, "data", "synthetic_device_events.json");
  if (!fs.existsSync(fp)) return res.status(404).json({ success:false, message:"synthetic_device_events.json not found" });

  let raw: any[];
  try { raw = JSON.parse(fs.readFileSync(fp, "utf-8")); }
  catch { return res.status(500).json({ success:false, message:"Failed to parse JSON" }); }

  const stmt = db.prepare(`
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
  `);

  let count = 0;
  for (const e of raw) {
    const norm: DeviceEvent = { ...e, user_id: e.user ?? e.user_id, usb_action: e.action ?? e.usb_action };
    const { score: risk_score } = scoreDeviceEvent(norm);
    try {
      stmt.run({
        event_id:              norm.event_id              ?? null,
        user_id:               norm.user_id               ?? null,
        device_id:             norm.device_id             ?? null,
        device_type:           norm.device_type           ?? null,
        event_type:            norm.event_type            ?? null,
        process_name:          norm.process_name          ?? null,
        process_path:          norm.process_path          ?? null,
        suspicious:            norm.suspicious ? 1 : 0,
        cpu_percent:           norm.cpu_percent           ?? null,
        baseline_cpu:          norm.baseline_cpu          ?? null,
        duration_seconds:      norm.duration_seconds      ?? null,
        usb_id:                norm.usb_id                ?? null,
        usb_action:            norm.usb_action            ?? null,
        new_executable_started: norm.new_executable_started ? 1 : 0,
        exe_path:              norm.exe_path              ?? null,
        component:             norm.component             ?? null,
        new_status:            norm.new_status            ?? null,
        timestamp:             norm.timestamp             ?? null,
        payload:               JSON.stringify(e),
        risk_score,
      });

      const unified: UnifiedEvent = {
        ...norm,
        event_category: "device",
        user_id: norm.user_id,
      };
      insertUnifiedEvent(unified, risk_score);
      count++;
    } catch (err) {
      console.error("Error inserting unified event:", err);
    }
  }

  res.json({ success:true, count, message:`Loaded ${count} device events` });
});

app.post("/api/add", (req, res) => {
  const python = spawn("python3", ["scripts/generate_network_events.py"]);
  python.on("close", (code) => {
    if (code !== 0) return res.status(500).json({ success:false, message:"Python script failed" });
    const fp = path.join(__dirname, "data", "synthetic_network_events.json");
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
        const risk_score = calculateRiskScore(e);
        stmt.run({ ...e, payload:JSON.stringify(e), risk_score });
        insertUnifiedEvent({ ...(e as any), event_category:"network" }, risk_score);
      }
      res.json({ success:true, message:"Events generated and ingested" });
    } catch { res.status(500).json({ success:false, message:"Failed to ingest" }); }
  });
  python.on("error", (err) => res.status(500).json({ success:false, message:(err as Error).message }));
});

app.post("/api/reset", (req, res) => {
  const fp = path.join(__dirname, "data", "synthetic_network_events.json");
  try {
    fs.writeFileSync(fp, JSON.stringify([], null, 2));
    db.prepare("DELETE FROM network_events").run();
    db.prepare("DELETE FROM device_events").run();
    db.prepare("DELETE FROM unified_events").run();
    db.prepare("DELETE FROM alerts").run();
    try { db.prepare("DELETE FROM sqlite_sequence WHERE name IN ('network_events','device_events','unified_events','alerts')").run(); } catch {}
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
app.get("/api/alerts",       (req, res) => res.json(db.prepare("SELECT * FROM alerts         ORDER BY created_at DESC LIMIT 200").all()));

app.post("/api/add-device", (req, res) => {
  const python = spawn("python3", ["scripts/generate_device_events.py", "5"]);
  python.on("close", (code) => {
    if (code !== 0) return res.status(500).json({ success: false, message: "Script failed" });
    try {
      const all = readJson(path.join(__dirname, "data", "synthetic_device_events.json"));
      for (const e of all.slice(-5)) ingestDeviceEvent(e);
      res.json({ success: true });
    } catch { res.status(500).json({ success: false, message: "Failed to ingest" }); }
  });
  python.on("error", (err: Error) => res.status(500).json({ success: false, message: err.message }));
});

app.post("/api/reset-device", (req, res) => {
  try {
    fs.writeFileSync(path.join(__dirname, "data", "synthetic_device_events.json"), "[]", { encoding: "utf8" });
    db.prepare("DELETE FROM device_events").run();
    db.prepare("DELETE FROM unified_events WHERE event_category = 'device'").run();
    try { db.prepare("DELETE FROM sqlite_sequence WHERE name = 'device_events'").run(); } catch {}
    res.json({ success: true });
  } catch { res.status(500).json({ success: false, message: "Reset failed" }); }
});

app.listen(PORT, () => console.log(`PirateShield running at http://localhost:${PORT}`));