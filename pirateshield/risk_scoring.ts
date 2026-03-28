import type { NetworkEvent } from "./server.ts";

const HIGH_RISK_PORTS        = [22, 23, 3389, 4444, 5900, 6667, 1337];
const VPN_PROXY_PORTS        = [1080, 1194, 8080, 9050, 9150, 4145, 1081];
const SUSPICIOUS_DEST_IPS    = ["185.220.101.1", "198.51.100.77", "203.0.113.45"];
const SUSPICIOUS_PROTOCOLS   = ["ICMP", "RAW"];
const HIGH_RISK_NET_TYPES    = ["port_scan","brute_force","data_exfil","malware","lateral_movement","c2_beacon"];
const MEDIUM_RISK_NET_TYPES  = ["unusual_login","vpn_connection"];

const SUSPICIOUS_PROCESSES   = ["wireguard","openvpn","tor","proxychains","nmap","netcat","nc","mimikatz","metasploit","msfconsole"];
const HIGH_RISK_DEV_TYPES    = ["process_start"];
const CPU_SPIKE_RATIO        = 2.5;
const CPU_LONG_DURATION      = 600;

export interface UnifiedEvent {
  event_id?: string;
  user_id?: string;
  device_id?: string;
  event_category: "network" | "identity" | "device";
  event_type?: string;
  timestamp?: string;
  // NETWORK
  source_ip?: string;
  destination_ip?: string;
  destination_port?: number;
  protocol?: string;
  bytes_sent?: number;
  bytes_received?: number;
  user_known_devices?: string[];
  lat?: number;
  long?: number;
  // IDENTITY
  login_success?: boolean;
  login_attempts?: number;
  new_device?: boolean;
  os_change?: boolean;
  // DEVICE
  device_type?: string;
  process_name?: string;
  process_path?: string;
  suspicious?: boolean;
  cpu_percent?: number;
  baseline_cpu?: number;
  duration_seconds?: number;
  usb_id?: string;
  usb_action?: string;
  new_executable_started?: boolean;
  exe_path?: string;
  component?: string;
  new_status?: string;
}

export interface DeviceEvent {
  event_id?: string;
  user_id?: string;
  device_id?: string;
  device_type?: string;
  event_type?: string;
  process_name?: string;
  process_path?: string;
  suspicious?: boolean;
  cpu_percent?: number;
  baseline_cpu?: number;
  duration_seconds?: number;
  usb_id?: string;
  usb_action?: string;
  new_executable_started?: boolean;
  exe_path?: string;
  component?: string;
  new_status?: string;
  timestamp?: string;
  risk_score?: number;
}

export interface RiskResult {
  score: number;
  reasons: string[];
}

export interface NetworkRiskBreakdown {
  m01: number;
  m02: number;
  m03: number;
  m04: number;
  m05: number;
  m06: number;
  m07: number;
  m08: number;
  composite: number;
  reasons: string[];
}

export type AlertSeverity = "low" | "medium" | "high" | "critical";

export function scoreNetworkRules(event: Partial<NetworkEvent & UnifiedEvent>): NetworkRiskBreakdown {
  const reasons: string[] = [];
  let m01 = 0, m02 = 0, m03 = 0, m04 = 0, m05 = 0, m06 = 0, m07 = 0, m08 = 0;

  // M01: Excessive Outbound Traffic
  if (event.bytes_sent && event.bytes_sent > 5_000_000) {
    m01 = 40;
    reasons.push(`M01: Excessive outbound ${(event.bytes_sent / 1_000_000).toFixed(1)} MB`);
  } else if (event.bytes_sent && event.bytes_sent > 1_000_000) {
    m01 = 25;
    reasons.push(`M01: Large outbound ${(event.bytes_sent / 1_000_000).toFixed(1)} MB`);
  }

  // M02: VPN / Proxy Destination
  if (event.destination_ip && SUSPICIOUS_DEST_IPS.includes(event.destination_ip)) {
    m02 += 15;
    reasons.push(`M02: Suspicious destination IP ${event.destination_ip}`);
  }
  if (event.destination_port && VPN_PROXY_PORTS.includes(event.destination_port)) {
    m02 = Math.min(25, m02 + 15);
    reasons.push(`M02: VPN/proxy port ${event.destination_port}`);
  }
  if (event.event_type?.toLowerCase() === "vpn_connection") {
    m02 = Math.min(25, m02 + 10);
    reasons.push("M02: VPN connection detected");
  }

  // M03: Abnormal Connection Burst (limited in per-event mode, full detection in batch Python model)
  // Per-event: only flag if event type suggests scanning
  if (event.event_type?.toLowerCase() === "port_scan") {
    m03 = 20;
    reasons.push("M03: Port scan activity detected");
  }

  // M04: High-Risk Port Access
  if (event.destination_port && HIGH_RISK_PORTS.includes(event.destination_port)) {
    if ([4444, 1337, 6667].includes(event.destination_port)) {
      m04 = 30;
    } else {
      m04 = 25;
    }
    reasons.push(`M04: High-risk port ${event.destination_port}`);
  }

  // M05: Suspicious Protocol
  if (event.protocol && SUSPICIOUS_PROTOCOLS.includes(event.protocol.toUpperCase())) {
    m05 = event.protocol.toUpperCase() === "RAW" ? 20 : 10;
    reasons.push(`M05: Suspicious protocol ${event.protocol}`);
  }

  // M06: Unknown Device
  if (event.device_id && event.user_known_devices && !event.user_known_devices.includes(event.device_id)) {
    m06 = 15;
    reasons.push(`M06: Unknown device ${event.device_id}`);
  }

  // M07: C2 Beaconing (per-event: flag c2_beacon type, full variance analysis in Python batch)
  if (event.event_type?.toLowerCase() === "c2_beacon") {
    m07 = 30;
    reasons.push("M07: C2 beacon event type (full analysis requires batch model)");
  }

  // M08: Threat Event Classification
  const et = event.event_type?.toLowerCase() ?? "";
  if (["c2_beacon", "malware"].includes(et)) {
    m08 = 40;
    reasons.push(`M08: Critical threat type ${event.event_type}`);
  } else if (["data_exfil", "brute_force", "lateral_movement"].includes(et)) {
    m08 = 35;
    reasons.push(`M08: High threat type ${event.event_type}`);
  } else if (et === "port_scan") {
    m08 = 20;
    reasons.push(`M08: Scan activity ${event.event_type}`);
  } else if (MEDIUM_RISK_NET_TYPES.includes(et)) {
    m08 = 15;
    reasons.push(`M08: Medium-risk type ${event.event_type}`);
  }

  const composite = Math.min(100, m01 + m02 + m03 + m04 + m05 + m06 + m07 + m08);
  return { m01, m02, m03, m04, m05, m06, m07, m08, composite, reasons };
}

function scoreNetworkEvent(event: Partial<NetworkEvent & UnifiedEvent>): RiskResult {
  const breakdown = scoreNetworkRules(event);
  return { score: breakdown.composite, reasons: breakdown.reasons };
}

export function scoreDeviceEvent(event: Partial<DeviceEvent | UnifiedEvent>): RiskResult {
  let score = 0;
  const reasons: string[] = [];

  if ((event as any).suspicious === true) {
    score += 40;
    reasons.push(`Process flagged as suspicious: ${(event as any).process_name ?? "unknown"}`);
  }

  const proc = ((event as any).process_name ?? "").toLowerCase();
  if (proc && SUSPICIOUS_PROCESSES.includes(proc)) {
    if (!reasons.some(r => r.includes("suspicious"))) {
      score += 35;
      reasons.push(`High-risk process started: ${proc}`);
    }
  }

  if ((event as any).event_type === "usb_event" && (event as any).new_executable_started === true) {
    score += 45;
    reasons.push(`USB insertion triggered executable: ${(event as any).exe_path ?? "unknown path"}`);
  }

  const cpuPct  = (event as any).cpu_percent  ?? 0;
  const baseCpu = (event as any).baseline_cpu ?? 1;
  const dur     = (event as any).duration_seconds ?? 0;
  const ratio   = cpuPct / baseCpu;
  if (ratio >= CPU_SPIKE_RATIO && dur >= CPU_LONG_DURATION) {
    score += 30;
    reasons.push(`Sustained CPU spike: ${cpuPct.toFixed(1)}% (${ratio.toFixed(1)}x baseline) for ${dur}s`);
  } else if (ratio >= CPU_SPIKE_RATIO) {
    score += 10;
    reasons.push(`Brief CPU spike: ${cpuPct.toFixed(1)}% (${ratio.toFixed(1)}x baseline)`);
  }

  if ((event as any).event_type === "security_change" && (event as any).new_status === "disabled") {
    score += 50;
    reasons.push(`Security component disabled: ${(event as any).component ?? "unknown"}`);
  }

  return { score, reasons };
}

function scoreIdentityEvent(event: Partial<UnifiedEvent>): RiskResult {
  let score = 0;
  const reasons: string[] = [];

  if (event.login_success === false) {
    score += 25;
    reasons.push("Failed login attempt");
  }
  if (event.login_attempts && event.login_attempts >= 5) {
    score += 30;
    reasons.push(`Repeated login failures: ${event.login_attempts} attempts`);
  }
  if (event.new_device === true) {
    score += 20;
    reasons.push("Login from a new/unrecognised device");
  }
  if (event.device_id && event.user_known_devices && !event.user_known_devices.includes(event.device_id)) {
    score += 15;
    reasons.push(`Device not in user known device list: ${event.device_id}`);
  }

  return { score, reasons };
}

export function calculateRiskScore(event: Partial<NetworkEvent>): number {
  return Math.min(scoreNetworkEvent(event).score, 100);
}

export function calculateUnifiedRisk(event: Partial<UnifiedEvent | DeviceEvent>): RiskResult {
  let result: RiskResult;

  const cat = (event as UnifiedEvent).event_category;
  if (cat === "identity") {
    result = scoreIdentityEvent(event as UnifiedEvent);
  } else if (cat === "device" || !cat) {
    result = scoreDeviceEvent(event as DeviceEvent);
  } else {
    result = scoreNetworkEvent(event as Partial<NetworkEvent>);
  }

  return { score: Math.min(result.score, 100), reasons: result.reasons };
}

export function getAlertSeverity(score: number): AlertSeverity | null {
  if (score >= 85) return "critical";
  if (score >= 60) return "high";
  if (score >= 35) return "medium";
  if (score >= 15) return "low";
  return null;
}

export function shouldGenerateNetworkAlert(score: number, breakdown?: NetworkRiskBreakdown): boolean {
  if (score >= 60) return true;
  if (breakdown) {
    const ruleMax: Record<string, number> = { m01: 40, m02: 25, m03: 35, m04: 30, m05: 20, m06: 15, m07: 40, m08: 40 };
    for (const [key, max] of Object.entries(ruleMax)) {
      if ((breakdown as any)[key] >= max * 0.8) return true;
    }
  }
  return false;
}