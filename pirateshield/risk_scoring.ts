import type { NetworkEvent } from "./server.ts";

const HIGH_RISK_PORTS        = [22, 23, 3389, 4444, 5900, 6667, 1337];
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

export type AlertSeverity = "low" | "medium" | "high" | "critical";

function scoreNetworkEvent(event: Partial<NetworkEvent & UnifiedEvent>): RiskResult {
  let score = 0;
  const reasons: string[] = [];

  if (event.destination_port && HIGH_RISK_PORTS.includes(event.destination_port)) {
    score += 30;
    reasons.push(`High-risk destination port: ${event.destination_port}`);
  }
  if (event.protocol && SUSPICIOUS_PROTOCOLS.includes(event.protocol.toUpperCase())) {
    score += 20;
    reasons.push(`Suspicious protocol: ${event.protocol}`);
  }
  if (event.event_type && HIGH_RISK_NET_TYPES.includes(event.event_type.toLowerCase())) {
    score += 40;
    reasons.push(`High-risk event type: ${event.event_type}`);
  } else if (event.event_type && MEDIUM_RISK_NET_TYPES.includes(event.event_type.toLowerCase())) {
    score += 20;
    reasons.push(`Medium-risk event type: ${event.event_type}`);
  }
  if (event.bytes_sent && event.bytes_sent > 5_000_000) {
    score += 20;
    reasons.push(`Large data transfer: ${(event.bytes_sent / 1_000_000).toFixed(1)} MB sent`);
  }
  if (event.device_id && event.user_known_devices && !event.user_known_devices.includes(event.device_id)) {
    score += 15;
    reasons.push(`Unknown device: ${event.device_id}`);
  }

  return { score, reasons };
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