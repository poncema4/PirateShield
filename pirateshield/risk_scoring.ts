import type { NetworkEvent } from './server.ts';

const HIGH_RISK_PORTS = [22, 23, 3389, 4444, 5900, 6667];
const SUSPICIOUS_PROTOCOLS = ['ICMP', 'RAW'];
const HIGH_RISK_EVENT_TYPES = ['port_scan', 'brute_force', 'data_exfil', 'malware', 'lateral_movement'];

export function calculateRiskScore(event: Partial<NetworkEvent>): number {
  let score = 0;

  // Rule 1: High-risk destination port
  if (event.destination_port && HIGH_RISK_PORTS.includes(event.destination_port)) {
    score += 30;
  }

  // Rule 2: Suspicious protocol
  if (event.protocol && SUSPICIOUS_PROTOCOLS.includes(event.protocol.toUpperCase())) {
    score += 20;
  }

  // Rule 3: Known high-risk event type
  if (event.event_type && HIGH_RISK_EVENT_TYPES.includes(event.event_type.toLowerCase())) {
    score += 40;
  }

  // Rule 4: Unusually high data transfer (potential exfiltration)
  if (event.bytes_sent && event.bytes_sent > 5_000_000) {
    score += 20;
  }

  // Rule 5: Unknown device
  if (event.device_id && event.user_known_devices && !event.user_known_devices.includes(event.device_id)) {
    score += 15;
  }

  return Math.min(score, 100);
}