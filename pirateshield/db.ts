import Database from "better-sqlite3";

const db = new Database("pirateshield.db");

db.exec(`
  CREATE TABLE IF NOT EXISTS network_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT,
    user_id TEXT,
    timestamp TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    destination_port INTEGER,
    protocol TEXT,
    bytes_sent INTEGER,
    bytes_received INTEGER,
    device_id TEXT,
    event_type TEXT,
    payload TEXT,
    risk_score REAL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS device_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE,
    user_id TEXT,
    device_id TEXT,
    device_type TEXT,
    event_type TEXT,
    process_name TEXT,
    process_path TEXT,
    suspicious INTEGER DEFAULT 0,
    cpu_percent REAL,
    baseline_cpu REAL,
    duration_seconds INTEGER,
    usb_id TEXT,
    usb_action TEXT,
    new_executable_started INTEGER DEFAULT 0,
    exe_path TEXT,
    component TEXT,
    new_status TEXT,
    timestamp TEXT,
    payload TEXT,
    risk_score REAL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS identity_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE,
    user_id TEXT,
    device_id TEXT,
    event_type TEXT,
    login_success INTEGER,
    login_attempts INTEGER,
    new_device INTEGER DEFAULT 0,
    os_change INTEGER DEFAULT 0,
    user_known_devices TEXT,
    timestamp TEXT,
    payload TEXT,
    risk_score REAL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS unified_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE,
    user_id TEXT,
    device_id TEXT,
    event_category TEXT NOT NULL,
    event_type TEXT,
    timestamp TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    destination_port INTEGER,
    protocol TEXT,
    bytes_sent INTEGER,
    bytes_received INTEGER,
    user_known_devices TEXT,
    lat REAL,
    long REAL,
    payload TEXT,
    risk_score REAL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT,
    user_id TEXT,
    device_id TEXT,
    severity TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
    reason TEXT NOT NULL,
    risk_score REAL NOT NULL,
    acknowledged INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  )
`);

export default db;