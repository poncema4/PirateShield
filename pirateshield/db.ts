import Database from 'better-sqlite3';

const db = new Database('pirateshield.db');

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

export default db;