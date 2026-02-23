import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn } from 'child_process';
import db from './db.ts';
import { calculateRiskScore } from './risk_scoring.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
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

app.get('/', (req, res) => {
  const filePath = path.join(__dirname, 'data', 'synthetic_network_events.json');

  let events: NetworkEvent[] = [];
  if (fs.existsSync(filePath)) {
    events = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  }

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>PirateShield</title>
      <style>
        body { font-family: Arial; max-width: 1000px; margin: 50px auto; padding: 20px; }
        .controls { margin: 20px 0; display: flex; gap: 10px; }
        button {
          padding: 10px 20px;
          font-size: 16px;
          cursor: pointer;
          border: none;
          border-radius: 5px;
          color: white;
        }
        .add-btn { background: #28a745; }
        .add-btn:hover { background: #218838; }
        .refresh-btn { background: #007bff; }
        .refresh-btn:hover { background: #0056b3; }
        .reset-btn { background: #dc3545; }
        .reset-btn:hover { background: #c82333; }
        button:disabled { opacity: 0.6; cursor: not-allowed; }
        .event { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .risk-high { border-left: 5px solid #dc3545; }
        .risk-medium { border-left: 5px solid #ffc107; }
        .risk-low { border-left: 5px solid #28a745; }
        .risk-badge { 
          display: inline-block; padding: 2px 8px; border-radius: 10px; 
          font-size: 12px; font-weight: bold; color: white; margin-left: 8px;
        }
        .badge-high { background: #dc3545; }
        .badge-medium { background: #ffc107; color: #333; }
        .badge-low { background: #28a745; }
        .status { padding: 10px; margin: 10px 0; border-radius: 5px; display: none; }
        .status.show { display: block; }
        .status.success { background: #d4edda; color: #155724; }
        .status.error { background: #f8d7da; color: #721c24; }
      </style>
    </head>
    <body>
      <h1>PirateShield Events</h1>

      <div class="controls">
        <button class="add-btn" onclick="addEvents()">Add 5 Events</button>
        <button class="refresh-btn" onclick="location.reload()">Refresh</button>
        <button class="reset-btn" onclick="resetEvents()">Reset</button>
      </div>

      <div id="status" class="status"></div>

      <p><strong>Total Events:</strong> ${events.length}</p>

      <div id="events">
        ${events.length === 0
          ? '<p style="color: #999;">No events have been created yet, click "Add 5 Events" to generate data</p>'
          : events.map(e => {
              const score = calculateRiskScore(e);
              const riskClass = score >= 60 ? 'risk-high' : score >= 30 ? 'risk-medium' : 'risk-low';
              const badgeClass = score >= 60 ? 'badge-high' : score >= 30 ? 'badge-medium' : 'badge-low';
              return `
                <div class="event ${riskClass}">
                  <strong>${e.user_id}</strong> | <strong>${e.event_id}</strong> - ${e.timestamp}
                  <span class="risk-badge ${badgeClass}">Risk: ${score}</span><br>
                  ${e.source_ip} → ${e.destination_ip}:${e.destination_port} (${e.protocol}) | [${e.lat}, ${e.long}]<br>
                  Device: ${e.device_id} | Sent: ${e.bytes_sent.toLocaleString()} | Received: ${e.bytes_received.toLocaleString()}<br>
                  User Known Devices: ${e.user_known_devices}
                </div>
              `;
            }).join('')
        }
      </div>

      <script>
        function showStatus(message, type) {
          const status = document.getElementById('status');
          status.textContent = message;
          status.className = 'status show ' + type;
          setTimeout(() => { status.className = 'status'; }, 3000);
        }

        async function addEvents() {
          const btn = event.target;
          btn.disabled = true;
          btn.textContent = 'Generating...';

          try {
            const response = await fetch('/api/add', { method: 'POST' });
            const data = await response.json();

            if (data.success) {
              showStatus('Added 5 new events!', 'success');
              setTimeout(() => location.reload(), 1000);
            } else {
              showStatus('Failed to generate events', 'error');
              btn.disabled = false;
              btn.textContent = 'Add 5 Events';
            }
          } catch (error) {
            showStatus('Error: ' + error.message, 'error');
            btn.disabled = false;
            btn.textContent = 'Add 5 Events';
          }
        }

        async function resetEvents() {
          if (!confirm('Are you sure you want to delete all events? This cannot be undone.')) return;

          try {
            const response = await fetch('/api/reset', { method: 'POST' });
            const data = await response.json();

            if (data.success) {
              showStatus('All events deleted', 'error');
              setTimeout(() => location.reload(), 1000);
            }
          } catch (error) {
            showStatus('Error: ' + error.message, 'error');
          }
        }
      </script>
    </body>
    </html>
  `);
});

app.post('/api/add', (req, res) => {
  const python = spawn('python3', ['scripts/generate_network_events.py']);

  python.on('close', (code) => {
    if (code !== 0) {
      return res.status(500).json({ success: false, message: 'Failed to generate events' });
    }

    const filePath = path.join(__dirname, 'data', 'synthetic_network_events.json');
    try {
      const all: NetworkEvent[] = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      const newest = all.slice(-5);

      const stmt = db.prepare(`
        INSERT INTO network_events
          (event_id, user_id, timestamp, source_ip, destination_ip, destination_port,
           protocol, bytes_sent, bytes_received, device_id, event_type, payload, risk_score)
        VALUES
          (@event_id, @user_id, @timestamp, @source_ip, @destination_ip, @destination_port,
           @protocol, @bytes_sent, @bytes_received, @device_id, @event_type, @payload, @risk_score)
      `);

      for (const event of newest) {
        const risk_score = calculateRiskScore(event);
        stmt.run({
          event_id:         event.event_id         ?? null,
          user_id:          event.user_id          ?? null,
          timestamp:        event.timestamp        ?? new Date().toISOString(),
          source_ip:        event.source_ip        ?? null,
          destination_ip:   event.destination_ip   ?? null,
          destination_port: event.destination_port ?? null,
          protocol:         event.protocol         ?? null,
          bytes_sent:       event.bytes_sent       ?? null,
          bytes_received:   event.bytes_received   ?? null,
          device_id:        event.device_id        ?? null,
          event_type:       event.event_type       ?? null,
          payload:          JSON.stringify(event),
          risk_score,
        });
      }

      res.json({ success: true, message: 'Events generated and ingested' });
    } catch (err) {
      res.status(500).json({ success: false, message: 'Failed to ingest events into DB' });
    }
  });

  python.on('error', (error) => {
    res.status(500).json({ success: false, message: error.message });
  });
});

app.post('/api/reset', (req, res) => {
  const filePath = path.join(__dirname, 'data', 'synthetic_network_events.json');

  try {
    fs.writeFileSync(filePath, JSON.stringify([], null, 2));

    db.prepare('DELETE FROM network_events').run();
    db.prepare("DELETE FROM sqlite_sequence WHERE name='network_events'").run();

    res.json({ success: true, message: 'Events reset' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to reset events' });
  }
});

app.post('/ingest', (req, res) => {
  const event: Partial<NetworkEvent> = req.body;

  if (!event || typeof event !== 'object') {
    return res.status(400).json({ error: 'Invalid event payload' });
  }

  const risk_score = calculateRiskScore(event);

  const stmt = db.prepare(`
    INSERT INTO network_events
      (event_id, user_id, timestamp, source_ip, destination_ip, destination_port,
       protocol, bytes_sent, bytes_received, device_id, event_type, payload, risk_score)
    VALUES
      (@event_id, @user_id, @timestamp, @source_ip, @destination_ip, @destination_port,
       @protocol, @bytes_sent, @bytes_received, @device_id, @event_type, @payload, @risk_score)
  `);

  const result = stmt.run({
    event_id:         event.event_id         ?? null,
    user_id:          event.user_id          ?? null,
    timestamp:        event.timestamp        ?? new Date().toISOString(),
    source_ip:        event.source_ip        ?? null,
    destination_ip:   event.destination_ip   ?? null,
    destination_port: event.destination_port ?? null,
    protocol:         event.protocol         ?? null,
    bytes_sent:       event.bytes_sent       ?? null,
    bytes_received:   event.bytes_received   ?? null,
    device_id:        event.device_id        ?? null,
    event_type:       event.event_type       ?? null,
    payload:          JSON.stringify(event),
    risk_score,
  });

  res.status(201).json({
    message: 'Event ingested successfully',
    id: result.lastInsertRowid,
    risk_score,
  });
});

app.get('/api/db-events', (req, res) => {
  const events = db.prepare('SELECT * FROM network_events ORDER BY created_at DESC LIMIT 100').all();
  res.json(events);
});

app.listen(PORT, () => {
  console.log(`PirateShield running at http://localhost:${PORT}`);
});