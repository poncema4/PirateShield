import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

interface NetworkEvent {
  event_id: string;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  destination_port: number;
  protocol: string;
  bytes_sent: number;
  bytes_received: number;
  device_id: string;
  event_type: string;
}

app.get('/', (req, res) => {
  const filePath = path.join(__dirname, 'data', 'synthetic_events.json');
  
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
        button { padding: 10px 20px; font-size: 16px; cursor: pointer; }
        .event { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
      </style>
    </head>
    <body>
      <h1>PirateShield Events</h1>
      <button onclick="location.reload()">Refresh</button>
      <p>Total Events: ${events.length}</p>
      <div id="events">
        ${events.map(e => `
          <div class="event">
            <strong>${e.event_id}</strong> - ${e.timestamp}<br>
            ${e.source_ip} → ${e.destination_ip}:${e.destination_port} (${e.protocol})<br>
            Device: ${e.device_id} | Sent: ${e.bytes_sent} | Received: ${e.bytes_received}
          </div>
        `).join('')}
      </div>
    </body>
    </html>
  `);
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});