import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn } from 'child_process';

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

app.use(express.json());

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
        ${events.length === 0 ? '<p style="color: #999;">No events have been created yet, "Add 5 Events" to generate data</p>' : 
          events.map(e => `
            <div class="event">
              <strong>${e.event_id}</strong> - ${e.timestamp}<br>
              ${e.source_ip} → ${e.destination_ip}:${e.destination_port} (${e.protocol})<br>
              Device: ${e.device_id} | Sent: ${e.bytes_sent.toLocaleString()} | Received: ${e.bytes_received.toLocaleString()}
            </div>
          `).join('')
        }
      </div>

      <script>
        function showStatus(message, type) {
          const status = document.getElementById('status');
          status.textContent = message;
          status.className = 'status show ' + type;
          setTimeout(() => {
            status.className = 'status';
          }, 3000);
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
          if (!confirm('Are you sure you want to delete all events? This cannot be undone.')) {
            return;
          }

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

// API endpoint to add events
app.post('/api/add', (req, res) => {
  const python = spawn('python3', ['scripts/generate_synthetic_events_test.py']);
  
  python.on('close', (code) => {
    if (code === 0) {
      res.json({ success: true, message: 'Events generated' });
    } else {
      res.status(500).json({ success: false, message: 'Failed to generate events' });
    }
  });

  python.on('error', (error) => {
    res.status(500).json({ success: false, message: error.message });
  });
});

// API endpoint to reset events
app.post('/api/reset', (req, res) => {
  const filePath = path.join(__dirname, 'data', 'synthetic_events.json');
  
  try {
    fs.writeFileSync(filePath, JSON.stringify([], null, 2));
    res.json({ success: true, message: 'Events reset' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to reset events' });
  }
});

app.listen(PORT, () => {
  console.log(`PirateShield running at http://localhost:${PORT}`);
});