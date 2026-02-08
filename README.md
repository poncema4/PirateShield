# PirateShield

## Feb 1 – Feb 15 (Marco Ponce)
- Backend architecture design
- Unified event schema
- Network anomaly rules (v1)
- Synthetic network event data

## Getting Started

### Prerequisites
- Node.js (v18 or higher)
- Python 3

### Installation

1. Clone the repository and navigate to the project folder:
```bash
cd pirateshield
```

2. Install dependencies:
```bash
npm install
```

### Running the Project

To start the development server:
```bash
npm run dev
```

This will:
1. Generate synthetic network events using the Python script
2. Start the local server at `http://localhost:3000`

### Viewing the Data

Open your browser and go to:
```
http://localhost:3000
```

You will see all the generated network events. Click the "Refresh" button to generate 5 more events and append them to the existing data

### Project Structure
```
pirateshield/
├── data/                              # Generated synthetic events
│   └── synthetic_events.json
├── docs/                              # Documentation
├── scripts/                           # Python scripts
│   └── generate_synthetic_events_test.py
├── package.json                       # Node.js dependencies
└── server.ts                          # TypeScript server
```

### Troubleshooting

If you encounter issues:
- Make sure Python 3 is installed: `python3 --version`
- If the data folder does not exist, it will be created automatically
- Delete `data/synthetic_events.json` to start fresh