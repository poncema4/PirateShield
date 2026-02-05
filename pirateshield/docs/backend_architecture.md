## Overview

The system is modular and extensible, allowing new rules and analysis components to be added over time

---

## Architecture Flow

```
[ client / agent ]
        |
        v
    POST/ingest
        |
        v
[ Ingestion API / Fast API ]
        |
        v
[ Raw Event Storage ]
        |
        v
[ Risk Scoring Engine ]
        |
        v
[ Risk Scores / Alerts ]
```

---

## Ingestion API:

- Exposes a REST endpoint (/ingest)
- Accepts JSON-formatted network events
- Performs basic validation
- Stores events for later analysis

---

## Event Storage:

- Stores raw, unmodified events
- Enables replay, auditing, and future rule improvements
- Database choices we have: SQlite (development), PostgreSQL (production)

---

## Risk Scoring Engine:

- Processes stored events
- Applies anomaly detection rules
- Assigns risk scores based on severity
- Designed to be modular so new rules can be added easily

---

## Design Goals:

- Simple and extensible
- Rule-driven analysis
- Separation between ingestion, storage, and analysis
- Suitable for real-time or batch processing