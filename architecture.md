# NetGuard IDS — Architecture

## System Flow

```
[Network Interface]
        |
        | (raw packets via Scapy)
        v
[IDS Engine — ids_engine.py]
        |
        |—— Rule-Based Detection (fast, signature matching)
        |      • DDoS:        pps > threshold
        |      • Port Scan:   unique_ports > 20 in 1s
        |      • Brute Force: high rate on port 22/3389
        |      • DNS Flood:   high rate on port 53
        |
        |—— ML Detection (Isolation Forest)
        |      • Feature extraction (8 numerical features)
        |      • Anomaly score from trained model
        |      • Attack type heuristic classification
        |
        v
[Alert Generated]
        |
        |—— Saved to MongoDB (database.py)
        |—— Auto-block IP (if severity CRITICAL/HIGH and auto_block=ON)
        |
        v
[Flask API — app.py]
        |  GET /api/alerts
        |  GET /api/stats
        |  GET /api/traffic
        |  POST /api/block
        |  GET/POST /api/settings
        v
[React Dashboard — App.jsx]
        |
        |—— Dashboard tab    (live charts, stats)
        |—— Attacks tab      (filtered alert table)
        |—— Logs tab         (searchable log view)
        |—— Settings tab     (toggle ML, thresholds)
        |—— AI Chat tab      (Claude API chatbot)
```

## ML Pipeline

```
Raw Packet
    |
    v
Feature Extraction
    • pkt_size, protocol, src_port, dst_port
    • packets_per_sec, unique_ports
    • has_payload, tcp_flags
    |
    v
StandardScaler (normalize features)
    |
    v
Isolation Forest (unsupervised anomaly detection)
    • contamination = 0.05 (5% expected anomalies)
    • n_estimators = 200
    |
    v
Anomaly Score
    |
    v
Attack Type Classification (rule + score heuristics)
    |
    v
Severity Assignment (LOW / MEDIUM / HIGH / CRITICAL)
```

## Cloud Deployment (AWS)

```
Internet
    |
    v
[AWS Route 53] — DNS
    |
    v
[CloudFront CDN] — static assets
    |
    v
[EC2 Instance] — Flask backend (gunicorn)
    • Ubuntu 22.04 LTS
    • t2.medium (2 vCPU, 4GB RAM)
    • Security Group: port 5000 open
    |
    v
[MongoDB Atlas] — cloud database
    • M0 Free Tier for testing
    • M10+ for production
```
