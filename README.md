# 🛡️ SentinelSOC

### Unified Cyber Defense & Mini-SOC Platform

SentinelSOC is a Python-based Security Operations Center (SOC) platform designed to simulate an end-to-end security monitoring and incident detection workflow.

The system ingests security telemetry, normalizes events, detects suspicious activity, correlates multiple alerts into incidents, calculates risk, enriches incidents with MITRE ATT&CK information, recommends response actions, persists security data in SQLite, and exposes the results through a FastAPI backend and SOC dashboard.

---

## 🚀 Project Overview

Traditional security monitoring often produces large numbers of individual alerts that analysts must manually investigate.

SentinelSOC addresses this problem by building a simplified SOC pipeline:

```text
Security Logs
     │
     ▼
┌─────────────────────┐
│  Event Collection   │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Parsing & Normalize │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Detection Manager   │
│                     │
│ • Brute Force       │
│ • Password Spray    │
│ • Port Scan         │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Alert Correlation   │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Risk Scoring Engine │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Threat Intelligence │
│ & MITRE ATT&CK      │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Response Engine     │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ SQLite Persistence  │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ FastAPI REST API    │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ SOC Dashboard       │
└─────────────────────┘
```

---

# 🔥 Key Features

## 1. Multi-Source Security Event Ingestion

SentinelSOC can collect security events from multiple log sources.

Supported telemetry includes:

- Linux authentication logs
- Firewall/network connection logs
- Port scanning activity
- Attack-chain simulation logs

The ingestion pipeline separates raw log collection from parsing and detection.

---

## 2. Normalized Security Event Schema

Raw security logs are converted into a common security event structure.

Events can contain fields such as:

- Timestamp
- Source
- Event type
- Severity
- Source IP
- Source port
- Destination IP
- Destination port
- Username
- Protocol
- Action
- Raw log
- Message
- Metadata

This allows different security telemetry sources to be processed consistently by the detection engine.

---

# 🔍 Detection Capabilities

SentinelSOC currently contains three primary detection capabilities.

## Brute-Force Detection

Detects repeated authentication failures from a source within a configured time window.

Example scenario:

```text
192.168.1.70
      │
      ├── Failed login
      ├── Failed login
      ├── Failed login
      ├── Failed login
      └── Failed login
              │
              ▼
       Brute-Force Alert
```

The current detector uses a threshold-based approach over a time window.

---

## Password-Spray Detection

Detects authentication attempts where a single source targets multiple user accounts.

Example:

```text
192.168.1.70
      │
      ├── admin
      ├── user1
      ├── user2
      ├── user3
      └── user4
              │
              ▼
       Password Spray
```

This helps distinguish password spraying from attacks focused on a single account.

---

## Port-Scan Detection

Detects a source IP probing multiple destination ports within a configured time window.

Example:

```text
192.168.1.70
      │
      ├── :21
      ├── :22
      ├── :23
      ├── :25
      ├── :53
      ├── :80
      ├── :443
      └── :445
              │
              ▼
          Port Scan
```

The detector identifies multiple unique destination ports from the same source.

---

# 🔗 Alert Correlation

One of the core features of SentinelSOC is **security alert correlation**.

Instead of treating every detection as an isolated event, the correlation engine looks for relationships between alerts and underlying security events.

For example:

```text
Port Scan
    +
Brute Force
    +
Successful Login
    │
    ▼
Attack Chain
    │
    ▼
High/Critical Risk Incident
```

This provides better context for security analysts than individual alerts alone.

The correlation engine also supports successful authentication following failed authentication attempts, allowing the system to identify potentially successful brute-force activity.

---

# ⚠️ Risk Scoring

SentinelSOC includes a risk scoring engine that combines multiple pieces of evidence.

Risk factors include:

- Attack type
- Successful authentication
- Failed authentication count
- Source IP correlation
- Username correlation
- Number of targeted users
- Number of destination ports
- High-volume reconnaissance
- Combined attack activity

The resulting score is normalized to a maximum of:

```text
100
```

Severity is then assigned based on the calculated risk.

```text
Risk Score     Severity
-----------    --------
0 - 29         LOW
30 - 59        MEDIUM
60 - 79        HIGH
80 - 100       CRITICAL
```

This allows the SOC dashboard to prioritize incidents according to their potential impact.

---

# 🎯 MITRE ATT&CK Mapping

SentinelSOC enriches detected incidents with MITRE ATT&CK information.

Current attack scenarios include techniques related to:

### T1046 — Network Service Scanning

Used to represent reconnaissance through scanning of network services and ports.

### T1110 — Brute Force

Used to represent repeated authentication attempts and credential attacks.

MITRE enrichment allows incidents to be viewed from an adversary-behavior perspective rather than only from raw log activity.

---

# 🚨 Incident Response Engine

After an incident is generated, SentinelSOC produces recommended response actions based on the incident's severity and type.

Example:

```text
Incident
   │
   ▼
Risk Assessment
   │
   ▼
Severity Classification
   │
   ▼
Response Recommendation
```

For critical incidents, the system can recommend escalation to the security operations team.

The response engine is designed as a recommendation layer rather than automatically executing destructive security actions.

---

# 💾 Security Data Persistence

SentinelSOC uses **SQLite** for local security data persistence.

The database stores information related to:

### Events

Normalized security telemetry.

### Alerts

Detection results generated by the detection engine.

### Incidents

Correlated security incidents with risk and enrichment data.

### Response Actions

Recommended response actions associated with incidents.

The persistence layer also uses deterministic hashing to help prevent duplicate event, alert, and incident records.

---

# 🌐 FastAPI Backend

SentinelSOC exposes security data through a REST API built using FastAPI.

## Main Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | API information |
| `/api/health` | GET | Health check |
| `/api/incidents` | GET | Retrieve incidents |
| `/api/incidents/{incident_id}` | GET | Retrieve a specific incident |
| `/api/incidents/{incident_id}/status` | PATCH | Update incident status |
| `/api/events` | GET | Retrieve security events |
| `/api/alerts` | GET | Retrieve generated alerts |
| `/api/statistics` | GET | Retrieve SOC statistics |
| `/api/summary` | GET | Retrieve dashboard summary |

Interactive API documentation is available through FastAPI's documentation interface.

When running locally:

```text
http://127.0.0.1:8000/docs
```

---

# 📊 SOC Dashboard

SentinelSOC includes a web-based SOC dashboard that consumes data from the FastAPI backend.

The dashboard provides visibility into:

- API status
- Total events
- Total alerts
- Total incidents
- Open incidents
- Incident severity
- Security events
- Detection alerts
- Incident details
- Incident status

The dashboard is designed to provide a simplified analyst-facing view of the detection pipeline.

---

# 🧪 Attack-Chain Demonstration

SentinelSOC includes an attack-chain simulation combining network reconnaissance and authentication activity.

A sample scenario contains:

```text
Source IP: 192.168.1.70
```

The simulated activity includes:

```text
1. Network connection attempts
        ↓
2. Multiple destination ports
        ↓
3. Port-scan detection
        ↓
4. Multiple failed SSH authentication attempts
        ↓
5. Brute-force detection
        ↓
6. Successful authentication
        ↓
7. Alert correlation
        ↓
8. Attack-chain incident
        ↓
9. Risk scoring
        ↓
10. MITRE enrichment
        ↓
11. Response recommendation
```

Example engine result:

```text
========== SENTINELSOC ENGINE ==========

Parsed events: 14
Alerts generated: 2
Incidents correlated: 1

========== INCIDENTS ==========

[CRITICAL] attack_chain
Source: 192.168.1.70
Risk: 100

Attack types:
['brute_force', 'port_scan']

Response:
Escalate incident to the security operations team

========== COMPLETE ==========
```

This demonstrates how multiple low-level security events can be transformed into a higher-level security incident.

---

# 🧪 Testing

SentinelSOC includes automated tests for the detection and correlation components.

Run the complete test suite:

```bash
python -m pytest -q
```

Current result:

```text
25 passed
```

The test suite validates important parts of the security pipeline including:

- Event processing
- Brute-force detection
- Password-spray detection
- Port-scan detection
- Detection management
- Alert correlation
- Attack-chain handling
- Risk scoring
- Incident processing
- Response behavior

---

# 📁 Project Structure

```text
SentinelSOC/
│
├── data/
│   └── samples/
│       ├── attack_chain.log
│       └── port_scan.log
│
├── dashboard/
│   ├── index.html
│   ├── app.js
│   └── styles.css
│
├── src/
│   │
│   ├── api/
│   │   └── main.py
│   │
│   ├── collector/
│   │   └── multi_source_collector.py
│   │
│   ├── database/
│   │   ├── database.py
│   │   └── incident_store.py
│   │
│   ├── detectors/
│   │   ├── brute_force_detector.py
│   │   ├── password_spray_detector.py
│   │   ├── port_scan_detector.py
│   │   └── detection_manager.py
│   │
│   ├── parser/
│   │   ├── linux_auth_parser.py
│   │   ├── network_parser.py
│   │   └── parser_router.py
│   │
│   ├── engine/
│   │   └── ...
│   │
│   ├── intelligence/
│   │   └── ...
│   │
│   ├── response/
│   │   └── ...
│   │
│   └── utils/
│       └── event_schema.py
│
├── tests/
│   └── ...
│
├── requirements.txt
├── README.md
└── .github/
    └── workflows/
        └── tests.yml
```

> The exact contents of some directories may evolve as SentinelSOC continues to be developed.

---

# ⚙️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core security processing |
| FastAPI | REST API |
| SQLite | Security data persistence |
| Pytest | Automated testing |
| HTML/CSS/JavaScript | SOC dashboard |
| Git | Version control |
| GitHub Actions | Continuous Integration |

---

# 🛠️ Installation

## 1. Clone the Repository

```bash
git clone <YOUR-GITHUB-REPOSITORY-URL>
cd SentinelSOC
```

---

## 2. Create a Virtual Environment

```bash
python -m venv venv
```

Activate it on Windows Git Bash:

```bash
source venv/Scripts/activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

# ▶️ Running SentinelSOC

## Run the Security Engine

From the project root:

```bash
python -m src.engine
```

This processes the configured security event sources and generates:

```text
Events
   ↓
Alerts
   ↓
Incidents
   ↓
Risk
   ↓
MITRE Intelligence
   ↓
Response Recommendations
```

---

# 🌐 Start the API

Run:

```bash
uvicorn src.api.main:app --reload
```

The API will be available at:

```text
http://127.0.0.1:8000
```

Interactive API documentation:

```text
http://127.0.0.1:8000/docs
```

---

# 📊 Start the Dashboard

Open a second terminal.

Navigate to the dashboard:

```bash
cd dashboard
```

Start the local web server:

```bash
python -m http.server 5500
```

Open:

```text
http://127.0.0.1:5500
```

The dashboard communicates with the FastAPI backend to display stored SOC data.

---

# 🔄 Complete Local Workflow

For a complete demonstration:

### Terminal 1

```bash
cd SentinelSOC
source venv/Scripts/activate
python -m src.engine
```

### Terminal 2

```bash
cd SentinelSOC
source venv/Scripts/activate
uvicorn src.api.main:app --reload
```

### Terminal 3

```bash
cd SentinelSOC/dashboard
python -m http.server 5500
```

Then open:

```text
http://127.0.0.1:5500
```

---

# 🔐 Security Architecture

SentinelSOC follows a layered detection architecture:

```text
                 ┌──────────────────┐
                 │ Security Sources │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │    Collector     │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │     Parser       │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │ Detection Engine │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │    Correlation   │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │   Risk Engine    │
                 └────────┬─────────┘
                          │
                          ▼
              ┌────────────────────────┐
              │ MITRE / Intelligence   │
              └────────────┬───────────┘
                           │
                           ▼
                 ┌──────────────────┐
                 │ Response Engine  │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │ SQLite Database  │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │    FastAPI       │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │  SOC Dashboard   │
                 └──────────────────┘
```

---

# 🧠 Design Principles

SentinelSOC was developed around several security engineering principles:

### Normalization

Different log sources should be converted into a common event representation.

### Detection Separation

Individual detection techniques are implemented independently and managed through a central detection manager.

### Correlation

Multiple alerts should be analyzed together to identify broader attack activity.

### Risk-Based Prioritization

Incidents should be prioritized according to accumulated security evidence.

### Explainability

Risk scores include reasons explaining why an incident received its severity.

### Persistence

Security events, alerts, incidents, and response information should remain available for investigation.

### Analyst-Centric Response

The response engine provides recommendations instead of automatically executing potentially destructive actions.

---

# 🔬 Example Detection Scenario

Consider the following activity:

```text
192.168.1.70
       │
       ├── TCP :21
       ├── TCP :22
       ├── TCP :23
       ├── TCP :25
       ├── TCP :53
       ├── TCP :80
       ├── TCP :443
       └── TCP :445
```

The port-scan detector identifies reconnaissance.

The same source then produces:

```text
Failed SSH authentication
Failed SSH authentication
Failed SSH authentication
Failed SSH authentication
Failed SSH authentication
Successful SSH authentication
```

SentinelSOC correlates the activity into a broader incident.

```text
Network Reconnaissance
        +
Credential Attack
        +
Successful Authentication
        │
        ▼
   Attack Chain
        │
        ▼
 Critical Incident
```

This demonstrates the difference between simple alert generation and security-event correlation.

---

# 📈 Current Project Status

### Completed

- [x] Security event schema
- [x] Linux authentication parsing
- [x] Network telemetry parsing
- [x] Multi-source collection
- [x] Brute-force detection
- [x] Password-spray detection
- [x] Port-scan detection
- [x] Detection manager
- [x] Alert correlation
- [x] Attack-chain detection
- [x] Risk scoring
- [x] MITRE ATT&CK enrichment
- [x] Incident response recommendations
- [x] SQLite persistence
- [x] Event/alert/incident deduplication
- [x] FastAPI backend
- [x] SOC dashboard
- [x] Automated testing
- [x] GitHub Actions CI

### Test Status

```text
25 tests passed
```

---

# 🔮 Future Improvements

Potential future development includes:

- Real-time log streaming
- Windows Event Log ingestion
- Syslog ingestion
- Additional authentication detectors
- Suspicious process detection
- Malware indicator matching
- IP reputation enrichment
- Threat intelligence API integration
- Advanced behavioral correlation
- Analyst authentication and role-based access
- Alert acknowledgement workflow
- Incident investigation timeline
- Production database support
- Containerized deployment
- Cloud deployment
- Automated response playbooks

---

# ⚠️ Project Scope

SentinelSOC is an educational and portfolio-oriented SOC simulation platform.

The current implementation primarily processes simulated/sample security telemetry and demonstrates the architecture and engineering principles of a security monitoring platform.

It is **not intended to replace a production SIEM, EDR, SOAR, or enterprise SOC platform**.

---

# 👨‍💻 Author

**Sundaram Yadav**

Cybersecurity / Software Engineering Portfolio Project

---

# ⭐ Project Goal

The goal of SentinelSOC is to demonstrate practical understanding of:

```text
Security Monitoring
        +
Log Analysis
        +
Detection Engineering
        +
Alert Correlation
        +
Risk Analysis
        +
Threat Intelligence
        +
Incident Response
        +
Backend Development
        +
Database Design
        +
Security Dashboard Development
        +
Automated Testing
```

SentinelSOC demonstrates how these components can be combined into a unified cybersecurity monitoring pipeline.

---

## 📜 License

This project is intended for educational, research, and portfolio purposes.