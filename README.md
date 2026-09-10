# AegisSOC — Unified Security Operations & Cyber Readiness Platform

> A production-grade, AI-augmented Security Operations Center (SOC) dashboard, Digital Forensics & Incident Response (DFIR) suite, Training Academy LMS, and Red vs. Blue CTF Arena.

---

## 📑 Table of Contents
1. [Overview](#overview)
2. [Working Architecture](#working-architecture)
3. [Key Modules & Capabilities](#key-modules--capabilities)
4. [Host Server Setup & Installation](#host-server-setup--installation)
5. [Syslog Collector Setup (Port 514 UDP/TCP)](#syslog-collector-setup-port-514-udptcp)
6. [Client & Network Device Configuration](#client--network-device-configuration)
   - [Cisco Switches & Routers](#1-cisco-switches--routers)
   - [Fortinet FortiGate Firewalls](#2-fortinet-fortigate-firewall)
   - [Palo Alto Networks NGFW](#3-palo-alto-networks-ngfw)
   - [Linux Servers (Ubuntu / Debian / RHEL)](#4-linux-servers-native-rsyslog)
   - [Windows Servers (Sysmon + NXLog / Winlogbeat)](#5-windows-servers)
7. [REST Ingestion API Reference](#rest-ingestion-api-reference)
8. [Pushing to Git Repository](#pushing-to-git-repository)
9. [Production Deployment (Systemd / Docker)](#production-deployment)

---

## 🌐 Overview

**AegisSOC** bridges the operational divide between live incident detection and workforce preparedness:
- **Live SOC Operations**: Real-time event correlation, MITRE ATT&CK mapping, active perimeter IOC blocklists, and dynamic 3D topology views.
- **Autonomous AI Copilot**: Powered by **Gemini 3.8 Flash** for instantaneous true/false positive classification, MITRE mapping, and automated containment runbook generation.
- **Microsecond DFIR Timeline**: Forensic artifact inspection (MFT, Prefetch, Registry, Process Memory hex dumps) and evidence tagging.
- **Continuous Cyber Readiness**: Converts sanitized real-world security incidents directly into hands-on **CTF Arena challenges** and **interactive LMS courses**.

---

## 🏗 Working Architecture

AegisSOC integrates directly into standard enterprise network architectures without requiring custom client code on network devices:

```
┌─────────────────────────┐  ┌─────────────────────────┐  ┌─────────────────────────┐
│   Core Switch & Router  │  │   Internet Firewall     │  │      DMZ Firewall       │
│   (Cisco / Arista / HP) │  │ (Fortinet / Palo Alto)  │  │    (PNS / Check Point)  │
└────────────┬────────────┘  └────────────┬────────────┘  └────────────┬────────────┘
             │                            │                            │
             │ (Syslog UDP/TCP 514)       │ (Syslog UDP/TCP 514)       │ (Syslog UDP/TCP 514)
             └────────────────────────────┼────────────────────────────┘
                                          ▼
                      ┌───────────────────────────────────────┐
                      │    YOUR LOG COLLECTOR / LINUX HOST    │
                      │                                       │
                      │  1. rsyslog / Vector daemon           │
                      │     Listening on Port 514 (UDP & TCP) │
                      │                   │                   │
                      │                   │ (Local HTTP POST) │
                      │                   ▼                   │
                      │  2. AegisSOC Backend (Port 3000)      │
                      │     Endpoint: /api/telemetry/ingest   │
                      └───────────────────┬───────────────────┘
                                          │
                      ┌───────────────────┴───────────────────┐
                      │                                       │
                      ▼                                       ▼
    ┌───────────────────────────────────┐   ┌───────────────────────────────────┐
    │     Autonomous AI Copilot Layer   │   │       Live SOC Web Dashboard      │
    │  - Gemini 3.8 Flash Triage Engine │   │  - Real-Time SSE Event Stream     │
    │  - MITRE ATT&CK Matrix Correlator │   │  - Alerts & Incident Management   │
    │  - Auto-generated Runbooks        │   │  - DFIR Forensic Artifacts        │
    └───────────────────────────────────┘   └───────────────────────────────────┘
                      │
                      ▼
    ┌───────────────────────────────────┐
    │     Training & CTF Cyber Arena    │
    │  - Interactive LMS Lessons        │
    │  - Live Red vs. Blue CTF Drills   │
    │  - Phishing Simulation Platform   │
    └───────────────────────────────────┘
```

---

## ⚡ Key Modules & Capabilities

| Module | Features |
| :--- | :--- |
| **SOC Operations** | Real-time alerts feed with one-click triage, IP/Domain/Hash IOC blocklist, 3D animated network topology, global threat map, and live EPS metrics. |
| **AI Security Hub** | Gemini 3.8 Flash copilot for log explanation, forensic query generator, attack scenario simulator, and automated containment playbook synthesis. |
| **DFIR Timeline** | High-precision forensic timeline, raw payload hex viewer, artifact categorization, and evidence tagging with exportable forensic audit reports. |
| **Training & LMS** | Interactive modular curriculum (SOC Ops, DFIR, Red Team, Cloud Security), video labs, knowledge quizzes, and simulated phishing campaigns. |
| **CTF Arena** | Multi-category jeopardy CTF (Web, Forensics, Reverse Engineering, Cryptography, OSINT, Pwn) with dynamic point decay, hints, and live leaderboards. |
| **Audit Reports** | Executive compliance summaries, NIST CSF 2.0 / ISO 27001 readiness scoring, MTTD/MTTR analytics, and PDF/JSON export. |

---

## 🚀 Host Server Setup & Installation

### Prerequisites
- **Operating System**: Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+, or CentOS Stream), macOS, or Windows Server.
- **Runtime**: Node.js **18.x** or higher and `npm`.
- **Docker + Docker Compose** (for the full production stack: PostgreSQL, Redis, nginx).

### 1. Clone & Install Dependencies
```bash
# Clone the repository
git clone <your-repository-url>
cd aegis-soc-platform

# Install project dependencies
npm install
```

### 2. Environment Configuration
Create an environment file:
```bash
cp .env.example .env
```
Edit `.env` to configure authentication and optional AI features:
```env
# Port (3000 in development; nginx exposes 80 in the Docker stack)
PORT=3000

# REQUIRED IN PRODUCTION — JWT signing secrets (openssl rand -base64 48)
JWT_ACCESS_SECRET=
JWT_REFRESH_SECRET=

# Persistence (leave unset to run with the zero-dependency in-memory store)
DATABASE_URL=postgres://aegis:aegis_dev_password@localhost:5432/aegis
REDIS_URL=redis://localhost:6379

# Optional: Enables Gemini 3.8 Flash autonomous triage & AI Copilot features
GEMINI_API_KEY=your_gemini_api_key_here

# Optional: static API key for machine log forwarders calling /api/telemetry/ingest
INGEST_API_KEY=
```

> **Persistence:** with `DATABASE_URL` set, the server provisions its schema and seed data automatically on first boot (users, alerts, IOCs, courses, CTF challenges, DFIR timeline, audit log — all stored in PostgreSQL). Without it, the app falls back to an in-memory store for local development (data resets on restart). `REDIS_URL` enables cross-replica SSE fan-out and shared rate limiting; both degrade gracefully when unreachable.

### Authentication & RBAC
All API endpoints require a JWT (15-minute access token, 7-day refresh token, scrypt-hashed passwords). Four roles are enforced server-side:

| Role | Username (seeded) | Capabilities |
| :--- | :--- | :--- |
| Admin | `admin` | Full control, audit log access |
| SOC Analyst | `analyst` | Alert triage, IOC management, CTF, AI copilot, ingest |
| Trainer | `trainer` | LMS content, phishing campaigns, CTF management |
| Viewer | `viewer` | Read-only dashboards |

Seeded passwords default to `ChangeMe_<Role>_2026!` (e.g. `ChangeMe_Admin_2026!`) and can be overridden via `SEED_*_PASSWORD` env vars. Every security-relevant action is written to an append-only audit trail (`GET /api/audit`, admin only) and streamed live over SSE.

**Machine ingestion (rsyslog / Vector):** set `INGEST_API_KEY` in `.env` and send it as the `x-api-key` header — no user token required. The AegisSOC UI's Syslog Ingest test view authenticates with your logged-in session instead.

**CTF integrity:** flags are never sent to the browser — submissions are validated server-side only.

**Per-user progress (Phase 2):** lesson completions, CTF solves, hint unlocks, and scores are tracked per user in PostgreSQL (`user_progress`, `user_solves`, `user_hints`, `users.score`). Two analysts see independent course progress and challenge states; CTF points are awarded once per user (hint penalties included) and the leaderboard ranks real platform users alongside seeded bot teams. Scores/solves are returned in login and `/api/auth/me` responses.

**Zero-training-data AI (Phase 3):** no ML training anywhere. Gemini output (triage verdicts, phishing analysis, CTF hints) is schema-validated with zod before it is trusted or persisted — invalid output falls back to deterministic engines. New `/api/ai/anomaly` runs rolling z-score anomaly detection on live telemetry; `/api/ai/correlate` clusters related alerts by MITRE technique + source IP within a time window; `/api/ai/ctf-hint` generates LLM nudges from public challenge metadata only (flags never enter prompts or responses). The email analyzer parses real SPF/DKIM/DMARC headers when no API key is configured.

### 3. Run Development Server
```bash
npm run dev
```
The application will be accessible at: `http://localhost:3000` (or `http://<YOUR_SERVER_IP>:3000`).

### 4. Production Build
```bash
# Compiles Vite frontend into dist/ and bundles backend into dist/server.cjs
npm run build

# Start production server (requires JWT_ACCESS_SECRET / JWT_REFRESH_SECRET in prod)
npm start
```

### 5. Docker Deployment (Recommended)
The Docker stack runs the whole platform — app, PostgreSQL, Redis, and an nginx reverse proxy (SSE-buffering disabled for live streams):

```bash
# One command: builds the image, starts Postgres + Redis + app + nginx
docker compose up -d --build

# The platform is now at http://localhost (nginx on port 80)

# Logs / status
make logs        # or: docker compose logs -f --tail=100
make ps          # or: docker compose ps

# Stop (keeps database volume)
docker compose down

# Stop AND wipe the database (fresh start)
make clean       # or: docker compose down -v
```

Environment for the stack is read from your shell (or a `.env` file in the repo root):

| Variable | Default in compose | Notes |
| :--- | :--- | :--- |
| `POSTGRES_PASSWORD` | `aegis_dev_password` | Set a strong value before first `up` |
| `JWT_ACCESS_SECRET` / `JWT_REFRESH_SECRET` | dev placeholders | **Set real values** (`openssl rand -base64 48`) |
| `INGEST_API_KEY` | — | API key for log forwarders |
| `GEMINI_API_KEY` | — | Enables AI copilot features |
| `SEED_*_PASSWORD` | `ChangeMe_<Role>_2026!` | Override seeded demo passwords |
| `HTTP_PORT` | `80` | Host port for nginx |

> **First boot** creates the schema and seeds demo data automatically. The container waits for PostgreSQL to be healthy, then the app connects, seeds, and serves. CTF flags remain server-side only; audit events are persisted to `audit_log` and streamed live.

---

## 📡 Syslog Collector Setup (Port 514 UDP/TCP)

To allow switches, firewalls, and servers to send logs directly without installing custom HTTP software, configure your host's native `rsyslog` daemon to accept logs on port 514 and forward them into AegisSOC.

### Option A: Native `rsyslog` (Pre-installed on Linux)

#### 1. Enable Port 514 Ingestion
Edit `/etc/rsyslog.conf`:
```bash
sudo nano /etc/rsyslog.conf
```
Uncomment or add:
```text
# Provides UDP syslog reception
module(load="imudp")
input(type="imudp" port="514")

# Provides TCP syslog reception
module(load="imtcp")
input(type="imtcp" port="514")
```

#### 2. Install HTTP Bridge Module & Create Forwarding Rule
Install the rsyslog HTTP module:
```bash
# Ubuntu / Debian
sudo apt-get update && sudo apt-get install -y rsyslog-omhttp

# RHEL / CentOS / Rocky Linux
sudo dnf install -y rsyslog-omhttp
```

Create `/etc/rsyslog.d/99-aegis-bridge.conf`:
```text
module(load="omhttp")

template(name="AegisJSON" type="string" 
  string="{\"source\":\"%HOSTNAME%\",\"title\":\"%syslogtag%\",\"description\":\"%msg:::json%\",\"severity\":\"%syslogseverity-text%\",\"asset\":\"%HOSTNAME%\"}")

action(
  type="omhttp"
  server="127.0.0.1"
  serverport="3000"
  restpath="api/telemetry/ingest"
  template="AegisJSON"
  action.resumeRetryCount="-1"
)
```

#### 3. Restart rsyslog
```bash
sudo systemctl restart rsyslog
```

---

### Option B: High-Performance Vector Container (Docker)

If you prefer running a containerized collector:

Create `docker-compose.yml`:
```yaml
version: '3.8'
services:
  syslog-collector:
    image: timberio/vector:0.38.X-alpine
    container_name: aegis-syslog-collector
    restart: always
    ports:
      - "514:514/udp"
      - "514:514/tcp"
    volumes:
      - ./vector.yaml:/etc/vector/vector.yaml:ro
```

Create `vector.yaml`:
```yaml
sources:
  network_syslog:
    type: "syslog"
    address: "0.0.0.0:514"
    mode: "udp"

transforms:
  format_soc:
    type: "remap"
    inputs: ["network_syslog"]
    source: |
      .source = .appname || "Syslog Device"
      .sourceIp = to_string(.host) || "10.0.0.1"
      .title = "Syslog: " + to_string(.appname || "Security Event")
      .description = to_string(.message)
      .severity = if .severity == "emergency" || .severity == "critical" { "critical" } else if .severity == "error" { "high" } else { "medium" }

sinks:
  aegis_api:
    type: "http"
    inputs: ["format_soc"]
    uri: "http://127.0.0.1:3000/api/telemetry/ingest"
    method: "post"
    encoding:
      codec: "json"
```

Start the container:
```bash
docker compose up -d
```

---

## 🛠 Client & Network Device Configuration

> Replace `10.0.0.50` with your actual AegisSOC server IP address.

### 1. Cisco Switches & Routers
Connect via SSH or console and run:
```cisco
configure terminal
logging on
logging host 10.0.0.50
logging trap warnings
logging facility local4
logging source-interface GigabitEthernet0/1
exit
write memory
```

### 2. Fortinet FortiGate Firewall
Run via CLI console:
```bash
config log syslogd setting
    set status enable
    set server "10.0.0.50"
    set mode udp
    set port 514
    set facility local7
    set format default
end
```
*Alternatively, in Web UI: **Log & Report → Log Settings → Remote Syslog Server**.*

### 3. Palo Alto Networks NGFW
In the PAN-OS Web GUI:
1. Navigate to **Device → Server Profiles → Syslog**.
2. Click **Add** → Name: `AegisSOC-Syslog`.
3. Under Servers, click **Add**:
   - Name: `AegisCollector`
   - Syslog Server: `10.0.0.50`
   - Port: `514`
   - Facility: `LOG_USER`
4. Navigate to **Objects → Log Forwarding** and attach the profile to your active Security Rules.
5. Click **Commit**.

### 4. Linux Servers (Native rsyslog)
Run this single command on your Ubuntu/Debian/RHEL servers:
```bash
echo "*.* @10.0.0.50:514" | sudo tee /etc/rsyslog.d/50-aegis-forward.conf
sudo systemctl restart rsyslog
```
Test sending a log:
```bash
logger -p auth.warn "AegisSOC test event from $(hostname)"
```

### 5. Windows Servers
Install **NXLog Community Edition** or **Winlogbeat**:
Edit `C:\Program Files\nxlog\conf\nxlog.conf`:
```text
define ROOT C:\Program Files\nxlog

Moduledir %ROOT%\modules
CacheDir %ROOT%\data
Pidfile %ROOT%\data\nxlog.pid
SpoolDir %ROOT%\data

<Extension _syslog>
    Module  xm_syslog
</Extension>

<Input in_eventlog>
    Module  im_msvistalog
</Input>

<Output out_syslog>
    Module  om_udp
    Host    10.0.0.50
    Port    514
    Exec    to_syslog_ietf();
</Output>

<Route 1>
    Path    in_eventlog => out_syslog
</Route>
```
Restart the NXLog Windows service.

---

## 🔌 REST Ingestion API Reference

### 1. Single or Batch Telemetry Ingestion
```http
POST /api/telemetry/ingest
Content-Type: application/json
```

**Payload**:
```json
{
  "severity": "critical",
  "title": "Cobalt Strike C2 Beaconing Detected",
  "description": "Repetitive 60s jitter beacons to suspicious domain c2-update-sync.xyz",
  "source": "Suricata NIDS / Core Sensor",
  "mitreTechnique": "T1071.004 - DNS Application Layer Protocol",
  "mitreTactic": "Command and Control",
  "sourceIp": "10.0.4.12",
  "destIp": "185.220.101.5",
  "asset": "DC-PROD-01"
}
```

**Response**:
```json
{
  "status": "accepted",
  "eventsReceived": 1,
  "alertGenerated": true,
  "alertId": "ALT-9602"
}
```

### 2. Live Server-Sent Events (SSE) Stream
```http
GET /api/events/stream
```
Connect your frontend or integration scripts to listen for real-time `alert:new` notifications.

---

## 📦 Pushing to Git Repository

Follow these standard commands to initialize and push your project to GitHub or GitLab:

```bash
# Initialize git (if not already initialized)
git init

# Stage all files
git add .

# Commit changes
git commit -m "feat: complete AegisSOC suite with syslog ingestion, AI triage, and CTF arena"

# Link your remote repository
git remote add origin https://github.com/<your-username>/<your-repo-name>.git

# Set main branch and push
git branch -M main
git push -u origin main
```

---

## 🛡 Production Deployment

### Running as a Systemd Service (Linux)
Create `/etc/systemd/system/aegis-soc.service`:
```ini
[Unit]
Description=AegisSOC Enterprise Platform
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/aegis-soc-platform
ExecStart=/usr/bin/npm start
Restart=on-failure
Environment=NODE_ENV=production
Environment=PORT=3000
Environment=GEMINI_API_KEY=your_gemini_api_key_here

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable aegis-soc
sudo systemctl start aegis-soc
sudo systemctl status aegis-soc
```

---

## 📄 License
This project is licensed under the MIT License — see the LICENSE file for details.
