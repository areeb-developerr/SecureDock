# Secure Dock — Container Security Monitoring with Falco

Real-time container security monitoring system that uses **Falco** to detect malicious activity inside Docker containers and displays alerts on a live dashboard.

## Architecture

```
┌──────────────────┐    ┌─────────────┐    ┌─────────────┐    ┌──────────────┐
│  Docker Containers│───▷│    Falco     │───▷│   Backend   │───▷│   Frontend   │
│  (monitored)     │    │  (eBPF)     │    │  (Django)   │    │  (React)     │
└──────────────────┘    └─────────────┘    └─────────────┘    └──────────────┘
       syscalls          output.log        REST + WebSocket     Dashboard
```

**Flow:** Container syscalls → Falco detects via eBPF → Writes JSON to `output.log` → Backend ingests & classifies events → Frontend displays real-time alerts

## Project Structure

```
secure-dock/
├── attacks/                 # Attack & test scripts
├── backend/                 # Django REST API + WebSocket server
├── docker/                  # Docker Compose files + Falco rules
├── falco-logs/              # Falco runtime output logs
├── secure-dock-frontend/    # React + Vite dashboard
└── webapp/                  # Vulnerable Flask webapp (target)
```

## Prerequisites

- **Docker** and **Docker Compose**
- **Python 3.10+** with `venv`
- **Node.js 18+** and `npm`
- **Linux kernel with eBPF support** (tested on Kali 6.16)

---

## Quick Start

You need **5 terminals** to run the full stack. Follow each terminal setup below in order.

### Terminal 1 — Docker Containers + Falco

```bash
cd docker
docker compose up -d
```

This starts:
- `benign-nginx` — a safe nginx container (port 8888)
- `vulnerable-webapp` — a deliberately vulnerable Flask app (port 5000)
- `falco-monitor` — Falco with modern eBPF, monitoring all containers

Verify all are running:
```bash
docker compose ps
```

### Terminal 2 — Backend API Server

```bash
cd backend
source venv/bin/activate
python manage.py runserver
```

The Django REST API starts on `http://localhost:8000`. It serves container data, events, and alerts to the frontend.

### Terminal 3 — Falco Log Ingestor

```bash
cd backend
source venv/bin/activate
python manage.py ingest_falco_logs --log-file ../falco-logs/output.log --tail
```

This tails the Falco log file and:
- Parses each JSON event
- Classifies it as malicious or benign
- Saves it to the database
- Detects attack patterns (e.g., reconnaissance sprees)
- Broadcasts events to the frontend via WebSocket

### Terminal 4 — Frontend Dashboard

```bash
cd secure-dock-frontend
npm run dev
```

The React dashboard starts on `http://localhost:5173`. Open this in your browser.

### Terminal 5 — Run Tests

See the [Testing](#testing) section below for all available test scripts.

---

## Testing

All test scripts are in the `attacks/` directory.

### 1. Benign vs Malicious Comparison Test

The main demo script — proves the system correctly distinguishes safe containers from attacked ones.

```bash
cd attacks
bash test_benign_vs_malicious.sh
```

**What it does:**
- **Phase 1:** Sends normal HTTP requests and harmless file operations to `benign-nginx`
- **Phase 2:** Runs real attacks (shell spawn, file read, recon, binary write, web shell) on `vulnerable-webapp`

**Expected results on the frontend:**

| Container | Health | Malicious Events |
|-----------|--------|-----------------|
| `benign-nginx` | 🟢 Healthy | 0 |
| `vulnerable-webapp` | 🔴 Malicious | 5+ |

### 2. Benign Activity Only

Generates routine, non-malicious activity on the nginx container.

```bash
cd attacks
bash test_benign_nginx.sh
```

**What it does:**
- Sends 10 HTTP GET requests to nginx
- Performs 8 harmless in-container file operations (touch, cp, mv, rm)
- All events are classified as `INFO` priority (benign)

### 3. Individual Attack Tester

Interactive menu to run one attack at a time on any container.

```bash
cd attacks
bash test_single_attack.sh
```

**Available attacks:**

| # | Attack Type | Falco Rule Triggered | Priority |
|---|-------------|---------------------|----------|
| 1 | Shell Spawning | Shell Spawned in Container | Warning |
| 2 | Sensitive File Read | Read sensitive file untrusted | Warning |
| 3 | Reconnaissance Tools | Reconnaissance Tool Execution | Notice |
| 4 | Write to Binary Dir | System Binary Modification | Critical |
| 5 | Privilege Escalation | PrivEsc Tool Executed | Notice |
| 6 | Web Shell Upload | Script Written to Webroot | Warning |
| 7 | Container Escape | Container Management Tool | Warning |
| 8 | Log Tampering | Log File Tampering | Warning |

### 4. Run All Attacks

Runs all attack scripts sequentially and displays Falco log analysis.

```bash
cd attacks
bash run_all_attacks.sh
```

### 5. Python Attack Suites

Targeted attacks against specific containers:

```bash
cd attacks
python3 falco_detectable_attacks.py     # System-level attacks
python3 benign_requests.py              # Normal web traffic
python3 sql_injection.py                # SQL injection
python3 path_traversal.py               # Path traversal
python3 brute_force.py                  # Brute force login
python3 command_injection.py            # Command injection
```

---

## Clearing Data for a Fresh Test

To reset everything and start a clean test:

```bash
# 1. Stop the ingestor (Ctrl+C in Terminal 3)

# 2. Clear the database
cd backend
source venv/bin/activate
python manage.py shell -c "
from monitoring.models import FalcoEvent, Alert
FalcoEvent.objects.all().delete()
Alert.objects.all().delete()
print('Database cleared')
"

# 3. Truncate the Falco log
sudo truncate -s 0 falco-logs/output.log

# 4. Restart the ingestor (Terminal 3)
python manage.py ingest_falco_logs --log-file ../falco-logs/output.log --tail
```

---

## Falco Custom Rules

Custom detection rules are defined in `docker/falco_rules_custom.yaml`:

| Rule | Description | Priority |
|------|-------------|----------|
| Shell Spawned in Container | Shell process (sh/bash) spawned | Warning |
| Sensitive File Read | Reads /etc/shadow, sudoers, SSH keys | Warning |
| Write to Binary Directory | Writes to /bin, /sbin, /usr/bin | Critical |
| Crypto Miner Binary Execution | Known crypto miner binaries | Critical |
| Outbound Connection Detected | Network connections from container | Notice |
| Reconnaissance Tool Execution | whoami, id, uname, ps, etc. | Notice |
| Privileged Component Execution | mount, nsenter, docker | Warning |
| Log File Modification | Writing/deleting log files | Warning |
| Write to Webroot | Script files in web directories | Warning |
| Bulk File Renaming or Deletion | Mass file rename/delete operations | Info |
| Timestomping Detected | touch command usage | Info |

---

## Event Classification

Events are classified based on Falco priority:

| Priority | Classification | Description |
|----------|---------------|-------------|
| Critical | 🔴 Malicious | Severe threats (binary planting, crypto mining) |
| Error | 🔴 Malicious | System errors indicating attacks |
| Warning | 🟠 Malicious | Active attacks (shell spawn, file reads) |
| Notice | 🟡 Malicious | Suspicious activity (recon, priv esc) |
| Info | 🟢 Benign | Routine operations (file ops, housekeeping) |

---

## Tech Stack

- **Monitoring:** Falco (modern eBPF engine)
- **Backend:** Django, Django REST Framework, Django Channels (WebSocket)
- **Frontend:** React, Vite, TypeScript
- **Database:** SQLite
- **Container Runtime:** Docker, Docker Compose