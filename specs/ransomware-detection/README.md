# 🛡️ ACDS — Autonomous Cyber Defense System

A multi-agent AI-powered cybersecurity platform for automated threat detection and response.

---

## 📌 Project Overview

ACDS is an autonomous cyber defense system that uses machine learning and a multi-agent architecture to detect, analyze, and respond to cyber threats in real time. The system currently supports two threat detection modules:

- **Phishing Detection** — ML-based email phishing detection using TF-IDF + Logistic Regression
- **Ransomware Detection** — ML-based ransomware command detection using TF-IDF + Random Forest

---

## 🏗️ System Architecture

```
Frontend (React + Vite)
        ↓
Backend (FastAPI)
        ↓
API Routes (/api/v1/threats/  |  /api/v1/ransomware/)
        ↓
Orchestrator Agents (pipeline coordinators)
        ↓
Detection → Explainability → Response → Alert
        ↓
ML Models (scikit-learn)
        ↓
MongoDB (threat storage)
```

---

## 🚀 Getting Started

### Prerequisites
- Docker + Docker Compose
- Node.js 18+
- Python 3.10+

### Run with Docker

```bash
# Clone the repository
git clone https://github.com/sultan9723/ACDS-FYP.git
cd ACDS-FYP

# Start backend
docker compose up --build

# Start frontend (separate terminal)
cd frontend
npm install
npm run dev
```

### Access
- **Frontend:** http://localhost:5173
- **Backend API:** http://localhost:8000
- **API Docs:** http://localhost:8000/docs

---

## 📁 Project Structure

```
ACDS-FYP/
├── backend/
│   ├── main.py                          # FastAPI entry point
│   ├── agents/
│   │   ├── detection_agent.py           # Phishing detection agent
│   │   ├── explainability_agent.py      # Phishing explainability agent
│   │   ├── response_agent.py            # Phishing response agent
│   │   ├── orchestrator_agent.py        # Phishing orchestrator
│   │   ├── alert_agent.py               # Shared MongoDB alert agent
│   │   ├── ransomware_detection_agent.py
│   │   ├── ransomware_explainability_agent.py
│   │   ├── ransomware_response_agent.py
│   │   └── ransomware_orchestrator_agent.py
│   ├── ml/
│   │   ├── phishing_service.py
│   │   ├── preprocess.py
│   │   ├── ransomware_service.py
│   │   ├── ransomware_preprocess.py
│   │   └── models/
│   │       ├── phishing_model.pkl
│   │       └── ransomware_model.pkl
│   ├── ml_training/
│   │   ├── phishingmodel.ipynb
│   │   └── ransomware_model.ipynb
│   ├── api/routes/
│   │   ├── threats.py                   # Phishing endpoints
│   │   └── ransomware.py                # Ransomware endpoints
│   ├── database/
│   │   └── connection.py
│   └── config/
│       └── settings.py
└── frontend/
    ├── src/
    │   ├── pages/
    │   │   ├── Dashboard.jsx
    │   │   ├── PhishingModule.jsx
    │   │   └── RansomwareModule.jsx
    │   └── components/
    │       ├── Phishing/
    │       └── Ransomware/
    └── package.json
```

---

## 🔬 Ransomware Detection Module

### How It Works

The ransomware module uses a **4-stage multi-agent pipeline** to detect, explain, and respond to ransomware behavior in process commands:

```
Command Input
      ↓
Stage 1: Detection Agent     → ML model classifies command (ransomware/safe)
      ↓
Stage 2: Explainability Agent → Extracts IOCs, maps to MITRE ATT&CK
      ↓
Stage 3: Response Agent       → Executes automated response by severity
      ↓
Stage 4: Alert Agent          → Logs incident to MongoDB
```

### ML Model

| Property | Value |
|---|---|
| Algorithm | TF-IDF + Random Forest |
| Training Samples | ~10,000 |
| Features | 5,000 TF-IDF features (unigrams + bigrams) |
| Model File | `ml/models/ransomware_model.pkl` |

### Severity Levels

| Severity | Confidence | Response Actions |
|---|---|---|
| CRITICAL | ≥ 90% | Kill process + Isolate host + Block hash + Alert SOC |
| HIGH | ≥ 75% | Kill process + Block hash + Alert SOC |
| MEDIUM | ≥ 60% | Kill process + Alert SOC |
| LOW | ≥ 50% | Alert SOC only |

### Detected Behavior Categories

- Shadow copy deletion (`vssadmin`, `wbadmin`)
- Boot configuration tampering (`bcdedit`)
- Security service termination
- Persistence mechanisms
- Lateral movement
- Command obfuscation (Base64 PowerShell)
- Credential harvesting (`mimikatz`, `pwdump`)
- Ransom note creation

### MITRE ATT&CK Mapping

| Behavior | Tactic ID | Tactic Name |
|---|---|---|
| Shadow deletion | T1490 | Inhibit System Recovery |
| Boot modification | T1542 | Pre-OS Boot |
| Service kill | T1489 | Service Stop |
| Persistence | T1547 | Boot or Logon Autostart |
| Lateral movement | T1021 | Remote Services |
| Obfuscation | T1027 | Obfuscated Files or Information |
| Credential theft | T1003 | OS Credential Dumping |
| Ransom note | T1486 | Data Encrypted for Impact |

### API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/ransomware/scan` | Full pipeline scan |
| POST | `/api/v1/ransomware/scan/batch` | Batch scan |
| POST | `/api/v1/ransomware/scan/quick` | Quick detection only |
| POST | `/api/v1/ransomware/scan/explain` | Detection + explainability |
| GET | `/api/v1/ransomware/list` | List ransomware threats |
| GET | `/api/v1/ransomware/scans/list` | Scan history |
| GET | `/api/v1/ransomware/alerts` | MongoDB alerts |
| GET | `/api/v1/ransomware/stats` | Pipeline statistics |
| GET | `/api/v1/ransomware/health` | Health check |

### Example Scan

```bash
curl -X POST http://localhost:8000/api/v1/ransomware/scan \
  -H "Content-Type: application/json" \
  -d '{"command": "vssadmin delete shadows /all /quiet"}'
```

**Response:**
```json
{
  "success": true,
  "result": {
    "incident_id": "RAN_B889C9BD8929",
    "severity": "HIGH",
    "risk_score": 50,
    "lifecycle_state": "reported",
    "pipeline_results": {
      "detection": {
        "is_ransomware": true,
        "confidence": 0.90,
        "severity": "HIGH"
      },
      "explainability": {
        "behavior_categories": ["shadow_deletion", "service_kill"],
        "attack_stage": "impact",
        "mitre_tactics": ["T1490: Inhibit System Recovery"]
      },
      "response": {
        "actions_executed": ["Terminated malicious process", "SOC team alerted"]
      }
    }
  }
}
```

---

## 🗄️ Database Collections (MongoDB)

| Collection | Contents |
|---|---|
| `threats` | All detected threats (phishing + ransomware) |
| `email_scans` | Phishing scan history |
| `ransomware_scans` | Ransomware scan history |
| `alerts` | MongoDB alerts from alert agent |
| `users` | User accounts |
| `feedback` | User feedback on detections |
| `reports` | Generated reports |

---


