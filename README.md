# ACDS-FYP — Autonomous Cyber Defense System

A compact research prototype that demonstrates an autonomous cyber defense pipeline: data ingestion from a simulated lab, machine learning-based detection, and automated response agents with a visualization dashboard.

Features
- Simulated attacker/victim lab environment
- FastAPI backend with ML inference for phishing detection
- Modular agents: Detection, Response, Intel, Alert
- Streamlit dashboard for monitoring and feedback
- Extensible SOAR-style automation rules

Tech stack
- Python 3.9+
- FastAPI (backend API)
- scikit-learn / custom ML code (in `backend/ml`)
- Streamlit (frontend dashboard)
- MongoDB (recommended for telemetry and alerts)

Repository structure (top-level)

```
ACDS-FYP/
├─ backend/            # backend services, agents, ML models
├─ frontend/           # Streamlit dashboard
├─ docs/               # detailed design and architecture docs
├─ data/               # raw and processed datasets
├─ lab/                # simulated attacker/victim sensors
├─ models/             # trained model artifacts
├─ tests/              # test suite
├─ docker/             # docker-related files
├─ requirements.txt
└─ README.md
```

How to run locally (quick)
1. Create and activate a virtual environment (Windows cmd):

```cmd
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

2. Start the backend (example):

```cmd
python backend/main.py
```

3. Start the Streamlit dashboard (from `frontend/`):

```cmd
streamlit run frontend/dashboard/streamlit_dashboard.py
```

See `/docs` for detailed design, architecture, and operational notes.

Contributing
- Please open issues for bugs or feature requests.
- Create small, focused pull requests with tests where possible.
- Follow existing code style and update docs when adding features.

License
- This project is released under the terms in `LICENSE`.

