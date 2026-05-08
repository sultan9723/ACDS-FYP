# SYSTEM_DESIGN

```mermaid
graph LR
	Attacker[Attacker] --> Victim[Victim]
	Victim --> Backend[Backend\n(FastAPI + ML)]
	Backend --> Agents[Agents\n(Detection -> Response -> Intel -> Alert)]
	Agents --> MongoDB[MongoDB]
	MongoDB --> Dashboard[Streamlit\nDashboard]
```

Overview

Attacker — Represents an adversary or simulated attacker component in the lab that generates malicious traffic or phishing payloads. The lab hosts attacker nodes and payload generators used for evaluation and telemetry collection.

Victim — Represents target hosts and sensors (victim machines) that receive or interact with attacker traffic. Instrumentation on the victim side captures telemetry and suspicious events which are forwarded to the backend.

Backend (FastAPI + ML) — The backend receives telemetry and events from the lab and exposes APIs for inference, training, and health checks. ML models (in `backend/ml`) perform detection/inference and provide scores and metadata back to the agent pipeline.

Agents (Detection → Response → Intel → Alert) — A modular agent chain coordinates autonomous actions: the Detection agent evaluates events, Response issues mitigation actions, Intel enriches events with context, and Alert formats/persists incidents. Rules-based automation can drive transitions between agents.

MongoDB — A recommended persistence layer for telemetry, alerts, and historical data used for analytics and model retraining. Agents and the backend write incident records and enrichment artifacts here.

Streamlit Dashboard — A lightweight dashboard for visualizing alerts, model scores, and system status. It reads from the persistence layer and provides quick feedback loops for analysts.

