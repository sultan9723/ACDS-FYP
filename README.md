
# Autonomous Cyber Defense System (ACDS-FYP)

![CI](https://github.com/sultan9723/ACDS-FYP/actions/workflows/ci.yml/badge.svg?branch=develop)

## 1. Project Title and Introduction

The Autonomous Cyber Defense System (ACDS-FYP) is an autonomous cybersecurity platform that integrates backend orchestration, machine learning, and automated agents to detect and respond to simulated attacks in real time. It demonstrates how intelligent automation can enhance security operations and reduce response times in modern threat environments.

## 2. Problem Statement

Traditional Security Operation Centers (SOCs) face major challenges in handling the increasing volume and complexity of cyberattacks. Manual analysis and response are time-consuming, prone to human error, and often lead to delayed mitigation. The reliance on human analysts for repetitive monitoring tasks reduces efficiency and increases operational costs. The need for an intelligent, autonomous system that can automatically detect, analyze, and respond to security threats has become essential. The Autonomous Cyber Defense System (ACDS) addresses this gap by integrating artificial intelligence, machine learning, and SOAR principles to create an automated, self-learning defense platform.

## 3. Objectives

- Automate detection and response to simulated cyberattacks using AI and ML.
- Implement SOAR (Security Orchestration, Automation, and Response) workflows for event-driven actions.
- Provide real-time threat analysis and scoring via machine learning models.
- Visualize detections, alerts, and system health through an interactive dashboard.
- Ensure compliance with industry security frameworks and best practices.
- Enable modular agent collaboration for scalable and extensible defense.

## 4. Project Hierarchy

```
ACDS-FYP/
├── backend/
│   └── agents/
├── models/
├── tests/
├── docs/
├── .github/
│   └── workflows/
├── requirements.txt
├── docker-compose.yml
└── README.md
```

## 5. System Architecture

```
Attacker Node
	│
	▼
Victim System
	│
	▼
Backend (FastAPI + ML)
	│
	▼
Agents (Detection → Response → Intel → Alert)
	│
	▼
Dashboard (Streamlit)
	│
	▼
MongoDB
```

**Flow Explanation:**
An attack is triggered by the Attacker Node and targets the Victim System. Logs and telemetry are captured and sent to the Backend, where machine learning models analyze the data. Automated agents respond to threats based on SOAR rules. The Dashboard visualizes detections and responses, while all events and alerts are stored in MongoDB.

## 6. Core Components

- **Backend:** Orchestrates event ingestion, ML inference, agent workflows, and SOAR rule execution.
- **ML Engine:** Provides real-time threat scoring and detection using trained models.
- **Agents:** Modular components for detection, response, enrichment, and alerting.
- **SOAR Layer:** Automates security workflows and response actions.
- **Database:** MongoDB for storing events, alerts, and system state.
- **Dashboard:** Streamlit UI for monitoring, analytics, and analyst feedback.
- **Simulation Nodes:** Attacker and Victim systems for generating and capturing realistic events.

## 7. MVP (50%) Progress

| Feature                | Status      |
|------------------------|------------|
| Backend Orchestration  | Complete   |
| ML Integration         | Complete   |
| CI/CD Automation       | Complete   |
| Documentation          | Complete   |
| Dashboard UI           | In Progress|
| Agent Collaboration    | In Progress|

*This is the first deliverable milestone (MVP 50%).*

## 8. Tech Stack

| Technology     | Purpose                        |
|----------------|-------------------------------|
| Python 3.10    | Core language                 |
| FastAPI        | Backend API                   |
| Streamlit      | Dashboard UI                  |
| MongoDB        | Database                      |
| scikit-learn   | Machine Learning              |
| APScheduler    | Task Scheduling               |
| Docker         | Containerization              |
| GitHub Actions | CI/CD Automation              |

## 9. Dataset Overview

| Dataset                | Description                        | Source/Size      |
|------------------------|------------------------------------|------------------|
| Phishing URLs          | Malicious and benign URLs           | Public (Kaggle)  |
| Ransomware Commands    | Command patterns for ransomware     | Synthetic/Public |
| Credential Stuffing    | Login attempts (normal/malicious)   | Synthetic        |
| Normal Traffic         | Baseline user/system activity       | Internal         |

## 10. CI/CD Integration

GitHub Actions is configured to automatically lint, test, and validate the codebase on every push to the `develop` branch. This ensures code quality, prevents regressions, and enforces safe-mode operation before merging.

## 11. Compliance and Security

ACDS aligns with:
- **NIST Cybersecurity Framework:** Covers Identify, Protect, Detect, Respond, Recover.
- **PCI DSS:** Implements secure data handling, access control, and audit trails.
- **ALCOA+:** Ensures data is Attributable, Legible, Contemporaneous, Original, Accurate, and complete.

## 12. SOC Analyst Evolution

| Traditional SOC Responsibilities         | ACDS Automated SOC Responsibilities         |
|------------------------------------------|---------------------------------------------|
| Manual alert triage                      | Automated detection and triage              |
| Manual incident response                 | Automated response and containment          |
| Repetitive monitoring                    | Analyst oversight and policy tuning         |
| Delayed mitigation                       | Real-time, rule-driven mitigation           |
| Manual reporting and compliance          | Automated logging and compliance reporting  |

## 13. Installation and Setup

```bash
# 1. Clone the repository
git clone https://github.com/sultan9723/ACDS-FYP.git
cd ACDS-FYP

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate   # On Windows: .\.venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the backend server
python backend/main.py

# 5. Run the dashboard (in a new terminal)
streamlit run frontend/dashboard/streamlit_dashboard.py
```

## 14. Testing

Run all tests with:

```bash
pytest
```

All tests are integrated with CI/CD and run automatically on every push.

## 15. Future Enhancements

- Reinforcement learning agents for adaptive defense
- Explainable AI for transparent decision-making
- Integration with external threat intelligence feeds
- Cloud-native deployment (AWS, Docker Swarm, Kubernetes)
- Advanced agent collaboration and voting mechanisms

## 16. Team Roles

| Name            | Role                                   | Responsibilities                        |
|-----------------|----------------------------------------|-----------------------------------------|
| Sultan Qaiser   |  / System Architect      | Backend, CI/CD, SOAR                    |
| Teammate 2      | Machine Learning Engineer              | Datasets, model training, integration   |
| Teammate 3      | Frontend Developer                     | Dashboard UI, visualization             |

## 17. Contribution Guide

- Fork the repository
- Create a feature branch
- Commit your changes
- Open a pull request for review

## 18. License

This project is licensed under the MIT License.

## 19. CI Status

![CI](https://github.com/sultan9723/ACDS-FYP/actions/workflows/ci.yml/badge.svg?branch=develop)

## 20. Contact

- Sultan Qaiser  
- Email: sultanquaiser@gmail.com  
- GitHub: [sultan9723](https://github.com/sultan9723)

## 21. Summary

ACDS-FYP demonstrates how artificial intelligence and automation can transform Security Operation Centers from manual, reactive environments into intelligent, self-learning defense systems capable of real-time detection and response.

