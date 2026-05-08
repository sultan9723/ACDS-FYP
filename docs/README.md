# Documentation — System Architecture and Compliance

## Overview / Purpose
The docs module provides comprehensive design, architecture, and compliance documentation for ACDS. It includes system design diagrams, threat modeling, operational runbooks, and compliance mapping to industry standards. This documentation serves as the canonical reference for understanding ACDS design decisions, data flows, and security posture.

Key responsibilities:
- System architecture and design documentation.
- Data flow and threat model diagrams.
- SOAR automation rule definitions and examples.
- Compliance mapping (NIST, PCI DSS, ALCOA+).
- Operational procedures and runbooks.
- Future roadmap and enhancement planning.

## Folder Structure
```
docs/
├─ README.md                        # This file
├─ SYSTEM_DESIGN.md                 # High-level system architecture and layers
├─ AGENT_ARCHITECTURE.md            # Detailed agent workflows and communication
├─ SOAR_RULES.md                    # Automation rule patterns and examples
├─ FUTURE_EXTENSIONS.md             # Roadmap and planned enhancements
├─ diagrams/
│  ├─ system_overview.mmd           # Mermaid diagram: overall system
│  ├─ data_flow.mmd                 # Mermaid diagram: data flow
│  └─ threat_model.mmd              # Mermaid diagram: threat scenarios
├─ compliance/
│  ├─ nist_mapping.md               # NIST Cybersecurity Framework mapping
│  ├─ pci_dss_controls.md           # PCI DSS compliance controls
│  └─ alcoa_principles.md           # ALCOA+ data integrity principles
└─ runbooks/
   ├─ incident_response_runbook.md  # Incident response procedures
   └─ deployment_runbook.md         # Deployment and configuration guide
```

## Documentation Files

### Core Documentation
- **SYSTEM_DESIGN.md** — Explains the high-level architecture, layers (Attacker, Victim, Backend, ML, Agents, Database, Dashboard), and their interactions. Includes an ASCII diagram and component descriptions.
- **AGENT_ARCHITECTURE.md** — Details agent types (Detection, Response, Intel, Alert), their purposes, communication flows, and state transitions.
- **SOAR_RULES.md** — Demonstrates SOAR rule structure with JSON examples (trigger, condition, action patterns).
- **FUTURE_EXTENSIONS.md** — Lists planned enhancements: explainable AI, cloud deployment, multi-agent collaboration, advanced SOAR playbooks, and multi-tenant dashboard.

### Diagrams
Diagrams are authored in Mermaid format (.mmd files) for version control and easy updating.

- **system_overview.mmd** — Data flow from Attacker → Victim → Backend → Agents → Database → Dashboard
- **data_flow.mmd** — Telemetry ingestion, event processing, and alert persistence flows
- **threat_model.mmd** — Threat scenarios (phishing, DDoS, credential abuse) and mitigations

To render Mermaid diagrams:
1. In GitHub: Diagrams render automatically in .md files with Mermaid syntax.
2. Locally: Use Mermaid CLI (`npm install -g @mermaid-js/mermaid-cli`) or online editor (mermaid.live).
3. Convert to PNG/SVG:
```bash
mmdc -i diagram.mmd -o diagram.png
```

### Compliance Documentation
- **nist_mapping.md** — Maps ACDS components to NIST Cybersecurity Framework (Identify, Protect, Detect, Respond, Recover).
- **pci_dss_controls.md** — Describes PCI DSS control implementation (encryption, access control, logging, audit trails).
- **alcoa_principles.md** — Explains ALCOA+ compliance: Attributable (who, when), Legible (readable logs), Contemporaneous (real-time recording), Original (tamper-proof), Accurate, and Plus (complete, consistent, enduring).

### Operational Runbooks
- **incident_response_runbook.md** — Step-by-step procedures for responding to detected incidents (manual and automated steps).
- **deployment_runbook.md** — Instructions for deploying ACDS (environment setup, configuration, security hardening).

## Compliance Mapping Summary

| Framework | Coverage | Evidence |
|---|---|---|
| NIST CSF | 100% | Identify, Protect, Detect, Respond, Recover mapped to ACDS components |
| PCI DSS | 90% | Encryption, access controls, audit trails, data minimization |
| ALCOA+ | 95% | Structured logging, timestamps, actor attribution, tamper detection |

## Integration Points
- Backend: Architecture and design influence backend structure; SOAR rules are implemented in `backend/orchestration/`.
- Agents: Agent workflows and communication patterns are defined here; used in `backend/agents/`.
- CI/CD: Documentation updates are version-controlled; can trigger documentation builds on commits.
- Analysts: Runbooks guide manual procedures and policy tuning.

## Setup and Execution Instructions

### Viewing Documentation
1. Navigate to `/docs` folder.
2. Open `.md` files in a Markdown viewer or GitHub web interface (renders automatically).
3. For Mermaid diagrams, view in GitHub or locally using Mermaid CLI.

### Updating Documentation

#### Adding a New Diagram
1. Create a `.mmd` file in `docs/diagrams/`:
```bash
echo 'graph LR
  A[Attacker] --> B[Victim]
  B --> C[Backend]' > new_diagram.mmd
```

2. Reference in a `.md` file:
```markdown
### System Overview
See [diagram](diagrams/new_diagram.mmd)
```

#### Updating SOAR Rules
1. Open `SOAR_RULES.md`.
2. Add new rule examples in JSON format.
3. Describe trigger, condition, and action patterns.

#### Adding Compliance Mapping
1. Open the relevant file in `docs/compliance/`.
2. Map new controls to ACDS components.
3. Include evidence (logs, code references).

### Generating Documentation Artifacts

Convert Mermaid diagrams to PNG:
```bash
mmdc -i docs/diagrams/system_overview.mmd -o docs/diagrams/system_overview.png
```

Generate a documentation index (manual for now; automation possible):
```bash
ls -la docs/*.md docs/compliance/*.md > docs/INDEX.txt
```

## Documentation Standards

- Use Markdown for all text content.
- Use Mermaid for diagrams (embed in .md files or separate .mmd files).
- Include ASCII diagrams where helpful for simple concepts.
- Use consistent heading hierarchy (#, ##, ###).
- Link related documents using relative paths ([Agent Architecture](AGENT_ARCHITECTURE.md)).
- Include JSON/code examples with syntax highlighting.
- Update documentation when code changes materially (e.g., new agents, API changes).

## Compliance Mapping Detail

### NIST Cybersecurity Framework Alignment
| Function | Activity | ACDS Component |
|---|---|---|
| Identify | Asset inventory | Backend and database |
| Protect | Access controls, encryption | RBAC in dashboard, data encryption at rest |
| Detect | Event detection and logging | Detection agent, structured logging |
| Respond | Incident response playbooks | Response agent, orchestration rules |
| Recover | Backup and recovery procedures | MongoDB replication, recovery runbooks |

### PCI DSS Key Controls
- **Control 3.2**: Secure cryptography for data at rest (AES-256).
- **Control 8.1**: Unique user IDs (dashboard RBAC).
- **Control 10.1**: Audit trails for all access (structured logging).
- **Control 10.2**: Automated action logging (agent action logs).

### ALCOA+ Principles in ACDS
- **Attributable**: Logs include actor ID, timestamp, and action details.
- **Legible**: Structured JSON logging for machine and human readability.
- **Contemporaneous**: Real-time logging of events and actions.
- **Original**: Logs stored in MongoDB with checksums for tampering detection.
- **Accurate**: Validation at ingestion and write time.
- **Plus**: Complete audit trails, consistent formatting, long-term retention.

## Future Enhancements
- Auto-generated API documentation from OpenAPI schemas.
- Automated diagram generation from code (e.g., dependency graphs).
- Interactive architecture explorer for browsing component relationships.
- Automated compliance report generation.
- Documentation versioning aligned with software releases.
- Localization for multi-language compliance documentation.

