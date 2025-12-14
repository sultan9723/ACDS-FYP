# Implementation Plan: Phishing Detection Module

**Branch**: `develop` | **Date**: 2025-12-14 | **Spec**: `specs/phishing-detection/spec.md`
**Input**: Feature specification from `/specs/phishing-detection/spec.md`

**Note**: This template is filled in by the `/sp.plan` command. See `.specify/templates/commands/plan.md` for the execution workflow.

## Summary

The Phishing Detection Module is an AI-assisted SOC support platform component designed to process email input from Hugging Face datasets, detect phishing threats, create incidents, explain detections, trigger orchestration, update incident timelines, and generate reports.

## Technical Context

**Language/Version**: Python 3.11
**Primary Dependencies**: FastAPI, Pydantic, joblib, scikit-learn, Python's built-in email module
**Storage**: MongoDB
**Testing**: pytest (unit and integration)
**Target Platform**: Docker/Containerization (Linux-based)
**Project Type**: single
**Performance Goals**: Incident creation in DB < 5s; Orchestration initiation < 2s; Incident timeline update < 1s; Report generation < 10s.
**Constraints**: Local development, allowing justified cloud dependencies (e.g., cloud MongoDB) for MVP.
**Scale/Scope**: Initial MVP: Batch processing of datasets up to 10GB / 100,000 emails. Retention policy NEEDS CLARIFICATION.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

### I. ACDS Role Preservation
- **Check**: All changes must preserve ACDS as an investigation-preparation system.
- **Status**: PASSED. The Phishing Detection module contributes directly to investigation preparation.

### II. Responsible AI Usage
- **Check**: Training and inference pipelines must be separable.
- **Status**: PASSED. The spec implies distinct detection (inference) and potential training (implied by Hugging Face dataset import).
- **Check**: AI usage must support deterministic fallback. TODO(PRINCIPLE_AI_USAGE): Clarify the "deterministic fallback b" principle in constitution.
- **Status**: NEEDS CLARIFICATION. The spec does not detail deterministic fallback for the Detection Agent.

### III. Technology Stack Principles
- **Check**: The system must support local development, with explicit exceptions for cloud dependencies where justified (e.g., managed database services like cloud MongoDB).
- **Status**: PASSED. Local development will use cloud MongoDB as a justified exception.
- **Check**: Containerization is optional but supported.
- **Status**: NOT APPLICABLE.
- **Check**: The project must remain deployable without proprietary lock-in.
- **Status**: NOT APPLICABLE.

### IV. Version Control & Change Management
- **Check**: All changes must be tracked using Git.
- **Status**: PASSED. This process uses Git.
- **Check**: No direct commits are allowed on the main branch.
- **Status**: PASSED. Development is on a feature branch.
- **Check**: Feature work shall be performed on isolated feature branches.
- **Status**: PASSED. This work is on `develop` (treated as a feature branch for this module).
- **Check**: Each feature branch must represent one logical change.
- **Status**: PASSED. This module focuses on Phishing Detection.
- **Check**: Commits must be descriptive and scoped to a single purpose.
- **Status**: PASSED. Will adhere to this.
- **Check**: Pull requests must be used to merge changes into the develop branch.
- **Status**: PASSED. Will adhere to this.
- **Check**: Automated agents must never rewrite existing working logic without explicit intent.
- **Status**: PASSED. Adhering to this.

### V. Agent Behavior Constraints
- **Check**: Agents must respect this constitution at all times.
- **Status**: PASSED. Agent is respecting the constitution.
- **Check**: Agents must not override human intent.
- **Status**: PASSED. Agent is following user instructions.
- **Check**: Agents must request clarification when ambiguous. TODO(AGENT_BEHAVIOR): Confirm completion of "Agents must request clarification when ambiguous." in constitution.
- **Status**: PASSED. Agent requested clarifications during `/sp.clarify`.

## Project Structure

### Documentation (this feature)

```text
specs/phishing-detection/
├── plan.md              # This file (/sp.plan command output)
├── research.md          # Phase 0 output (/sp.plan command)
├── data-model.md        # Phase 1 output (/sp.plan command)
├── quickstart.md        # Phase 1 output (/sp.plan command)
├── contracts/           # Phase 1 output (/sp.plan command)
└── tasks.md             # Phase 2 output (/sp.tasks command - NOT created by /sp.plan)
```

### Source Code (repository root)

```text
# Option 2: Web application (when "frontend" + "backend" detected)
backend/
├── src/
│   ├── models/
│   ├── services/
│   │   └── phishing_detection/ # New directory for this module
│   └── api/
└── tests/

# Option 1: Single project (DEFAULT) - NOT USED
# Option 3: Mobile + API (when "iOS/Android" detected) - NOT USED
```

**Structure Decision**: The backend service structure (Option 2) will be used, with a new `phishing_detection/` directory within `backend/src/services/` to house the module's logic.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| [e.g., 4th project] | [current need] | [why 3 projects insufficient] |
| [e.g., Repository pattern] | [specific problem] | [why direct DB access insufficient] |
