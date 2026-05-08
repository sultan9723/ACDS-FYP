# Tasks: Phishing Detection Module MVP

**Input**: Design documents from `/specs/phishing-detection/`
**Prerequisites**: plan.md (required), spec.md (required for user stories)

**Tests**: This task list does not explicitly include test generation tasks. Test generation tasks can be added in a separate phase or integrated as part of the implementation tasks if a TDD approach is desired.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Web app**: `backend/src/`, `frontend/src/` (adjusting for backend focus)

## Phase 1: Setup (Project Initialization & Environment)

**Purpose**: Ensure the project environment is configured and basic dependencies are installed.

- [X] T001 Install Python 3.11 and create a virtual environment (if not already done).
- [X] T002 Install core Python dependencies from `requirements.txt`.
- [X] T003 Configure `.env` for MongoDB connection (add `MONGO_URI`, `DB_NAME`).
- [X] T004 Verify MongoDB connectivity (e.g., by running a simple connection script in `backend/tests/`).

---

## Phase 2: Foundational (Core Infrastructure & Shared Components)

**Purpose**: Implement core data models, database connection, and utility functions that are prerequisites for all user stories.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T005 [P] Define Pydantic models for `Email` and `Incident` in `backend/src/services/phishing_detection/models.py`.
- [X] T006 Implement asynchronous MongoDB client and database operations (e.g., `IncidentDatabase` class) in `backend/src/services/phishing_detection/database.py`.
- [X] T007 Implement `EmailDataLoader` for loading emails from Hugging Face datasets in `backend/src/services/phishing_detection/data_loader.py`.

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - End-to-End Phishing Incident Handling (Priority: P1) 🎯 MVP

**Goal**: Implement the full workflow for detecting phishing, creating incidents, explaining, triggering orchestration, updating timelines, and generating reports.

**Independent Test**: An email with known phishing characteristics can be submitted to the system via `run_quickstart.py` (or a test API endpoint), and a corresponding incident with an explanation, updated timeline, and generated PDF report should be available for review in the database and file system.

### Implementation for User Story 1

- [X] T008 [US1] Implement `DetectionAgent` with rule-based detection logic in `backend/src/services/phishing_detection/detection_agent.py`.
- [X] T009 [US1] Implement `IncidentManager` for creating, updating, and retrieving incidents in `backend/src/services/phishing_detection/incident_manager.py`.
- [X] T010 [US1] Implement `ExplainabilityAgent` for generating explanations in `backend/src/services/phishing_detection/explainability_agent.py`.
- [X] T011 [P] [US1] Create `ResponseAgent` (placeholder) in `backend/src/services/phishing_detection/response_agent.py`.
- [X] T012 [US1] Implement `ReportGenerator` for text and PDF reports in `backend/src/services/phishing_detection/report_generator.py`.
- [X] T013 [US1] Implement `OrchestratorAgent` to coordinate the workflow (integrating Detection, IncidentManager, Explainability, Response, ReportGenerator) in `backend/src/services/phishing_detection/orchestrator_agent.py`.
- [X] T014 [US1] Implement FastAPI application structure and main router in `backend/main.py` (or `backend/api/main.py`).
- [X] T015 [US1] Implement API endpoint `POST /api/v1/phishing-detection/process-emails` in `backend/main.py` (or `backend/api/main.py`).
- [X] T016 [US1] Implement API endpoint `GET /api/v1/phishing-detection/incidents/{incident_id}` in `backend/main.py` (or `backend/api/main.py`).
- [X] T017 [US1] Implement API endpoint `GET /api/v1/phishing-detection/incidents` in `backend/main.py` (or `backend/api/main.py`).
- [X] T018 [US1] Implement API endpoint `GET /api/v1/phishing-detection/incidents/{incident_id}/report/pdf` in `backend/main.py` (or `backend/api/main.py`).
- [ ] T019 [US1] **Integration Test**: Ensure `run_quickstart.py` successfully executes the end-to-end workflow and generates reports.

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently

---

## Final Phase: Polish & Cross-Cutting Concerns

**Purpose**: Address non-functional requirements and overall system quality.

- [ ] T020 [P] Implement API Key authentication middleware/logic for FastAPI in `backend/src/middleware/auth.py` (or integrated into API routes).
- [ ] T021 Configure structured logging across the application (e.g., in `backend/main.py` and agent modules).
- [ ] T022 Implement metrics exposure for basic health checks (e.g., Uvicorn server metrics or custom FastAPI endpoints).
- [ ] T023 Refine error handling across API endpoints and agent modules, ensuring proper logging and incident status updates for unrecoverable errors.
- [ ] T024 Update `README.md` with setup, API usage, and deployment instructions.
- [ ] T025 Code cleanup and refactoring across the codebase.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3)**: Depends on Foundational phase completion
- **Polish (Final Phase)**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) - No dependencies on other stories

### Within Each User Story

- Models (`models.py`) before database (`database.py`) and data loader (`data_loader.py`).
- Agents (`detection_agent.py`, `incident_manager.py`, `explainability_agent.py`, `response_agent.py`, `report_generator.py`) can be developed in parallel after foundational elements.
- `OrchestratorAgent` depends on all other agents.
- API Endpoints depend on `OrchestratorAgent` and `IncidentManager`.

### Parallel Opportunities

- All Setup tasks T005 can run in parallel.
- Within User Story 1, tasks T008-T012 (individual agents) can be developed in parallel after foundational elements are complete.
- Tasks T015-T018 (API endpoints) can be developed in parallel.
- All tasks in the "Polish & Cross-Cutting Concerns" phase marked [P] can run in parallel.

---

## Parallel Example: User Story 1

```bash
# Individual agent implementations (can be done by different developers concurrently):
Task: "Implement DetectionAgent in backend/src/services/phishing_detection/detection_agent.py"
Task: "Implement IncidentManager in backend/src/services/phishing_detection/incident_manager.py"
Task: "Implement ExplainabilityAgent in backend/src/services/phishing_detection/explainability_agent.py"
Task: "Create ResponseAgent (placeholder) in backend/src/services/phishing_detection/response_agent.py"
Task: "Implement ReportGenerator in backend/src/services/phishing_detection/report_generator.py"

# API Endpoints (can be done by different developers concurrently once agents are integrated into Orchestrator):
Task: "Implement API endpoint POST /api/v1/phishing-detection/process-emails in backend/main.py"
Task: "Implement API endpoint GET /api/v1/phishing-detection/incidents/{incident_id} in backend/main.py"
Task: "Implement API endpoint GET /api/v1/phishing-detection/incidents in backend/main.py"
Task: "Implement API endpoint GET /api/v1/phishing-detection/incidents/{incident_id}/report/pdf in backend/main.py"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL - blocks all stories)
3. Complete Phase 3: User Story 1
4. **STOP and VALIDATE**: Test User Story 1 independently using `run_quickstart.py` and API calls.
5. Deploy/demo if ready

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add User Story 1 → Test independently → Deploy/Demo (MVP!)
3. Proceed to Polish & Cross-Cutting Concerns.

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together.
2. Once Foundational is done:
   - Developer A: DetectionAgent, IncidentManager
   - Developer B: ExplainabilityAgent, ReportGenerator
   - Developer C: OrchestratorAgent, FastAPI endpoints
3. Integrate and test.

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Verify tests fail before implementing (if tests are added)
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Avoid: vague tasks, same file conflicts, cross-story dependencies that break independence