<!-- Sync Impact Report:
Version change: 0.0.0 -> 0.1.0
List of modified principles:
  - Initial creation of all principles.
Added sections:
  - Project Definition
  - Core Principles
  - Technology & Development Guidelines
  - Governance
Removed sections: None
Templates requiring updates:
  - .specify/templates/plan-template.md ⚠ pending
  - .specify/templates/spec-template.md ⚠ pending
  - .specify/templates/tasks-template.md ⚠ pending
  - All command files in .specify/templates/commands/*.md ⚠ pending
  - Any runtime guidance docs (e.g., README.md, docs/quickstart.md) ⚠ pending
Follow-up TODOs:
  - TODO(Preamble): Complete the last sentence.
  - TODO(RATIFICATION_DATE): User needs to provide the original adoption date.
  - TODO(PRINCIPLE_AI_USAGE): Clarify the "deterministic fallback" principle.
  - TODO(AGENT_BEHAVIOR): Confirm completion of "Agents must request clarification when ambiguous."
-->
# ACDS Constitution (Authoritative)
> 🔒 *Authoritative Document*
>
> This constitution is fully authored by the user.
> Agents MUST NOT infer, autogenerate, or alter any content of this constitution without explicit user instruction.

## Project Definition
ACDS (Autonomous Cyber Defense System) is an AI-assisted SOC support platform designed to prepare, structure, and explain security investigations, not to replace human analysis.

## Core Principles

### I. ACDS Role Preservation
All changes must preserve ACDS as an investigation-preparation system.

### II. Responsible AI Usage
*   Training and inference pipelines must be separable.
*   AI usage must support deterministic fallback. In cases where AI/ML models cannot make a confident prediction, or encounter errors, the system MUST revert to a pre-defined, predictable, and auditable non-AI based behavior (e.g., rule-based classification, manual review queue, or explicit 'uncertain' classification with a default action) rather than failing unpredictably or making random decisions.

## Technology & Development Guidelines

### III. Technology Stack Principles
*   The system must support local development, with explicit exceptions for cloud dependencies where justified (e.g., managed database services like cloud MongoDB).
*   Containerization is optional but supported.
*   The project must remain deployable without proprietary lock-in.

### IV. Version Control & Change Management
*   All changes must be tracked using Git.
*   No direct commits are allowed on the main branch.
*   Feature work shall be performed on isolated feature branches.
*   Each feature branch must represent one logical change.
*   Commits must be descriptive and scoped to a single purpose.
*   Pull requests must be used to merge changes into the develop branch.
*   Automated agents must never rewrite existing working logic without explicit intent.

### V. Agent Behavior Constraints
*   Agents must respect this constitution at all times.
*   Agents must not override human intent.
*   Agents must request clarification when ambiguous.

## Governance
<!-- This section requires user input to define specific governance rules -->
[GOVERNANCE_RULES]

**Version**: 0.2.0 | **Ratified**: TODO(RATIFICATION_DATE): User needs to provide the original adoption date. | **Last Amended**: 2025-12-15