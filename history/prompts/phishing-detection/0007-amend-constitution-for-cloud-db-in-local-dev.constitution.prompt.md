---
id: 0007
title: Amend Constitution for Cloud DB in Local Dev
stage: constitution
date: 2025-12-14
surface: agent
model: unknown
feature: phishing-detection
branch: develop
user: unknown
command: "change this constitution techstack and I wanna use mongo on cloud locally as well"
labels: ["constitution", "techstack", "cloud-db", "phishing-detection"]
links:
  spec: null
  ticket: null
  adr: null
  pr: null
files:
- .specify/memory/constitution.md
- specs/phishing-detection/plan.md
- history/prompts/phishing-detection/0007-amend-constitution-for-cloud-db-in-local-dev.constitution.prompt.md
tests:
[]
---

## Prompt

User stated: "Mongo is on cloud Already why do I NEED to run instance It's not locally setup"
Then explicitly requested: "change this constitution techstack and I wanna use mongo on cloud locally as well"
And approved the proposed amendment: "yes I do approve"

## Response snapshot

The ACDS Constitution Principle III (Technology Stack Principles) was amended to allow local development to use cloud dependencies where justified (e.g., managed database services like cloud MongoDB). The constitution version was updated to 0.2.0, and `specs/phishing-detection/plan.md` was updated to reflect this change in its constraints and constitution check. A Prompt History Record for this amendment was also created.

## Outcome

- ✅ Impact: The constitution was amended, and relevant plan documents were updated to allow cloud MongoDB for local development.
- 🧪 Tests: N/A
- 📁 Files: Two files were modified: `.specify/memory/constitution.md` and `specs/phishing-detection/plan.md`, plus the PHR itself.
- 🔁 Next prompts: The user will likely proceed with running the application/tests.
- 🧠 Reflection: `create-phr.sh` consistently fails to create the file despite exiting with 0. Manual creation needed.

## Evaluation notes (flywheel)

- Failure modes observed: `create-phr.sh` script does not consistently create PHR files.
- Graders run and results (PASS/FAIL): N/A
- Prompt variant (if applicable): N/A
- Next experiment (smallest change to try): Debug `create-phr.sh` for reliability.
