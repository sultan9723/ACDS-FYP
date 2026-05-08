# Credential Stuffing Detection Module - Technical Specification

## Goal

Build an end-to-end Credential Stuffing Detection module for ACDS.

The module must detect suspicious login behavior such as repeated failed logins, one IP targeting many usernames, one username targeted from many IPs, rapid login attempts, and suspicious success after many failures.

## Scope

This module must integrate into the existing ACDS FastAPI + MongoDB + React architecture without breaking existing phishing, dashboard, feedback, reports, auth, or demo functionality.

## Backend Requirements

### API Endpoints

Base route:

/api/v1/credential-stuffing

Required endpoints:

1. GET /health
   - Returns module status.

2. POST /login-event
   - Accepts a login event.
   - Stores the event in MongoDB.
   - Analyzes recent login behavior.
   - Returns detection result.

3. POST /analyze
   - Accepts one or more login events.
   - Runs detection without requiring frontend auth changes.

4. GET /alerts
   - Returns credential stuffing alerts from MongoDB.

5. POST /feedback
   - Stores analyst feedback for an alert.
   - Feedback values: true_positive, false_positive, needs_review.

6. GET /retraining-data
   - Returns labeled records generated from alerts + analyst feedback.

7. POST /simulate-attack
   - Creates safe synthetic test login events for demo only.
   - Must not perform real credential stuffing.
   - Must only generate local mock events.

## MongoDB Collections

1. credential_login_events
2. credential_stuffing_alerts
3. credential_response_actions
4. credential_analyst_feedback
5. credential_training_records

## Detection Features

For a rolling time window, calculate:

1. failed_attempts_from_ip
2. unique_usernames_from_ip
3. failed_attempts_for_username
4. unique_ips_for_username
5. attempts_per_minute
6. success_after_failures
7. user_agent_variation
8. country_variation

## Detection Logic

Phase 1 must include rule-based detection.

Rules:

- Same IP has >= 10 failed login attempts in 5 minutes.
- Same IP targets >= 5 unique usernames in 5 minutes.
- Same username receives failed attempts from >= 3 unique IPs in 5 minutes.
- Attempts per minute >= 10.
- Successful login occurs after multiple failures from suspicious IP.

Risk score:

- 0.00 - 0.39 = LOW
- 0.40 - 0.69 = MEDIUM
- 0.70 - 1.00 = HIGH

Recommended actions:

- LOW: log_only
- MEDIUM: notify_admin
- HIGH: block_ip_or_lock_account

## ML Requirements

Phase 2 must include a Jupyter notebook or Python training script.

Dataset:

Primary: Login Data Set for Risk-Based Authentication.

Training model:

- RandomForestClassifier
- Use pandas, scikit-learn, joblib
- Save model to models/credential_stuffing_model.joblib
- Save metrics to reports/credential_stuffing_model_metrics.json

Model features must match backend detection features.

## Frontend Requirements

Add a Credential Stuffing dashboard view or card.

Required UI:

1. Total credential stuffing alerts
2. High severity alerts
3. Recent suspicious IPs
4. Alert table
5. Feedback buttons:
   - True Positive
   - False Positive
   - Needs Review

If frontend integration is risky, backend Swagger demo is mandatory first.

## Testing Requirements

Minimum tests:

1. Normal login should not create high alert.
2. Many failed attempts from one IP should trigger alert.
3. One IP targeting many usernames should trigger alert.
4. One username attacked from many IPs should trigger alert.
5. Feedback should be stored.
6. Retraining endpoint should return labeled records.

## Safety Guardrails

- Do not use real credentials.
- Do not attack any live system.
- Do not automate login attempts against external services.
- simulate-attack endpoint must only generate local mock login events.
- Do not modify unrelated modules unless necessary for route registration.

## Acceptance Criteria

The module is complete when:

1. Backend starts.
2. /api/v1/credential-stuffing/health works.
3. Login event is stored in MongoDB.
4. Suspicious login pattern creates an alert.
5. Alert includes confidence, severity, evidence, and recommended action.
6. Feedback is stored.
7. Retraining data is available.
8. Model training script/notebook exists.
9. Model file can be generated.
10. Final code is committed on feature/credential-stuffing-module branch.