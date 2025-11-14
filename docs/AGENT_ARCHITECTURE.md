# AGENT_ARCHITECTURE

This document describes the four core agents in the ACDS pipeline and how they interact.

Agents

1. Detection
	- Purpose: Analyze incoming events or telemetry and determine whether they represent malicious or suspicious activity.
	- Behavior: Runs ML inference and/or rule-based checks, assigns a score, and forwards flagged events to the Response agent.

2. Response
	- Purpose: Take automated or semi-automated mitigation actions to contain or remediate detected issues.
	- Behavior: Maps detection outputs to actions (block IP, quarantine host, throttle connections) and records the action taken. May require human approval for high-impact operations.

3. Intel
	- Purpose: Enrich events with contextual information from internal sources or external threat-intel feeds.
	- Behavior: Adds indicators-of-compromise (IOCs), reputation data, and asset context to improve prioritization and root-cause analysis.

4. Alert
	- Purpose: Format, persist, and surface incidents to downstream systems and analysts.
	- Behavior: Writes incident records to the datastore, triggers notifications, and interfaces with the Streamlit dashboard for analyst review.

Simple workflow

1. Event ingested → 2. Detection evaluates → 3. If flagged, pass to Response → 4. Response executes mitigation and forwards to Intel → 5. Alert logs and notifies

