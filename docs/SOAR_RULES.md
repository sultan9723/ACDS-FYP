# SOAR_RULES

Example SOAR rule (JSON)

```json
{
	"id": "rule-001",
	"name": "Block suspicious sender",
	"trigger": {
		"type": "detection.event",
		"source": "phishing_model"
	},
	"condition": {
		"score_greater_than": 0.8
	},
	"action": {
		"type": "response.block_sender",
		"parameters": {
			"notify_admin": true,
			"quarantine": true
		}
	}
}
```

Fields
- trigger: event type or external signal that starts rule evaluation
- condition: boolean or threshold checks that must pass
- action: the automation to run when the condition is met

