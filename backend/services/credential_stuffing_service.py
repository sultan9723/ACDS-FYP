"""
Credential Stuffing Detection Service
=====================================
Rule-based Phase 1 detection for suspicious login behavior.
"""

from datetime import datetime, timedelta, timezone
import random
import uuid
from typing import Any, Dict, List, Optional

try:
    from database.connection import get_collection
except ImportError:
    try:
        from backend.database.connection import get_collection
    except ImportError:
        get_collection = None


LOGIN_EVENTS_COLLECTION = "credential_login_events"
ALERTS_COLLECTION = "credential_stuffing_alerts"
RESPONSE_ACTIONS_COLLECTION = "credential_response_actions"
FEEDBACK_COLLECTION = "credential_analyst_feedback"
TRAINING_RECORDS_COLLECTION = "credential_training_records"

WINDOW_MINUTES = 5


class CredentialStuffingService:
    """Service for storing login events and detecting credential stuffing."""

    def __init__(self):
        self.indexes_created = False

    def health(self) -> Dict[str, Any]:
        database_available = get_collection is not None
        collections_available = False

        if database_available:
            try:
                self._ensure_indexes()
                collections_available = self._collection(LOGIN_EVENTS_COLLECTION) is not None
            except Exception:
                collections_available = False

        return {
            "success": True,
            "module": "credential_stuffing_detection",
            "status": "healthy" if collections_available else "degraded",
            "phase": "phase_1_rule_based",
            "database_available": database_available,
            "collections_available": collections_available,
        }

    def process_login_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_indexes()

        normalized_event = self._normalize_event(event)
        event_id = self._store_login_event(normalized_event)
        result = self._detect(normalized_event)

        alert = None
        if result["risk_score"] >= 0.40:
            alert = self._store_alert(normalized_event, result, source="login-event")
            self._store_response_action(alert, result)

        return {
            "success": True,
            "event_id": event_id,
            "alert_created": alert is not None,
            "alert_id": alert.get("alert_id") if alert else None,
            "confidence": result["confidence"],
            "risk_score": result["risk_score"],
            "severity": result["severity"],
            "evidence": result["evidence"],
            "features": result["features"],
            "recommended_action": result["recommended_action"],
        }

    def analyze_events(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        self._ensure_indexes()

        normalized_events = [self._normalize_event(event) for event in events]
        for normalized_event in normalized_events:
            self._store_login_event(normalized_event)

        results = []
        alerts = []
        for normalized_event in normalized_events:
            result = self._detect(normalized_event, additional_events=normalized_events)
            alert = None
            if result["risk_score"] >= 0.40:
                alert = self._store_alert(normalized_event, result, source="analyze")
                self._store_response_action(alert, result)
                alerts.append(alert["alert_id"])

            results.append({
                "event": self._public_event(normalized_event),
                "alert_created": alert is not None,
                "alert_id": alert.get("alert_id") if alert else None,
                "confidence": result["confidence"],
                "risk_score": result["risk_score"],
                "severity": result["severity"],
                "evidence": result["evidence"],
                "features": result["features"],
                "recommended_action": result["recommended_action"],
            })

        highest_result = max(results, key=lambda item: item["risk_score"], default=None)
        max_score = highest_result["risk_score"] if highest_result else 0.0
        return {
            "success": True,
            "count": len(results),
            "alerts_created": len(alerts),
            "alert_ids": alerts,
            "confidence": round(max_score, 2),
            "severity": self._severity(max_score),
            "evidence": highest_result["evidence"] if highest_result else ["No login events were analyzed."],
            "recommended_action": self._recommended_action(max_score),
            "results": results,
        }

    def list_alerts(self, limit: int = 100, severity: Optional[str] = None) -> Dict[str, Any]:
        self._ensure_indexes()
        collection = self._collection(ALERTS_COLLECTION)
        query = {}
        if severity:
            query["severity"] = severity.upper()

        cursor = collection.find(query).sort("created_at", -1).limit(limit)
        alerts = [self._serialize(doc) for doc in cursor]
        return {
            "success": True,
            "alerts": alerts,
            "count": len(alerts),
        }

    def submit_feedback(self, alert_id: str, feedback: str, analyst: Optional[str] = None, notes: Optional[str] = None) -> Dict[str, Any]:
        self._ensure_indexes()

        if feedback not in {"true_positive", "false_positive", "needs_review"}:
            raise ValueError("feedback must be one of: true_positive, false_positive, needs_review")

        alerts_collection = self._collection(ALERTS_COLLECTION)
        alert = alerts_collection.find_one({"alert_id": alert_id})
        if not alert:
            raise LookupError(f"Alert not found: {alert_id}")

        feedback_id = f"CFB-{uuid.uuid4().hex[:10].upper()}"
        now = datetime.now(timezone.utc)
        feedback_doc = {
            "feedback_id": feedback_id,
            "alert_id": alert_id,
            "feedback": feedback,
            "analyst": analyst or "anonymous",
            "notes": notes,
            "created_at": now,
        }
        self._collection(FEEDBACK_COLLECTION).insert_one(feedback_doc)

        label = self._feedback_to_label(feedback)
        training_record = {
            "training_record_id": f"CTR-{uuid.uuid4().hex[:10].upper()}",
            "alert_id": alert_id,
            "feedback_id": feedback_id,
            "label": label,
            "feedback": feedback,
            "features": alert.get("features", {}),
            "evidence": alert.get("evidence", []),
            "severity": alert.get("severity"),
            "confidence": alert.get("confidence"),
            "source_ip": alert.get("source_ip"),
            "username": alert.get("username"),
            "created_at": now,
        }
        self._collection(TRAINING_RECORDS_COLLECTION).insert_one(training_record)

        alerts_collection.update_one(
            {"alert_id": alert_id},
            {"$set": {"feedback": feedback, "feedback_id": feedback_id, "updated_at": now}},
        )

        return {
            "success": True,
            "feedback_id": feedback_id,
            "training_record_id": training_record["training_record_id"],
            "alert_id": alert_id,
            "feedback": feedback,
            "label": label,
            "confidence": alert.get("confidence"),
            "severity": alert.get("severity"),
            "evidence": alert.get("evidence", []),
            "recommended_action": alert.get("recommended_action"),
        }

    def get_retraining_data(self, limit: int = 500) -> Dict[str, Any]:
        self._ensure_indexes()
        cursor = self._collection(TRAINING_RECORDS_COLLECTION).find({}).sort("created_at", -1).limit(limit)
        records = [self._serialize(doc) for doc in cursor]
        return {
            "success": True,
            "records": records,
            "count": len(records),
        }

    def simulate_attack(self, source_ip: str = "198.51.100.25", username_prefix: str = "demo_user", count: int = 12) -> Dict[str, Any]:
        self._ensure_indexes()
        count = max(1, min(count, 50))
        now = datetime.now(timezone.utc)

        events = []
        for index in range(count):
            events.append({
                "username": f"{username_prefix}_{index % 8}",
                "ip_address": source_ip,
                "success": False,
                "timestamp": now - timedelta(seconds=(count - index) * 8),
                "user_agent": f"ACDS-Demo-Browser/{index % 3}",
                "country": random.choice(["US", "GB", "DE"]),
                "source": "credential_stuffing_simulation",
                "is_synthetic": True,
            })

        normalized_events = [self._normalize_event(event) for event in events]
        event_ids = [self._store_login_event(event) for event in normalized_events]
        result = self._detect(normalized_events[-1], additional_events=normalized_events)
        alert = self._store_alert(normalized_events[-1], result, source="simulate-attack")
        self._store_response_action(alert, result)

        return {
            "success": True,
            "message": "Synthetic local credential stuffing simulation generated.",
            "synthetic_only": True,
            "events_created": len(event_ids),
            "event_ids": event_ids,
            "alert_created": True,
            "alert_id": alert["alert_id"],
            "confidence": result["confidence"],
            "risk_score": result["risk_score"],
            "severity": result["severity"],
            "evidence": result["evidence"],
            "features": result["features"],
            "recommended_action": result["recommended_action"],
        }

    def _ensure_indexes(self) -> None:
        if self.indexes_created:
            return
        if get_collection is None:
            raise RuntimeError("MongoDB get_collection is unavailable")

        self._collection(LOGIN_EVENTS_COLLECTION).create_index([("timestamp", -1)])
        self._collection(LOGIN_EVENTS_COLLECTION).create_index([("ip_address", 1), ("timestamp", -1)])
        self._collection(LOGIN_EVENTS_COLLECTION).create_index([("username", 1), ("timestamp", -1)])
        self._collection(ALERTS_COLLECTION).create_index([("alert_id", 1)], unique=True)
        self._collection(ALERTS_COLLECTION).create_index([("created_at", -1)])
        self._collection(ALERTS_COLLECTION).create_index([("severity", 1)])
        self._collection(RESPONSE_ACTIONS_COLLECTION).create_index([("alert_id", 1)])
        self._collection(FEEDBACK_COLLECTION).create_index([("feedback_id", 1)], unique=True)
        self._collection(FEEDBACK_COLLECTION).create_index([("alert_id", 1)])
        self._collection(TRAINING_RECORDS_COLLECTION).create_index([("training_record_id", 1)], unique=True)
        self._collection(TRAINING_RECORDS_COLLECTION).create_index([("alert_id", 1)])
        self.indexes_created = True

    def _collection(self, name: str):
        if get_collection is None:
            raise RuntimeError("MongoDB get_collection is unavailable")
        collection = get_collection(name)
        if collection is None:
            raise RuntimeError(f"MongoDB collection unavailable: {name}")
        return collection

    def _normalize_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        timestamp = event.get("timestamp") or event.get("occurred_at")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return {
            "event_id": event.get("event_id") or f"CLE-{uuid.uuid4().hex[:10].upper()}",
            "username": str(event.get("username", "unknown")).strip().lower(),
            "ip_address": str(event.get("ip_address") or event.get("ip") or "unknown").strip(),
            "success": bool(event.get("success", False)),
            "timestamp": timestamp,
            "user_agent": event.get("user_agent") or "unknown",
            "country": event.get("country") or "unknown",
            "source": event.get("source", "api"),
            "is_synthetic": bool(event.get("is_synthetic", False)),
        }

    def _store_login_event(self, event: Dict[str, Any]) -> str:
        self._collection(LOGIN_EVENTS_COLLECTION).insert_one(event.copy())
        return event["event_id"]

    def _detect(self, event: Dict[str, Any], additional_events: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        window_start = event["timestamp"] - timedelta(minutes=WINDOW_MINUTES)
        recent_events = self._recent_events(event, window_start)

        seen_event_ids = {item.get("event_id") for item in recent_events}
        if additional_events:
            for item in additional_events:
                normalized = self._normalize_event(item)
                if (
                    normalized["event_id"] not in seen_event_ids
                    and window_start <= normalized["timestamp"] <= event["timestamp"]
                ):
                    recent_events.append(normalized)
                    seen_event_ids.add(normalized["event_id"])

        by_ip = [item for item in recent_events if item["ip_address"] == event["ip_address"]]
        by_username = [item for item in recent_events if item["username"] == event["username"]]
        failed_by_ip = [item for item in by_ip if not item["success"]]
        failed_for_username = [item for item in by_username if not item["success"]]

        features = {
            "failed_attempts_from_ip": len(failed_by_ip),
            "unique_usernames_from_ip": len({item["username"] for item in by_ip}),
            "failed_attempts_for_username": len(failed_for_username),
            "unique_ips_for_username": len({item["ip_address"] for item in failed_for_username}),
            "attempts_per_minute": round(len(by_ip) / WINDOW_MINUTES, 2),
            "success_after_failures": bool(event["success"] and len(failed_by_ip) >= 5),
            "user_agent_variation": len({item["user_agent"] for item in by_ip}),
            "country_variation": len({item["country"] for item in by_ip}),
        }

        evidence = []
        score = 0.0
        if features["failed_attempts_from_ip"] >= 10:
            score += 0.40
            evidence.append(f"IP {event['ip_address']} has {features['failed_attempts_from_ip']} failed attempts in {WINDOW_MINUTES} minutes.")
        if features["unique_usernames_from_ip"] >= 5:
            score += 0.25
            evidence.append(f"IP {event['ip_address']} targeted {features['unique_usernames_from_ip']} unique usernames.")
        if features["unique_ips_for_username"] >= 3:
            score += 0.25
            evidence.append(f"Username {event['username']} received failed attempts from {features['unique_ips_for_username']} unique IPs.")
        if features["attempts_per_minute"] >= 10:
            score += 0.20
            evidence.append(f"IP {event['ip_address']} reached {features['attempts_per_minute']} attempts per minute.")
        if features["success_after_failures"]:
            score += 0.25
            evidence.append("Successful login occurred after multiple failures from a suspicious IP.")
        if features["user_agent_variation"] >= 3:
            score += 0.05
            evidence.append(f"Observed {features['user_agent_variation']} user agents from the same IP.")
        if features["country_variation"] >= 3:
            score += 0.05
            evidence.append(f"Observed {features['country_variation']} countries from the same IP.")

        risk_score = round(min(score, 1.0), 2)
        if not evidence:
            evidence.append("No credential stuffing rule thresholds were met.")

        return {
            "risk_score": risk_score,
            "confidence": risk_score,
            "severity": self._severity(risk_score),
            "evidence": evidence,
            "features": features,
            "recommended_action": self._recommended_action(risk_score),
        }

    def _recent_events(self, event: Dict[str, Any], window_start: datetime) -> List[Dict[str, Any]]:
        query = {
            "timestamp": {"$gte": window_start, "$lte": event["timestamp"]},
            "$or": [
                {"ip_address": event["ip_address"]},
                {"username": event["username"]},
            ],
        }
        return list(self._collection(LOGIN_EVENTS_COLLECTION).find(query))

    def _store_alert(self, event: Dict[str, Any], result: Dict[str, Any], source: str) -> Dict[str, Any]:
        alert = {
            "alert_id": f"CSA-{uuid.uuid4().hex[:10].upper()}",
            "event_id": event["event_id"],
            "source_ip": event["ip_address"],
            "username": event["username"],
            "confidence": result["confidence"],
            "risk_score": result["risk_score"],
            "severity": result["severity"],
            "evidence": result["evidence"],
            "features": result["features"],
            "recommended_action": result["recommended_action"],
            "source": source,
            "status": "active",
            "feedback": None,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }
        self._collection(ALERTS_COLLECTION).insert_one(alert.copy())
        return alert

    def _store_response_action(self, alert: Dict[str, Any], result: Dict[str, Any]) -> None:
        action_doc = {
            "action_id": f"CRA-{uuid.uuid4().hex[:10].upper()}",
            "alert_id": alert["alert_id"],
            "recommended_action": result["recommended_action"],
            "severity": result["severity"],
            "status": "recommended",
            "details": "Phase 1 records recommended response actions only.",
            "created_at": datetime.now(timezone.utc),
        }
        self._collection(RESPONSE_ACTIONS_COLLECTION).insert_one(action_doc)

    def _severity(self, risk_score: float) -> str:
        if risk_score >= 0.70:
            return "HIGH"
        if risk_score >= 0.40:
            return "MEDIUM"
        return "LOW"

    def _recommended_action(self, risk_score: float) -> str:
        if risk_score >= 0.70:
            return "block_ip_or_lock_account"
        if risk_score >= 0.40:
            return "notify_admin"
        return "log_only"

    def _feedback_to_label(self, feedback: str) -> int:
        if feedback == "true_positive":
            return 1
        if feedback == "false_positive":
            return 0
        return -1

    def _public_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        public_event = event.copy()
        public_event["timestamp"] = public_event["timestamp"].isoformat()
        return public_event

    def _serialize(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        serialized = {}
        for key, value in doc.items():
            if key == "_id":
                serialized["id"] = str(value)
            elif isinstance(value, datetime):
                serialized[key] = value.isoformat()
            else:
                serialized[key] = value
        return serialized


_credential_stuffing_service: Optional[CredentialStuffingService] = None


def get_credential_stuffing_service() -> CredentialStuffingService:
    global _credential_stuffing_service
    if _credential_stuffing_service is None:
        _credential_stuffing_service = CredentialStuffingService()
    return _credential_stuffing_service
