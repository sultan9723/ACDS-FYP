"""
Credential Stuffing Detection Service
=====================================
Rule-based Phase 1 detection for suspicious login behavior.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import random
import uuid
from typing import Any, Dict, List, Optional

import joblib
import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

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
REPORTS_DIR = Path(__file__).resolve().parents[2] / "reports" / "credential_stuffing"

WINDOW_MINUTES = 5
MODEL_FEATURE_COLUMNS = [
    "failed_attempts_from_ip",
    "unique_usernames_from_ip",
    "failed_attempts_for_username",
    "unique_ips_for_username",
    "attempts_per_minute",
    "success_after_failures",
    "user_agent_variation",
    "country_variation",
]


def _resolve_model_path() -> Path:
    """Resolve the trusted local model path across dev and Docker layouts."""
    service_path = Path(__file__).resolve()
    candidates = [
        service_path.parents[2] / "models" / "credential_stuffing_model.joblib",
        service_path.parents[1] / "models" / "credential_stuffing_model.joblib",
        Path.cwd() / "models" / "credential_stuffing_model.joblib",
        Path("/app/models/credential_stuffing_model.joblib"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


class CredentialStuffingService:
    """Service for storing login events and detecting credential stuffing."""

    def __init__(self):
        self.indexes_created = False
        self.model = None
        self.model_path = _resolve_model_path()
        self.model_load_attempted = False
        self.model_load_error: Optional[str] = None

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
            "phase": "rule_based_with_optional_ml",
            "database_available": database_available,
            "collections_available": collections_available,
            "model_available": self._get_model() is not None,
            "model_path": str(self.model_path),
            "model_load_error": self.model_load_error,
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
            "detection_source": result["detection_source"],
            "model_available": result["model_available"],
            "model_path": result["model_path"],
            "model_prediction": result["model_prediction"],
            "model_confidence": result["model_confidence"],
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
                "detection_source": result["detection_source"],
                "model_available": result["model_available"],
                "model_path": result["model_path"],
                "model_prediction": result["model_prediction"],
                "model_confidence": result["model_confidence"],
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
            "detection_source": highest_result["detection_source"] if highest_result else "fallback_rule_based",
            "model_available": highest_result["model_available"] if highest_result else self._get_model() is not None,
            "model_path": highest_result["model_path"] if highest_result else str(self.model_path),
            "model_prediction": highest_result["model_prediction"] if highest_result else None,
            "model_confidence": highest_result["model_confidence"] if highest_result else None,
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

    def generate_alert_pdf_report(self, alert_id: str) -> Path:
        self._ensure_indexes()

        alert = self._collection(ALERTS_COLLECTION).find_one({"alert_id": alert_id})
        if not alert:
            raise LookupError(f"Alert not found: {alert_id}")

        feedback_doc = None
        feedback_id = alert.get("feedback_id")
        if feedback_id:
            feedback_doc = self._collection(FEEDBACK_COLLECTION).find_one({"feedback_id": feedback_id})
        if feedback_doc is None:
            feedback_doc = self._collection(FEEDBACK_COLLECTION).find_one({"alert_id": alert_id})

        try:
            REPORTS_DIR.mkdir(parents=True, exist_ok=True)
            safe_alert_id = "".join(char if char.isalnum() or char in {"-", "_"} else "_" for char in alert_id)
            report_path = REPORTS_DIR / f"credential_stuffing_report_{safe_alert_id}.pdf"
            self._build_pdf_report(report_path, alert, feedback_doc)
            return report_path
        except Exception as e:
            raise RuntimeError(f"Failed to generate credential stuffing PDF report: {e}")

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
            "detection_source": result["detection_source"],
            "model_available": result["model_available"],
            "model_path": result["model_path"],
            "model_prediction": result["model_prediction"],
            "model_confidence": result["model_confidence"],
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
            evidence.append(f"Rule engine: IP {event['ip_address']} has {features['failed_attempts_from_ip']} failed attempts in {WINDOW_MINUTES} minutes.")
        if features["unique_usernames_from_ip"] >= 5:
            score += 0.25
            evidence.append(f"Rule engine: IP {event['ip_address']} targeted {features['unique_usernames_from_ip']} unique usernames.")
        if features["unique_ips_for_username"] >= 3:
            score += 0.25
            evidence.append(f"Rule engine: Username {event['username']} received failed attempts from {features['unique_ips_for_username']} unique IPs.")
        if features["attempts_per_minute"] >= 10:
            score += 0.20
            evidence.append(f"Rule engine: IP {event['ip_address']} reached {features['attempts_per_minute']} attempts per minute.")
        if features["success_after_failures"]:
            score += 0.25
            evidence.append("Rule engine: Successful login occurred after multiple failures from a suspicious IP.")
        if features["user_agent_variation"] >= 3:
            score += 0.05
            evidence.append(f"Rule engine: Observed {features['user_agent_variation']} user agents from the same IP.")
        if features["country_variation"] >= 3:
            score += 0.05
            evidence.append(f"Rule engine: Observed {features['country_variation']} countries from the same IP.")

        rule_score = round(min(score, 1.0), 2)
        if not evidence:
            evidence.append("Rule engine: No credential stuffing rule thresholds were met.")

        model_status = self._predict_with_model(features, event)
        risk_score = rule_score
        detection_source = "rule_based" if model_status["model_available"] else "fallback_rule_based"

        if model_status["model_available"]:
            if model_status["model_prediction"] == 1:
                model_confidence = model_status["model_confidence"]
                model_score = model_confidence if model_confidence is not None else 0.65
                evidence.append(
                    "ML model: predicted credential stuffing risk"
                    + (f" with confidence {model_confidence:.2f}." if model_confidence is not None else ".")
                )
                if rule_score >= 0.70:
                    risk_score = rule_score
                    detection_source = "hybrid"
                    evidence.append("Hybrid decision: rule-based HIGH severity preserved; ML cannot reduce it.")
                elif rule_score >= 0.40:
                    risk_score = round(max(rule_score, model_score, 0.40), 2)
                    detection_source = "hybrid"
                    evidence.append("Hybrid decision: rule and ML both contributed to the final risk.")
                else:
                    risk_score = round(max(rule_score, model_score, 0.40), 2)
                    detection_source = "ml_model"
                    evidence.append("ML model: raised low rule-based risk to at least MEDIUM.")
            else:
                evidence.append("ML model: did not predict credential stuffing risk.")
                detection_source = "rule_based"
        elif model_status.get("model_load_error"):
            evidence.append(f"ML model unavailable; using fallback rule-based detection. Reason: {model_status['model_load_error']}")
        else:
            evidence.append("ML model unavailable; using fallback rule-based detection.")

        risk_score = round(min(risk_score, 1.0), 2)

        return {
            "risk_score": risk_score,
            "confidence": risk_score,
            "severity": self._severity(risk_score),
            "evidence": evidence,
            "features": features,
            "recommended_action": self._recommended_action(risk_score),
            "detection_source": detection_source,
            **model_status,
        }

    def _get_model(self):
        if self.model_load_attempted:
            return self.model

        self.model_load_attempted = True
        self.model_path = _resolve_model_path()
        if not self.model_path.exists():
            self.model_load_error = "model file not found"
            return None

        try:
            # Only load the local trusted model artifact produced by the training pipeline.
            self.model = joblib.load(self.model_path)
            self.model_load_error = None
        except Exception as e:
            self.model = None
            self.model_load_error = str(e)
        return self.model

    def _predict_with_model(self, features: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        model = self._get_model()
        status = {
            "model_available": model is not None,
            "model_path": str(self.model_path),
            "model_prediction": None,
            "model_confidence": None,
            "model_load_error": self.model_load_error,
        }
        if model is None:
            return status

        row = {column: features[column] for column in MODEL_FEATURE_COLUMNS}
        row["success_after_failures"] = int(bool(row["success_after_failures"]))
        row["user_agent"] = event.get("user_agent") or "unknown"

        try:
            input_frame = pd.DataFrame([row])
            prediction = model.predict(input_frame)[0]
        except Exception:
            try:
                input_values = [[row[column] for column in MODEL_FEATURE_COLUMNS]]
                prediction = model.predict(input_values)[0]
            except Exception as e:
                status["model_available"] = False
                status["model_load_error"] = f"model prediction failed: {e}"
                return status

        status["model_prediction"] = int(prediction)

        if hasattr(model, "predict_proba"):
            try:
                proba = model.predict_proba(input_frame)
                classes = list(getattr(model, "classes_", []))
                if 1 in classes:
                    risk_index = classes.index(1)
                else:
                    risk_index = min(1, len(proba[0]) - 1)
                status["model_confidence"] = round(float(proba[0][risk_index]), 4)
            except Exception:
                status["model_confidence"] = None

        return status

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
            "detection_source": result.get("detection_source"),
            "model_available": result.get("model_available"),
            "model_path": result.get("model_path"),
            "model_prediction": result.get("model_prediction"),
            "model_confidence": result.get("model_confidence"),
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

    def _build_pdf_report(self, report_path: Path, alert: Dict[str, Any], feedback_doc: Optional[Dict[str, Any]]) -> None:
        styles = getSampleStyleSheet()
        story = [
            Paragraph("ACDS Credential Stuffing Incident Report", styles["Title"]),
            Spacer(1, 12),
        ]

        summary_fields = [
            "alert_id",
            "event_id",
            "username",
            "source_ip",
            "severity",
            "confidence",
            "risk_score",
            "detection_source",
            "model_available",
            "model_prediction",
            "model_confidence",
            "recommended_action",
            "status",
            "created_at",
            "updated_at",
        ]
        story.append(Paragraph("Incident Summary", styles["Heading2"]))
        story.append(self._pdf_table([[field, self._format_pdf_value(alert.get(field))] for field in summary_fields]))
        story.append(Spacer(1, 12))

        story.append(Paragraph("Evidence", styles["Heading2"]))
        evidence = alert.get("evidence") or []
        evidence_rows = [[str(index + 1), str(item)] for index, item in enumerate(evidence)]
        story.append(self._pdf_table(evidence_rows or [["-", "No evidence recorded."]]))
        story.append(Spacer(1, 12))

        story.append(Paragraph("Behavioral Features", styles["Heading2"]))
        features = alert.get("features") or {}
        feature_rows = [[key, self._format_pdf_value(value)] for key, value in features.items()]
        story.append(self._pdf_table(feature_rows or [["-", "No features recorded."]]))
        story.append(Spacer(1, 12))

        story.append(Paragraph("Analyst Feedback", styles["Heading2"]))
        feedback_rows = self._feedback_pdf_rows(alert, feedback_doc)
        story.append(self._pdf_table(feedback_rows))

        doc = SimpleDocTemplate(
            str(report_path),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
            title="ACDS Credential Stuffing Incident Report",
        )
        doc.build(story)

    def _pdf_table(self, rows: List[List[str]]) -> Table:
        table = Table(rows, colWidths=[160, 340])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E5E7EB")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#111827")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        return table

    def _feedback_pdf_rows(self, alert: Dict[str, Any], feedback_doc: Optional[Dict[str, Any]]) -> List[List[str]]:
        if feedback_doc:
            serialized_feedback = self._serialize(feedback_doc)
            return [[key, self._format_pdf_value(value)] for key, value in serialized_feedback.items() if key != "id"]
        if alert.get("feedback"):
            return [["feedback", self._format_pdf_value(alert.get("feedback"))]]
        return [["feedback", "No analyst feedback recorded."]]

    def _format_pdf_value(self, value: Any) -> str:
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, (dict, list)):
            return str(value)
        if value is None:
            return ""
        return str(value)

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
