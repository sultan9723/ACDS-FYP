"""
Ransomware incident report generation service.

Generates PDF reports from actual ransomware detection pipeline output and
stores report metadata for later download/history.
"""

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    from database.connection import get_collection
except ImportError:
    try:
        from backend.database.connection import get_collection
    except ImportError:
        get_collection = None


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORTS_DIR = PROJECT_ROOT / "reports" / "ransomware"
METADATA_PATH = REPORTS_DIR / "ransomware_reports_metadata.json"


class RansomwareIncidentReportService:
    """Create executive, analyst, and PDF incident reports for ransomware detections."""

    def __init__(self, reports_dir: Optional[Path] = None) -> None:
        self.reports_dir = reports_dir or REPORTS_DIR
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_path = self.reports_dir / METADATA_PATH.name
        self._reports_metadata = self._load_metadata()

    def generate_report(
        self,
        detection_result: Dict[str, Any],
        report_type: str = "technical",
        requested_by: str = "soc-console",
    ) -> Dict[str, Any]:
        """Generate report metadata, narrative sections, and a downloadable PDF."""
        if not REPORTLAB_AVAILABLE:
            raise RuntimeError("ReportLab is not installed; PDF generation is unavailable")
        if not detection_result:
            raise ValueError("A ransomware detection result is required")
        if report_type not in {"technical", "executive"}:
            raise ValueError("report_type must be technical or executive")

        normalized = self._normalize_detection(detection_result)
        report_id = f"RAN-RPT-{uuid.uuid4().hex[:10].upper()}"
        incident_id = normalized["incident_id"]
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_incident_id = re.sub(r"[^A-Za-z0-9_.-]", "_", incident_id)[:80]
        filename = f"ransomware_incident_{safe_incident_id}_{timestamp}.pdf"
        filepath = self.reports_dir / filename

        ai_summary = self._generate_ai_summary(normalized)
        executive_summary = self._generate_executive_summary(normalized)
        technical_summary = self._generate_technical_summary(normalized)
        mitre_mapping = self._map_mitre_attack(normalized)
        recommendations = self._generate_recommendations(normalized, mitre_mapping)

        self._create_pdf(
            filepath=filepath,
            report_id=report_id,
            report_type=report_type,
            normalized=normalized,
            ai_summary=ai_summary,
            executive_summary=executive_summary,
            technical_summary=technical_summary,
            mitre_mapping=mitre_mapping,
            recommendations=recommendations,
        )

        metadata = {
            "report_id": report_id,
            "incident_id": incident_id,
            "threat_id": normalized.get("threat_id"),
            "filename": filename,
            "filepath": str(filepath),
            "download_url": f"/api/v1/ransomware/reports/{report_id}/download",
            "report_type": report_type,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "requested_by": requested_by,
            "severity": normalized["severity"],
            "ml_threat_score": normalized["ml_threat_score"],
            "sha256": normalized["sha256"],
            "ai_summary": ai_summary,
            "executive_summary": executive_summary,
            "technical_summary": technical_summary,
            "mitre_mapping": mitre_mapping,
            "recommendations": recommendations,
        }
        self._reports_metadata.append(metadata)
        self._reports_metadata = self._reports_metadata[-500:]
        self._save_metadata()
        self._store_metadata_to_db(metadata)
        return metadata

    def list_reports(self, limit: int = 50, incident_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return historical ransomware report metadata."""
        records = self._reports_metadata
        if incident_id:
            records = [item for item in records if item.get("incident_id") == incident_id]
        return sorted(records, key=lambda item: item.get("generated_at", ""), reverse=True)[:limit]

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Return one report metadata record."""
        for report in self._reports_metadata:
            if report.get("report_id") == report_id:
                return report
        return None

    def get_report_path(self, report_id: str) -> Optional[Path]:
        """Return the generated PDF path if it exists."""
        report = self.get_report(report_id)
        if not report:
            return None
        path = Path(report.get("filepath", ""))
        if path.exists() and path.is_file():
            return path
        return None

    def _normalize_detection(self, result: Dict[str, Any]) -> Dict[str, Any]:
        layers = result.get("layers", {})
        layer1 = layers.get("layer1_command_behavior", {})
        layer2 = layers.get("layer2_pe_header", {})
        static = layers.get("layer2_static_executable_analysis", {})
        layer3 = layers.get("layer3_mass_encryption", {})
        sample = result.get("sample", {})
        pipeline = result.get("pipeline_results", {})
        detection = pipeline.get("detection", {})
        explainability = pipeline.get("explainability", {})
        response = pipeline.get("response", {})

        confidence = (
            result.get("detection_confidence")
            or detection.get("confidence")
            or layer2.get("model_confidence")
            or layer2.get("confidence")
            or 0
        )
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.0
        if confidence > 1:
            confidence = confidence / 100

        severity = result.get("severity") or layer1.get("severity")
        if not severity:
            severity = "CRITICAL" if confidence >= 0.85 else (
                "HIGH" if confidence >= 0.65 else (
                    "MEDIUM" if confidence >= 0.4 else "LOW"
                )
            )

        sha256 = (
            result.get("sha256")
            or sample.get("sha256")
            or static.get("sha256")
            or result.get("iocs", {}).get("sha256")
            or "N/A"
        )

        suspicious_imports = static.get("suspicious_imports") or []
        yara = static.get("yara") or {}
        response_actions = (
            result.get("response_actions")
            or response.get("actions_executed")
            or [item.get("label") for item in result.get("response_recommendations", []) if item.get("label")]
        )

        indicators = []
        indicators.extend(result.get("triggered_layers", []) or [])
        indicators.extend(static.get("indicators", []) or [])
        indicators.extend(layer1.get("detected_patterns", []) or [])
        indicators.extend(layer3.get("indicators", []) or [])
        indicators.extend(explainability.get("behavior_categories", []) or [])

        return {
            "incident_id": str(
                result.get("incident_id")
                or result.get("threat_id")
                or result.get("scan_id")
                or sha256
                or f"RAN-INC-{uuid.uuid4().hex[:8].upper()}"
            ),
            "threat_id": result.get("threat_id"),
            "timestamp": result.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "overall_verdict": result.get("overall_verdict") or (
                "RANSOMWARE_DETECTED" if detection.get("is_ransomware") else "SUSPICIOUS"
            ),
            "severity": str(severity).upper(),
            "ml_threat_score": round(confidence, 4),
            "source_host": result.get("source_host") or "unknown",
            "process_name": result.get("process_name") or sample.get("filename") or "unknown",
            "process_pid": result.get("process_pid") or layer3.get("process_pid"),
            "user": result.get("user"),
            "command": result.get("command") or detection.get("command") or "N/A",
            "file_name": sample.get("filename") or Path(layer2.get("binary_path", "")).name or "N/A",
            "file_path": sample.get("path") or layer2.get("binary_path") or "N/A",
            "file_size": sample.get("size_bytes") or static.get("size_bytes") or "N/A",
            "sha256": sha256,
            "entropy": static.get("entropy", "N/A"),
            "suspicious_imports": suspicious_imports,
            "suspicious_import_count": static.get("suspicious_import_count", len(suspicious_imports)),
            "yara_matches": yara.get("matches", []) if isinstance(yara, dict) else [],
            "yara_status": yara.get("status", "unavailable") if isinstance(yara, dict) else "unavailable",
            "features_extracted": layer2.get("features_extracted", "N/A"),
            "model_loaded": layer2.get("model_loaded", "N/A"),
            "affected_files": layer3.get("affected_files", "N/A"),
            "response_actions": [str(action) for action in response_actions if action],
            "response_recommendations": result.get("response_recommendations", []),
            "indicators": list(dict.fromkeys([str(item) for item in indicators if item])),
        }

    def _generate_ai_summary(self, data: Dict[str, Any]) -> str:
        score = round(data["ml_threat_score"] * 100, 1)
        evidence = []
        if data["sha256"] != "N/A":
            evidence.append("a quarantined executable sample with a SHA256 hash")
        if data["entropy"] != "N/A":
            evidence.append(f"entropy measured at {data['entropy']}")
        if data["suspicious_import_count"]:
            evidence.append(f"{data['suspicious_import_count']} suspicious import indicators")
        if data["yara_matches"]:
            evidence.append(f"{len(data['yara_matches'])} YARA rule match(es)")
        if not evidence:
            evidence.append("behavioral detection signals from the ransomware pipeline")
        return (
            f"The ransomware pipeline classified this incident as {data['severity']} with an "
            f"ML threat score of {score}%. The assessment is based on "
            f"{', '.join(evidence)} and the observed verdict {data['overall_verdict']}."
        )

    def _generate_executive_summary(self, data: Dict[str, Any]) -> str:
        return (
            f"Incident {data['incident_id']} requires {data['severity']} priority handling. "
            f"The detected activity involves {data['process_name']} on {data['source_host']} "
            f"and should remain contained while analysts validate the sample, review affected "
            f"assets, and confirm backup integrity."
        )

    def _generate_technical_summary(self, data: Dict[str, Any]) -> str:
        imports = ", ".join(data["suspicious_imports"][:8]) or "none observed"
        yara = ", ".join(data["yara_matches"][:8]) or data["yara_status"]
        return (
            f"File {data['file_name']} produced SHA256 {data['sha256']}. "
            f"Entropy: {data['entropy']}; PE features extracted: {data['features_extracted']}; "
            f"suspicious imports: {imports}; YARA: {yara}. "
            f"Response actions/recommendations recorded: {', '.join(data['response_actions']) or 'none'}."
        )

    def _map_mitre_attack(self, data: Dict[str, Any]) -> List[Dict[str, str]]:
        text = " ".join(data["indicators"]).lower()
        mappings = []
        if "shadow" in text or "backup" in text:
            mappings.append({
                "technique": "T1490",
                "name": "Inhibit System Recovery",
                "evidence": "Shadow copy or backup interference indicator observed.",
            })
        if "encryption" in text or "mass" in text or data["affected_files"] != "N/A":
            mappings.append({
                "technique": "T1486",
                "name": "Data Encrypted for Impact",
                "evidence": "Mass-encryption or file encryption behavior observed.",
            })
        if "command" in text or data["command"] != "N/A":
            mappings.append({
                "technique": "T1059",
                "name": "Command and Scripting Interpreter",
                "evidence": "Suspicious command behavior was present in the detection context.",
            })
        if data["suspicious_imports"]:
            mappings.append({
                "technique": "T1027",
                "name": "Obfuscated Files or Information",
                "evidence": "Suspicious executable imports or packed-code indicators were observed.",
            })
        if not mappings:
            mappings.append({
                "technique": "T1486",
                "name": "Data Encrypted for Impact",
                "evidence": "Ransomware verdict generated by the detection pipeline.",
            })
        return mappings

    def _generate_recommendations(
        self,
        data: Dict[str, Any],
        mitre_mapping: List[Dict[str, str]],
    ) -> List[str]:
        recommendations = [
            "Keep the sample in quarantine and preserve file metadata for forensic review.",
            "Validate host containment status before restoring normal network access.",
            "Review response action history and confirm analyst approval for simulated actions.",
            "Search endpoint and SIEM telemetry for the reported SHA256 and process name.",
            "Confirm recent backups are clean before any restoration activity.",
        ]
        techniques = {item["technique"] for item in mitre_mapping}
        if "T1490" in techniques:
            recommendations.append("Inspect shadow copy and backup logs for deletion or tampering attempts.")
        if "T1486" in techniques:
            recommendations.append("Measure file modification rates on adjacent hosts for lateral encryption spread.")
        if data["yara_matches"]:
            recommendations.append("Promote matching YARA rules to monitored repositories after analyst validation.")
        return recommendations

    def _create_pdf(
        self,
        filepath: Path,
        report_id: str,
        report_type: str,
        normalized: Dict[str, Any],
        ai_summary: str,
        executive_summary: str,
        technical_summary: str,
        mitre_mapping: List[Dict[str, str]],
        recommendations: List[str],
    ) -> None:
        doc = SimpleDocTemplate(str(filepath), pagesize=letter, topMargin=0.45 * inch, bottomMargin=0.45 * inch)
        styles = getSampleStyleSheet()
        title = ParagraphStyle("RansomwareTitle", parent=styles["Heading1"], fontSize=18, textColor=colors.HexColor("#0f172a"))
        section = ParagraphStyle("RansomwareSection", parent=styles["Heading2"], fontSize=12, textColor=colors.HexColor("#2563eb"), spaceBefore=12)
        body = ParagraphStyle("RansomwareBody", parent=styles["BodyText"], fontSize=9, leading=12)
        small = ParagraphStyle("RansomwareSmall", parent=styles["BodyText"], fontSize=8, leading=10)

        story = [
            Paragraph("Ransomware Incident Report", title),
            Paragraph(f"Report ID: {report_id} | Type: {report_type.title()}", small),
            Spacer(1, 0.15 * inch),
        ]

        summary_rows = [
            ["Incident ID", normalized["incident_id"]],
            ["Generated At", datetime.now(timezone.utc).isoformat()],
            ["Detection Timestamp", normalized["timestamp"]],
            ["Verdict", normalized["overall_verdict"]],
            ["Severity", normalized["severity"]],
            ["ML Threat Score", f"{normalized['ml_threat_score'] * 100:.1f}%"],
            ["Source Host", normalized["source_host"]],
            ["Process", f"{normalized['process_name']} ({normalized.get('process_pid') or 'pid N/A'})"],
        ]
        story.append(self._table(summary_rows))
        story.extend([Spacer(1, 0.12 * inch), Paragraph("AI-Generated Threat Summary", section), Paragraph(ai_summary, body)])
        story.extend([Paragraph("Executive Summary", section), Paragraph(executive_summary, body)])
        story.extend([Paragraph("Technical Analyst Summary", section), Paragraph(technical_summary, body)])

        file_rows = [
            ["File Name", normalized["file_name"]],
            ["File Path", normalized["file_path"]],
            ["File Size", str(normalized["file_size"])],
            ["SHA256", normalized["sha256"]],
            ["Entropy", str(normalized["entropy"])],
            ["Suspicious Imports", ", ".join(normalized["suspicious_imports"]) or "None observed"],
            ["YARA Matches", ", ".join(normalized["yara_matches"]) or normalized["yara_status"]],
            ["PE Features Extracted", str(normalized["features_extracted"])],
        ]
        story.extend([Paragraph("File And ML Evidence", section), self._table(file_rows)])

        mitre_rows = [["Technique", "Name", "Evidence"]]
        mitre_rows.extend([[item["technique"], item["name"], item["evidence"]] for item in mitre_mapping])
        story.extend([Paragraph("MITRE ATT&CK Mapping", section), self._table(mitre_rows, header=True)])

        response_rows = [[action, "Recorded"] for action in normalized["response_actions"]]
        if not response_rows:
            response_rows = [["No response action recorded", "Pending analyst action"]]
        story.extend([Paragraph("Response Actions", section), self._table(response_rows)])

        story.append(Paragraph("Recommended Remediation", section))
        for index, item in enumerate(recommendations, start=1):
            story.append(Paragraph(f"{index}. {item}", body))

        doc.build(story)

    def _table(self, rows: List[List[Any]], header: bool = False) -> Table:
        styles = getSampleStyleSheet()
        cell_style = ParagraphStyle("RansomwareTableCell", parent=styles["BodyText"], fontSize=8, leading=10)
        wrapped_rows = [
            [Paragraph(escape(str(cell)), cell_style) for cell in row]
            for row in rows
        ]
        table = Table(wrapped_rows, colWidths=[1.65 * inch, 2.05 * inch, 2.8 * inch] if header else [1.6 * inch, 4.9 * inch])
        style = [
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]
        if header:
            style.extend([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e0f2fe")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ])
        table.setStyle(TableStyle(style))
        return table

    def _load_metadata(self) -> List[Dict[str, Any]]:
        if not self.metadata_path.exists():
            return []
        try:
            with self.metadata_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, list):
                return data
        except (OSError, json.JSONDecodeError):
            return []
        return []

    def _save_metadata(self) -> None:
        with self.metadata_path.open("w", encoding="utf-8") as handle:
            json.dump(self._reports_metadata, handle, indent=2)

    def _store_metadata_to_db(self, metadata: Dict[str, Any]) -> None:
        if get_collection is None:
            return
        try:
            collection = get_collection("ransomware_incident_reports")
            if collection is not None:
                collection.insert_one(metadata.copy())
        except Exception:
            return


_service_instance: Optional[RansomwareIncidentReportService] = None


def get_ransomware_incident_report_service() -> RansomwareIncidentReportService:
    """Return the singleton ransomware report service."""
    global _service_instance
    if _service_instance is None:
        _service_instance = RansomwareIncidentReportService()
    return _service_instance
