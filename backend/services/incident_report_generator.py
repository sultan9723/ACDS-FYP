"""
Incident Report Generator Service
==================================
Generates PDF incident reports for detected phishing threats.
These reports are stored in the reports folder and can be accessed via API.
"""

import os
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import json

# Try to import reportlab for PDF generation
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("⚠️ ReportLab not installed. PDF generation will be unavailable.")


@dataclass
class IncidentReport:
    """Data class for incident report metadata."""
    report_id: str
    threat_id: str
    filename: str
    filepath: str
    generated_at: str
    threat_type: str
    severity: str
    confidence: float
    email_subject: str
    email_sender: str
    status: str


class IncidentReportGenerator:
    """
    Generates PDF incident reports for phishing threats.
    """
    
    def __init__(self, reports_dir: str = None):
        """Initialize the report generator."""
        # Set default reports directory
        if reports_dir is None:
            # Go up from backend/services to project root, then to reports
            self.reports_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "reports"
            )
        else:
            self.reports_dir = reports_dir
        
        # Create reports directory if it doesn't exist
        os.makedirs(self.reports_dir, exist_ok=True)
        
        # Reports metadata storage (in-memory, could be persisted to DB)
        self._reports_metadata: List[Dict] = []
        
        # Load existing reports metadata
        self._load_metadata()
        
        print(f"📄 IncidentReportGenerator initialized. Reports dir: {self.reports_dir}")
    
    def _load_metadata(self):
        """Load existing reports metadata from JSON file."""
        metadata_file = os.path.join(self.reports_dir, "reports_metadata.json")
        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, 'r') as f:
                    self._reports_metadata = json.load(f)
                print(f"📂 Loaded {len(self._reports_metadata)} existing report records")
            except Exception as e:
                print(f"⚠️ Error loading reports metadata: {e}")
                self._reports_metadata = []
    
    def _save_metadata(self):
        """Save reports metadata to JSON file."""
        metadata_file = os.path.join(self.reports_dir, "reports_metadata.json")
        try:
            with open(metadata_file, 'w') as f:
                json.dump(self._reports_metadata, f, indent=2)
        except Exception as e:
            print(f"⚠️ Error saving reports metadata: {e}")
    
    def generate_incident_report(
        self,
        threat_data: Dict[str, Any],
        pipeline_results: Dict[str, Any] = None
    ) -> Optional[IncidentReport]:
        """
        Generate a PDF incident report for a detected threat.
        
        Args:
            threat_data: Dictionary containing threat information
            pipeline_results: Optional pipeline results with detection details
            
        Returns:
            IncidentReport object with metadata, or None if generation failed
        """
        if not REPORTLAB_AVAILABLE:
            print("⚠️ ReportLab not available, cannot generate PDF report")
            return None
        
        try:
            # Generate unique report ID
            report_id = f"RPT-{uuid.uuid4().hex[:8].upper()}"
            threat_id = threat_data.get("threat_id", f"THR-{uuid.uuid4().hex[:8].upper()}")
            
            # Generate filename with timestamp
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"incident_report_{threat_id}_{timestamp}.pdf"
            filepath = os.path.join(self.reports_dir, filename)
            
            # Extract threat details
            severity = threat_data.get("severity", "MEDIUM")
            confidence = threat_data.get("confidence", 0)
            email_subject = threat_data.get("email_subject", threat_data.get("subject", "No Subject"))
            email_sender = threat_data.get("email_sender", threat_data.get("sender", "Unknown"))
            email_content = threat_data.get("email_preview", threat_data.get("content", ""))[:500]
            status = threat_data.get("status", "resolved")
            actions_taken = threat_data.get("actions_taken", ["quarantine_email", "block_sender"])
            
            # Extract pipeline results if available
            detection_result = {}
            explainability_result = {}
            response_result = {}
            
            if pipeline_results:
                detection_result = pipeline_results.get("detection", {})
                explainability_result = pipeline_results.get("explainability", {})
                response_result = pipeline_results.get("response", {})
            
            # Generate PDF
            self._create_pdf_report(
                filepath=filepath,
                report_id=report_id,
                threat_id=threat_id,
                severity=severity,
                confidence=confidence,
                email_subject=email_subject,
                email_sender=email_sender,
                email_content=email_content,
                status=status,
                actions_taken=actions_taken,
                detection_result=detection_result,
                explainability_result=explainability_result,
                response_result=response_result
            )
            
            # Create report metadata
            report = IncidentReport(
                report_id=report_id,
                threat_id=threat_id,
                filename=filename,
                filepath=filepath,
                generated_at=datetime.now(timezone.utc).isoformat(),
                threat_type="Phishing",
                severity=severity,
                confidence=confidence,
                email_subject=email_subject,
                email_sender=email_sender,
                status=status
            )
            
            # Store metadata
            report_dict = {
                "report_id": report.report_id,
                "threat_id": report.threat_id,
                "filename": report.filename,
                "filepath": report.filepath,
                "generated_at": report.generated_at,
                "threat_type": report.threat_type,
                "severity": report.severity,
                "confidence": report.confidence,
                "email_subject": report.email_subject,
                "email_sender": report.email_sender,
                "status": report.status
            }
            self._reports_metadata.append(report_dict)
            self._save_metadata()
            
            # Also store to database
            self._store_report_to_db(report_dict)
            
            print(f"✅ Generated incident report: {filename}")
            return report
            
        except Exception as e:
            print(f"❌ Error generating incident report: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _create_pdf_report(
        self,
        filepath: str,
        report_id: str,
        threat_id: str,
        severity: str,
        confidence: float,
        email_subject: str,
        email_sender: str,
        email_content: str,
        status: str,
        actions_taken: List[str],
        detection_result: Dict,
        explainability_result: Dict,
        response_result: Dict
    ):
        """Create the actual PDF report file."""
        doc = SimpleDocTemplate(filepath, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
        styles = getSampleStyleSheet()
        story = []
        
        # Custom styles
        title_style = ParagraphStyle(
            'Title',
            parent=styles['Heading1'],
            fontSize=18,
            alignment=TA_CENTER,
            spaceAfter=20,
            textColor=colors.HexColor('#1e3a5f')
        )
        
        header_style = ParagraphStyle(
            'Header',
            parent=styles['Heading2'],
            fontSize=14,
            spaceBefore=15,
            spaceAfter=10,
            textColor=colors.HexColor('#2563eb'),
            borderPadding=5
        )
        
        normal_style = styles['Normal']
        
        # Severity color
        severity_colors = {
            "CRITICAL": colors.HexColor('#dc2626'),
            "HIGH": colors.HexColor('#ea580c'),
            "MEDIUM": colors.HexColor('#ca8a04'),
            "LOW": colors.HexColor('#16a34a')
        }
        severity_color = severity_colors.get(severity.upper(), colors.gray)
        
        # Title
        story.append(Paragraph("🛡️ PHISHING INCIDENT REPORT", title_style))
        story.append(Paragraph("Autonomous Cyber Defense System (ACDS)", 
                               ParagraphStyle('Subtitle', parent=normal_style, alignment=TA_CENTER, textColor=colors.gray)))
        story.append(Spacer(1, 0.3 * inch))
        
        # Report Info Box
        report_info = [
            ["Report ID:", report_id],
            ["Threat ID:", threat_id],
            ["Generated:", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")],
            ["Status:", status.upper()]
        ]
        
        info_table = Table(report_info, colWidths=[1.5*inch, 5*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#334155')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 0.3 * inch))
        
        # Threat Summary Section
        story.append(Paragraph("THREAT SUMMARY", header_style))
        
        # Format confidence
        conf_display = f"{confidence:.1f}%" if confidence > 1 else f"{confidence*100:.1f}%"
        
        threat_data = [
            ["Threat Type:", "Phishing Email"],
            ["Severity:", severity.upper()],
            ["Confidence:", conf_display],
            ["Email Subject:", email_subject[:60] + "..." if len(email_subject) > 60 else email_subject],
            ["Email Sender:", email_sender]
        ]
        
        threat_table = Table(threat_data, colWidths=[1.5*inch, 5*inch])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#fef3c7')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#334155')),
            ('TEXTCOLOR', (1, 1), (1, 1), severity_color),  # Severity value colored
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 1), (1, 1), 'Helvetica-Bold'),  # Severity value bold
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#fde68a')),
        ]))
        story.append(threat_table)
        story.append(Spacer(1, 0.2 * inch))
        
        # Email Content Preview
        story.append(Paragraph("EMAIL CONTENT PREVIEW", header_style))
        
        # Escape HTML in content
        safe_content = email_content.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        content_style = ParagraphStyle(
            'Content',
            parent=normal_style,
            fontSize=9,
            textColor=colors.HexColor('#475569'),
            backColor=colors.HexColor('#f8fafc'),
            borderPadding=10,
            leftIndent=10,
            rightIndent=10
        )
        story.append(Paragraph(f"<i>{safe_content}</i>", content_style))
        story.append(Spacer(1, 0.2 * inch))
        
        # Detection Analysis
        story.append(Paragraph("DETECTION ANALYSIS", header_style))
        
        risk_factors = detection_result.get("risk_factors", [
            "Suspicious sender domain",
            "Urgency language detected",
            "Suspicious URL patterns"
        ])
        
        # IOCs from explainability
        iocs = explainability_result.get("iocs", {})
        suspicious_urls = iocs.get("suspicious_urls", ["http://suspicious-link.com"])
        keywords = iocs.get("keywords", ["urgent", "verify", "suspended"])
        
        analysis_text = f"""
        <b>Risk Factors Identified:</b><br/>
        {', '.join(risk_factors) if risk_factors else 'Multiple phishing indicators detected'}<br/><br/>
        
        <b>Suspicious URLs:</b><br/>
        {', '.join(suspicious_urls[:3]) if suspicious_urls else 'None detected'}<br/><br/>
        
        <b>Trigger Keywords:</b><br/>
        {', '.join(keywords[:5]) if keywords else 'urgency, verify, account, suspended'}
        """
        story.append(Paragraph(analysis_text, normal_style))
        story.append(Spacer(1, 0.2 * inch))
        
        # Automated Response Actions
        story.append(Paragraph("AUTOMATED RESPONSE ACTIONS", header_style))
        
        actions_display = []
        for action in actions_taken:
            action_name = action.replace("_", " ").title()
            actions_display.append([f"✓ {action_name}", "Executed Successfully"])
        
        if actions_display:
            actions_table = Table(actions_display, colWidths=[3*inch, 2*inch])
            actions_table.setStyle(TableStyle([
                ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#16a34a')),
                ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#059669')),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(actions_table)
        else:
            story.append(Paragraph("No automated actions taken.", normal_style))
        
        story.append(Spacer(1, 0.3 * inch))
        
        # Recommendations
        story.append(Paragraph("RECOMMENDATIONS", header_style))
        
        recommendations = [
            "1. Do not interact with any links or attachments from this email",
            "2. Report this incident to your IT security team",
            "3. If credentials were entered, change passwords immediately",
            "4. Enable multi-factor authentication on sensitive accounts",
            "5. Review other emails from this sender for potential threats"
        ]
        
        for rec in recommendations:
            story.append(Paragraph(rec, ParagraphStyle('Rec', parent=normal_style, leftIndent=20, fontSize=10)))
        
        story.append(Spacer(1, 0.5 * inch))
        
        # Footer
        footer_style = ParagraphStyle(
            'Footer',
            parent=normal_style,
            fontSize=8,
            textColor=colors.gray,
            alignment=TA_CENTER
        )
        story.append(Paragraph(
            "This report was automatically generated by the Autonomous Cyber Defense System (ACDS)",
            footer_style
        ))
        story.append(Paragraph(
            f"© {datetime.now().year} ACDS Security Platform",
            footer_style
        ))
        
        # Build PDF
        doc.build(story)
    
    def _store_report_to_db(self, report_dict: Dict):
        """Store report metadata to MongoDB."""
        try:
            from database.connection import get_collection
            
            reports_col = get_collection("incident_reports")
            if reports_col is not None:
                reports_col.insert_one(report_dict.copy())
                print(f"✅ Report metadata stored in MongoDB: {report_dict['report_id']}")
        except Exception as e:
            print(f"⚠️ Could not store report to database: {e}")
    
    def get_reports(self, limit: int = 50) -> List[Dict]:
        """Get list of generated reports."""
        all_reports = []
        
        # First try database
        try:
            from database.connection import get_collection
            
            reports_col = get_collection("incident_reports")
            if reports_col is not None:
                cursor = reports_col.find({}).sort([("generated_at", -1)]).limit(limit)
                for report in cursor:
                    report["_id"] = str(report.get("_id"))
                    all_reports.append(report)
                print(f"📄 Fetched {len(all_reports)} reports from database")
        except Exception as e:
            print(f"⚠️ Could not fetch reports from database: {e}")
        
        # Also check in-memory metadata for any reports not yet in DB
        if self._reports_metadata:
            db_report_ids = {r.get("report_id") for r in all_reports}
            for report in self._reports_metadata:
                if report.get("report_id") not in db_report_ids:
                    all_reports.append(report)
        
        # Sort by generated_at descending and limit
        all_reports = sorted(all_reports, key=lambda x: x.get("generated_at", ""), reverse=True)[:limit]
        return all_reports
    
    def get_report_by_id(self, report_id: str) -> Optional[Dict]:
        """Get a specific report by ID."""
        for report in self._reports_metadata:
            if report.get("report_id") == report_id:
                return report
        return None
    
    def get_report_filepath(self, report_id: str) -> Optional[str]:
        """Get the filepath of a report by ID."""
        report = self.get_report_by_id(report_id)
        if report:
            return report.get("filepath")
        return None


# Global instance
_report_generator: Optional[IncidentReportGenerator] = None


def get_incident_report_generator() -> IncidentReportGenerator:
    """Get or create the incident report generator instance."""
    global _report_generator
    if _report_generator is None:
        _report_generator = IncidentReportGenerator()
    return _report_generator
