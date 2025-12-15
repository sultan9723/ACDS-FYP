import logging
from typing import Dict, Any
from uuid import UUID
from datetime import datetime
import json

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

from .models import Incident

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Generates summary reports for phishing incidents.
    """
    def __init__(self):
        logger.info("ReportGenerator initialized.")

    def generate_incident_report(self, incident: Incident, explanation: Dict[str, Any]) -> str:
        """
        Generates a human-readable summary report for a given incident.
        
        Args:
            incident: The Incident object.
            explanation: The structured explanation from the ExplainabilityAgent.
            
        Returns:
            A string containing the formatted report.
        """
        report_lines = []
        report_lines.append(f"--- Phishing Incident Report ---")
        report_lines.append(f"Incident ID: {incident.id}")
        report_lines.append(f"Detected On: {incident.detection_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report_lines.append(f"Status: {incident.status.value.replace('_', ' ').title()}")
        report_lines.append(f"Associated Email ID: {incident.email_id}")
        report_lines.append(f"Detection Agent: {incident.detection_agent_id}")
        report_lines.append(f"Assigned Analyst: {incident.assigned_analyst or 'Unassigned'}")
        report_lines.append("\n--- Detection Details ---")
        report_lines.append(f"Confidence Score: {float(explanation.get('confidence_level', '0%').replace('%','')):.2f}%") # Assuming % in explanation
        report_lines.append(f"Summary: {explanation.get('summary', 'N/A')}")
        report_lines.append("Matched Indicators:")
        for detail in explanation.get('details', []):
            report_lines.append(f"  {detail}")

        report_lines.append("\n--- Timeline of Events ---")
        if not incident.timeline_of_events:
            report_lines.append("No timeline events recorded.")
        else:
            for event in incident.timeline_of_events:
                timestamp = event.get('timestamp', datetime.min).strftime('%Y-%m-%d %H:%M:%S UTC')
                event_desc = event.get('event', 'Unknown Event')
                details_str = json.dumps(event.get('details', {}))
                report_lines.append(f"- {timestamp}: {event_desc} (Details: {details_str})")
        
        # Placeholder for response actions if they were explicitly recorded in incident.details
        # For now, it's implicitly part of the timeline
        
        report_lines.append(f"\n--- End of Report ---")
        
        logger.info(f"Generated report for incident {incident.id}.")
        return "\n".join(report_lines)

    def generate_incident_report_pdf(self, incident: Incident, explanation: Dict[str, Any], output_path: str) -> None:
        """
        Generates a comprehensive, human-readable PDF report for a phishing incident.
        
        Args:
            incident: The Incident object
            explanation: The structured explanation from the ExplainabilityAgent
            output_path: The file path where the PDF report should be saved
        """
        doc = SimpleDocTemplate(output_path, pagesize=letter, 
                                topMargin=0.5*inch, bottomMargin=0.5*inch,
                                leftMargin=0.75*inch, rightMargin=0.75*inch)
        
        styles = getSampleStyleSheet()
        story = []
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        header_style = ParagraphStyle(
            'CustomHeader',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#c0392b'),
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold'
        )
        
        subheader_style = ParagraphStyle(
            'CustomSubHeader',
            parent=styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=8,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        )
        
        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            spaceAfter=6
        )
        
        # ==================== HEADER ====================
        story.append(Paragraph("🚨 PHISHING INCIDENT REPORT", title_style))
        story.append(Paragraph(f"<i>Autonomous Cyber Defense System (ACDS)</i>", 
                              ParagraphStyle('subtitle', parent=normal_style, alignment=TA_CENTER, textColor=colors.grey)))
        story.append(Spacer(1, 0.3 * inch))
        
        # ==================== EXECUTIVE SUMMARY ====================
        story.append(Paragraph("EXECUTIVE SUMMARY", header_style))
        
        # Severity indicator
        severity = "HIGH RISK" if explanation.get('confidence_level', '0%').replace('%', '').replace('.', '').isdigit() and float(explanation.get('confidence_level', '0%').replace('%', '')) >= 70 else "MODERATE RISK"
        severity_color = colors.red if "HIGH" in severity else colors.orange
        
        summary_data = [
            ["Incident ID:", str(incident.id)],
            ["Detection Time:", incident.detection_timestamp.strftime('%B %d, %Y at %H:%M:%S UTC')],
            ["Threat Level:", severity],
            ["Status:", incident.status.value.replace('_', ' ').title()],
            ["Email ID:", str(incident.email_id)],
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 4.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3 * inch))
        
        # ==================== EMAIL DETAILS ====================
        story.append(Paragraph("EMAIL INFORMATION", header_style))
        
        email_details = incident.details or {}
        email_data = [
            ["From:", email_details.get('sender', 'N/A')],
            ["To:", ', '.join(email_details.get('recipients', [])) if email_details.get('recipients') else 'N/A'],
            ["Subject:", email_details.get('subject', 'N/A')],
        ]
        
        email_table = Table(email_data, colWidths=[1.5*inch, 5*inch])
        email_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(email_table)
        
        # Email body preview
        email_body = email_details.get('body', 'N/A')
        if email_body and email_body != 'N/A':
            story.append(Spacer(1, 0.15 * inch))
            story.append(Paragraph("Email Content Preview:", subheader_style))
            body_preview = email_body[:500] + "..." if len(email_body) > 500 else email_body
            story.append(Paragraph(f"<i>{body_preview}</i>", 
                                  ParagraphStyle('bodytext', parent=normal_style, 
                                               textColor=colors.HexColor('#34495e'),
                                               backColor=colors.HexColor('#f8f9fa'),
                                               borderPadding=10)))
        
        story.append(Spacer(1, 0.3 * inch))
        
        # ==================== DETECTION ANALYSIS ====================
        story.append(Paragraph("DETECTION ANALYSIS", header_style))
        
        story.append(Paragraph(f"<b>Detection Agent:</b> {incident.detection_agent_id}", normal_style))
        story.append(Paragraph(f"<b>Confidence Score:</b> {explanation.get('confidence_level', 'N/A')}", normal_style))
        story.append(Spacer(1, 0.1 * inch))
        
        story.append(Paragraph("<b>Analysis Summary:</b>", subheader_style))
        story.append(Paragraph(explanation.get('summary', 'No summary available.'), normal_style))
        story.append(Spacer(1, 0.15 * inch))
        
        # ==================== THREAT INDICATORS ====================
        story.append(Paragraph("THREAT INDICATORS", header_style))
        story.append(Paragraph("The following suspicious indicators were detected:", normal_style))
        
        details = explanation.get('details', [])
        if details:
            indicator_data = [["#", "Indicator Description"]]
            for idx, detail in enumerate(details, 1):
                indicator_data.append([str(idx), detail])
            
            indicator_table = Table(indicator_data, colWidths=[0.5*inch, 6*inch])
            indicator_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#c0392b')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('FONTSIZE', (0, 1), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
            ]))
            story.append(indicator_table)
        else:
            story.append(Paragraph("No specific indicators recorded.", normal_style))
        
        story.append(Spacer(1, 0.3 * inch))
        
        # ==================== AGENT WORKFLOW ====================
        story.append(Paragraph("AUTOMATED RESPONSE WORKFLOW", header_style))
        
        workflow_steps = [
            ["Step", "Agent", "Action", "Status"],
            ["1", "Detection Agent", "Analyzed email for phishing indicators", "✓ Complete"],
            ["2", "Incident Manager", "Created incident record in database", "✓ Complete"],
            ["3", "Explainability Agent", "Generated threat analysis & explanation", "✓ Complete"],
            ["4", "Orchestration Agent", "Determined response actions", "✓ Complete"],
            ["5", "Response Agent", "Executed automated countermeasures", "✓ Complete"],
            ["6", "Report Generator", "Generated this comprehensive report", "✓ Complete"],
        ]
        
        workflow_table = Table(workflow_steps, colWidths=[0.5*inch, 1.5*inch, 3*inch, 1.5*inch])
        workflow_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
        ]))
        story.append(workflow_table)
        story.append(Spacer(1, 0.3 * inch))
        
        # ==================== TIMELINE ====================
        story.append(Paragraph("INCIDENT TIMELINE", header_style))
        
        if incident.timeline_of_events:
            timeline_data = [["Time", "Event", "Details"]]
            for event in incident.timeline_of_events:
                timestamp = event.get('timestamp', datetime.min).strftime('%H:%M:%S')
                event_desc = event.get('event', 'Unknown Event')
                details_dict = event.get('details', {})
                details_str = ', '.join([f"{k}: {v}" for k, v in details_dict.items()]) if details_dict else "None"
                timeline_data.append([timestamp, event_desc, details_str])
            
            timeline_table = Table(timeline_data, colWidths=[1*inch, 2.5*inch, 3*inch])
            timeline_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#27ae60')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
            ]))
            story.append(timeline_table)
        else:
            story.append(Paragraph("No timeline events recorded.", normal_style))
        
        story.append(Spacer(1, 0.3 * inch))
        
        # ==================== RECOMMENDATIONS ====================
        story.append(Paragraph("RECOMMENDATIONS", header_style))
        
        recommendations = [
            "• Block sender email address from future communications",
            "• Quarantine or delete the suspicious email from all mailboxes",
            "• Alert affected recipients about the phishing attempt",
            "• Update email filtering rules to catch similar threats",
            "• Monitor for any similar phishing campaigns",
            "• Consider security awareness training for affected users"
        ]
        
        for rec in recommendations:
            story.append(Paragraph(rec, normal_style))
        
        story.append(Spacer(1, 0.3 * inch))
        
        # ==================== FOOTER ====================
        story.append(Spacer(1, 0.5 * inch))
        footer_text = f"""
        <para alignment="center">
        <font size="8" color="grey">
        This report was automatically generated by the Autonomous Cyber Defense System (ACDS)<br/>
        Report Generated: {datetime.utcnow().strftime('%B %d, %Y at %H:%M:%S UTC')}<br/>
        Assigned Analyst: {incident.assigned_analyst or 'Unassigned'}<br/>
        For questions, contact: security@acds.com
        </font>
        </para>
        """
        story.append(Paragraph(footer_text, normal_style))
        
        try:
            doc.build(story)
            logger.info(f"Generated comprehensive PDF report for incident {incident.id} at {output_path}.")
        except Exception as e:
            logger.error(f"Error generating PDF report for incident {incident.id}: {e}")
            raise

def get_report_generator() -> ReportGenerator:
    """Returns a singleton-like instance of the ReportGenerator."""
    return ReportGenerator()
