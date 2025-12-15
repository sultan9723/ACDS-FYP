# Reports Folder

This folder contains auto-generated PDF incident reports for detected phishing threats.

## How Reports Are Generated

When the Demo Scheduler processes emails and detects a phishing threat, the system automatically:

1. **Detects the threat** - ML model identifies phishing emails with confidence scores
2. **Stores in database** - Threat data is stored in MongoDB `threats` collection
3. **Generates PDF report** - A professional incident report is created with:
   - Report ID and Threat ID
   - Severity level (CRITICAL, HIGH, MEDIUM, LOW)
   - Confidence percentage
   - Email subject and sender information
   - Detection analysis and risk factors
   - Automated response actions taken
   - Security recommendations

## File Naming Convention

Reports are named using the following format:
```
incident_report_{THREAT_ID}_{TIMESTAMP}.pdf
```

Example: `incident_report_THR-A1B2C3D4_20250114_143052.pdf`

## Metadata Storage

Report metadata is stored in two locations:
1. `reports_metadata.json` - Local JSON file in this folder
2. MongoDB `incident_reports` collection - For persistence

## API Endpoints

Access reports through the following API endpoints:

- `GET /reports/incidents` - List all incident reports
- `GET /reports/incidents/{report_id}` - Get report metadata
- `GET /reports/incidents/{report_id}/download` - Download PDF file
- `DELETE /reports/incidents/{report_id}` - Delete a report

## Frontend Access

Reports can be viewed and downloaded from the **AI Reports** page in the ACDS dashboard:
1. Navigate to the Reports page
2. Click on "PDF Incident Reports" tab
3. View report list with severity, confidence, and timestamps
4. Click download icon to get the PDF file

## Dependencies

PDF generation requires the `reportlab` library:
```bash
pip install reportlab
```

This is already included in the project's `requirements.txt`.
