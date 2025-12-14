# Quickstart Guide: Phishing Detection Module

This guide provides a quick overview of how to set up and run the Phishing Detection Module.

## 1. Overview

The Phishing Detection Module is a backend service designed to process email datasets, detect phishing incidents, provide explanations, and generate reports. It integrates with MongoDB for incident storage.

## 2. Setup

### Prerequisites

*   Python 3.11+
*   Docker and Docker Compose (for MongoDB)
*   `pip` for Python package management

### Environment Configuration

Ensure you have a `.env` file in the root of your project or configure environment variables for MongoDB connection:

```
MONGO_URI="mongodb://localhost:27017"
DB_NAME="acds_phishing_db"
INCIDENT_COLLECTION="incidents"
```

### Install Dependencies

Navigate to the `backend` directory and install Python dependencies:

```bash
cd backend
pip install -r requirements.txt # (Assuming requirements.txt exists or will be created)
# Or install manually:
# pip install fastapi uvicorn pydantic motor datasets pymongo scikit-learn joblib
```

### Run MongoDB

The module uses MongoDB for incident storage. You can run MongoDB using Docker:

```bash
docker-compose up -d mongodb # Assuming docker-compose.yml has a 'mongodb' service
```

## 3. Usage Example (Programmatic)

Here's a basic Python script to demonstrate the end-to-end workflow:

```python
import asyncio
from uuid import UUID
from datetime import datetime
import os

# Adjust sys.path to allow imports if running this script from root or elsewhere
# import sys
# sys.path.append(os.path.abspath('./backend/src/services')) 

from backend.src.services.phishing_detection.models import Email, IncidentStatus
from backend.src.services.phishing_detection.database import incident_db, get_incident_db
from backend.src.services.phishing_detection.data_loader import get_email_data_loader
from backend.src.services.phishing_detection.detection_agent import get_detection_agent
from backend.src.services.phishing_detection.incident_manager import get_incident_manager
from backend.src.services.phishing_detection.explainability_agent import get_explainability_agent
from backend.src.services.phishing_detection.orchestration_trigger import get_orchestration_trigger
from backend.src.services.phishing_detection.report_generator import get_report_generator

async def run_phishing_detection_workflow():
    print("--- Starting Phishing Detection Workflow Example ---")

    # Connect to MongoDB
    await incident_db.connect()

    # Initialize agents and managers
    data_loader = get_email_data_loader(
        dataset_name="danish/phishing_emails", # Example Hugging Face dataset
        split="train", 
        raw_text_column="text"
    )
    detection_agent = get_detection_agent(use_ml=False) # Start with rule-based
    incident_manager = await get_incident_manager()
    explainability_agent = get_explainability_agent()
    orchestration_trigger = get_orchestration_trigger()
    report_generator = get_report_generator()

    # 1. Load Emails (using a placeholder dataset)
    print("\n1. Loading emails from Hugging Face dataset (placeholder)...")
    # Using a simple mock email for demonstration if HF dataset is not set up
    # In a real scenario, data_loader.load_emails_from_hf_dataset() would be used
    mock_email = Email(
        raw_content="Subject: Urgent action required! Your account is suspended.\nFrom: no-reply@fakebank.com\nTo: user@example.com\n\nPlease click here: http://192.168.1.1/login",
        headers={"From": "no-reply@fakebank.com", "To": "user@example.com", "Subject": "Urgent action required!"},
        sender="no-reply@fakebank.com",
        recipients=["user@example.com"],
        subject="Urgent action required! Your account is suspended.",
        body="Please click here to verify your account: http://192.168.1.1/login"
    )
    emails_to_process = [mock_email] # Or data_loader.load_emails_from_hf_dataset()

    for email in emails_to_process:
        print(f"\nProcessing Email ID: {email.id}, Subject: {email.subject[:50]}...")

        # 2. Detect Phishing
        detection_results = detection_agent.detect_phishing(email)
        print(f"   Detection Result: Is Phishing? {detection_results['is_phishing']}, Confidence: {detection_results['confidence_score']:.2f}")

        if detection_results["is_phishing"]:
            # 3. Create Incident
            incident = await incident_manager.create_new_incident(email, detection_results)
            if incident:
                print(f"   Incident created with ID: {incident.id}")

                # 4. Explain Phishing
                explanation = explainability_agent.generate_explanation(incident)
                print(f"   Explanation: {explanation['summary']}")
                for detail in explanation['details']:
                    print(f"      {detail}")

                # 5. Trigger Orchestration
                orchestration_success = await orchestration_trigger.trigger_orchestration(incident)
                print(f"   Orchestration Triggered: {orchestration_success}")

                # 6. Update Incident + Timeline
                updated_incident = await incident_manager.update_incident_status(incident.id, IncidentStatus.CONFIRMED_PHISHING, "System_Bot")
                if updated_incident:
                    print(f"   Incident {updated_incident.id} status updated to {updated_incident.status.value}")
                    await incident_manager.add_timeline_entry(updated_incident.id, "Automated response triggered", {"orchestration_status": orchestration_success})

                # 7. Generate Report
                final_incident = await incident_db.get_incident(str(incident.id))
                report = report_generator.generate_incident_report(final_incident, explanation)
                print(f"\n--- Incident Report for {final_incident.id} ---")
                print(report)
            else:
                print(f"   Failed to create incident for email {email.id}")
        else:
            print(f"   Email {email.id} is not detected as phishing.")
    
    # Disconnect from MongoDB
    await incident_db.disconnect()
    print("\n--- Workflow Example Complete ---")

if __name__ == "__main__":
    # Configure basic logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    asyncio.run(run_phishing_detection_workflow())
