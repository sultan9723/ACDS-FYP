import asyncio
from uuid import UUID
from datetime import datetime
import os
import logging
from dotenv import load_dotenv; load_dotenv() # Load environment variables from .env


# Adjust sys.path to allow imports if running this script from root or elsewhere
import sys
sys.path.append(os.path.abspath('./backend/src/services')) 
sys.path.append(os.path.abspath('./backend')) # Added for config.settings access

from backend.src.services.phishing_detection.database import incident_db
from backend.src.services.phishing_detection.data_loader import get_email_data_loader
from backend.src.services.phishing_detection.orchestrator_agent import get_orchestrator_agent # Use the new orchestrator
from backend.src.services.phishing_detection.explainability_agent import get_explainability_agent # Still needed for explanation for report
from backend.src.services.phishing_detection.report_generator import get_report_generator


async def run_phishing_detection_workflow():
    print("--- Starting Phishing Detection Workflow Example ---")

    # Create reports directory if it doesn't exist
    os.makedirs("reports", exist_ok=True)

    # Connect to MongoDB
    await incident_db.connect()

    # Initialize orchestrator
    orchestrator = await get_orchestrator_agent(incident_db)

    # 1. Load Emails
    print("\n1. Loading emails from Hugging Face dataset...")
    data_loader = get_email_data_loader(
        dataset_name="zefang-liu/phishing-email-dataset", # Correct Hugging Face dataset
        split="train", 
        raw_text_column="Email Text" # Corrected column name
    )
    emails_to_process = data_loader.load_emails_from_hf_dataset()
    if not emails_to_process:
        print("No emails loaded from dataset. Exiting.")
        await incident_db.disconnect()
        return

    print(f"Loaded {len(emails_to_process)} emails. Starting workflow for each.")
    
    for email in emails_to_process:
        print(f"\nProcessing Email ID: {email.id}, Subject: {email.subject[:50]}...")
        
        # Execute the full workflow for this email using the OrchestratorAgent
        incident = await orchestrator.process_email_workflow(email)

        if incident:
            print(f"   Workflow completed for Incident ID: {incident.id}")
            print(f"   PDF report saved to: reports/incident_report_{incident.id}.pdf")
        else:
            print(f"   Workflow did not result in an incident for email {email.id}.")
    
    # Disconnect from MongoDB
    await incident_db.disconnect()
    print("\n--- Workflow Example Complete ---")

if __name__ == "__main__":
    # Configure basic logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    asyncio.run(run_phishing_detection_workflow())
