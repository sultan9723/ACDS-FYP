import os
import logging
from typing import List, Dict, Any, Union, Optional
from datasets import load_dataset, Dataset
from pydantic import ValidationError
from email import message_from_string
from email.utils import parseaddr
import json

from .models import Email # Assuming Email model is in .models

logger = logging.getLogger(__name__)

class EmailDataLoader:
    """
    Handles loading email datasets, specifically from Hugging Face,
    and converting them into Email model instances.
    """
    def __init__(self, dataset_name: str = "your_org/phishing_email_dataset", 
                 split: str = "train", 
                 raw_text_column: str = "text",
                 cache_dir: Optional[str] = None):
        self.dataset_name = dataset_name
        self.split = split
        self.raw_text_column = raw_text_column
        self.cache_dir = cache_dir if cache_dir else os.path.join(os.getcwd(), ".hf_cache")
        os.makedirs(self.cache_dir, exist_ok=True)
        logger.info(f"Initialized EmailDataLoader for dataset: {dataset_name}, split: {split}")

    def load_hf_dataset(self) -> Dataset:
        """
        Loads a dataset from Hugging Face.
        """
        try:
            dataset = load_dataset(
                self.dataset_name, 
                split=self.split, 
                cache_dir=self.cache_dir
            )
            logger.info(f"Successfully loaded dataset '{self.dataset_name}' with {len(dataset)} examples.")
            return dataset
        except Exception as e:
            logger.error(f"Error loading Hugging Face dataset '{self.dataset_name}': {e}")
            raise

    def parse_email_from_raw_text(self, raw_text: str) -> Optional[Dict[str, Any]]:
        """
        Parses a raw email text string into a dictionary of components.
        """
        try:
            msg = message_from_string(raw_text)
            
            headers = {k: v for k, v in msg.items()}
            
            sender = parseaddr(msg.get('From', ''))[1]
            recipients = []
            for hdr in ['To', 'Cc', 'Bcc']:
                if msg[hdr]:
                    recipients.extend([parseaddr(addr)[1] for addr in msg.get_all(hdr, [])])

            subject = msg.get('Subject', '')
            
            # Extract plain text body
            body = ""
            for part in msg.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get('Content-Disposition'))

                if ctype == 'text/plain' and 'attachment' not in cdispo:
                    body = part.get_payload(decode=True).decode(errors='ignore')
                    break # Assuming first plain text part is the main body

            attachments = [] # Placeholder for attachment parsing if needed later

            return {
                "raw_content": raw_text,
                "headers": headers,
                "sender": sender,
                "recipients": recipients,
                "subject": subject,
                "body": body,
                "attachments": attachments,
                # received_at will default to current UTC time in the Email model
            }
        except Exception as e:
            logger.warning(f"Failed to parse raw email text: {e}. Raw text snippet: {raw_text[:200]}...")
            return None

    def load_emails_from_hf_dataset(self) -> List[Email]:
        """
        Loads emails from the configured Hugging Face dataset and converts them
        into a list of Email model instances.
        """
        dataset = self.load_hf_dataset()
        emails: List[Email] = []
        for item in dataset:
            raw_email_text = item.get(self.raw_text_column)
            if raw_email_text:
                parsed_data = self.parse_email_from_raw_text(raw_email_text)
                if parsed_data:
                    try:
                        email_instance = Email(**parsed_data)
                        emails.append(email_instance)
                    except ValidationError as e:
                        logger.error(f"Validation error for email data: {e}. Data: {parsed_data}")
                    except Exception as e:
                        logger.error(f"Unexpected error creating Email model: {e}. Data: {parsed_data}")
            else:
                logger.warning(f"Raw email text column '{self.raw_text_column}' not found or empty in item: {item}")
        logger.info(f"Successfully loaded and parsed {len(emails)} emails from dataset.")
        return emails

# Example of how to get a data loader
def get_email_data_loader(dataset_name: str = "your_org/phishing_email_dataset", 
                          split: str = "train", 
                          raw_text_column: str = "text") -> EmailDataLoader:
    """
    Returns a singleton instance of EmailDataLoader.
    """
    # For simplicity, returning a new instance. In a real app, you might want a true singleton or dependency injection.
    return EmailDataLoader(dataset_name=dataset_name, split=split, raw_text_column=raw_text_column)
