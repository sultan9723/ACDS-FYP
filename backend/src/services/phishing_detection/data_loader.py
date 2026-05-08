import os
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr # Added
from typing import Dict, Any, List, Optional
from datasets import load_dataset
from pydantic import EmailStr
import logging

from .models import Email

logger = logging.getLogger(__name__)

class EmailDataLoader:
    def __init__(self, dataset_name: str, split: str, raw_text_column: str = "Email Text"):
        self.dataset_name = dataset_name
        self.split = split
        self.raw_text_column = raw_text_column
        logger.info(f"EmailDataLoader initialized for dataset: {dataset_name}, split: {split}")

    def load_emails_from_hf_dataset(self) -> List[Email]:
        try:
            dataset = load_dataset(self.dataset_name, split=self.split)
            emails = []
            for item in dataset:
                raw_email_text = item.get(self.raw_text_column)
                if raw_email_text:
                    parsed_email = self._parse_raw_email(raw_email_text)
                    if parsed_email:
                        emails.append(parsed_email)
            logger.info(f"Loaded {len(emails)} emails from {self.dataset_name}.")
            return emails
        except Exception as e:
            logger.error(f"Error loading emails from Hugging Face dataset '{self.dataset_name}': {e}")
            return []

    def _parse_raw_email(self, raw_email_text: str) -> Optional[Email]:
        try:
            # BytesParser expects bytes, so encode the string
            msg = BytesParser(policy=policy.default).parsebytes(raw_email_text.encode('utf-8', errors='replace'))

            _name, sender_addr = parseaddr(msg["from"]) if msg["from"] else ("", "unknown@example.com")
            sender = EmailStr(sender_addr)

            recipients_raw = msg.get_all("to", []) + msg.get_all("cc", [])
            recipients = []
            for addr_raw in recipients_raw:
                _name, rec_addr = parseaddr(addr_raw)
                if rec_addr:
                    recipients.append(EmailStr(rec_addr))
            subject = msg["subject"] if msg["subject"] else ""

            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    ctype = part.get_content_type()
                    cdispo = str(part.get("Content-Disposition"))
                    # Look for plain text parts, not attachments
                    if ctype == "text/plain" and "attachment" not in cdispo:
                        body = part.get_payload(decode=True).decode('utf-8', errors='replace')
                        break
            else:
                body = msg.get_payload(decode=True).decode('utf-8', errors='replace')
            
            headers = {k.lower(): v for k, v in msg.items()}

            return Email(
                raw_content=raw_email_text,
                headers=headers,
                sender=sender,
                recipients=recipients,
                subject=subject,
                body=body,
                attachments=[] # For MVP, attachments are not parsed in detail
            )
        except Exception as e:
            logger.error(f"Error parsing raw email: {e}")
            return None

_data_loader_instance: Optional[EmailDataLoader] = None

def get_email_data_loader(dataset_name: str, split: str, raw_text_column: str) -> EmailDataLoader:
    global _data_loader_instance
    if _data_loader_instance is None:
        _data_loader_instance = EmailDataLoader(dataset_name, split, raw_text_column)
    return _data_loader_instance