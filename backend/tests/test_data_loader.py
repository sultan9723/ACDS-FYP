"""
Test Data Loader
=================
Loads sample phishing emails from HuggingFace dataset for testing.
"""

import random
from typing import List, Dict, Optional
from datetime import datetime, timezone

# Sample phishing and legitimate emails for testing
# These are realistic examples based on common phishing patterns

PHISHING_SAMPLES = [
    {
        "subject": "URGENT: Your Account Has Been Compromised",
        "sender": "security@bankofamerica-secure.com",
        "content": """Dear Valued Customer,

We have detected unusual activity on your Bank of America account. Your account has been temporarily suspended due to suspicious login attempts from an unrecognized device.

To restore access to your account, please verify your identity immediately by clicking the link below:

http://bankofamerica-verify-secure.com/login?id=8372641

If you do not verify your account within 24 hours, your account will be permanently locked and all funds will be frozen.

Your Account Details:
- Account ending in: ****4521
- Last login attempt: December 4, 2025 from IP 192.168.1.45

Click here to verify: http://secure-boa-login.com/verify

Thank you for your immediate attention to this matter.

Security Department
Bank of America""",
        "is_phishing": True,
        "indicators": ["urgency", "suspicious_link", "threat_of_action", "spoofed_sender"]
    },
    {
        "subject": "You've Won a $1000 Amazon Gift Card!",
        "sender": "rewards@amazon-prizes.net",
        "content": """Congratulations!

You have been selected as one of our lucky winners! You've won a $1000 Amazon Gift Card in our monthly sweepstakes!

To claim your prize, simply click the link below and enter your shipping details:

CLAIM YOUR PRIZE NOW: http://amazon-gift-claim.com/winner/claim?token=abc123

This offer expires in 48 hours. Don't miss out on your FREE gift card!

Requirements to claim:
- Must be 18 or older
- Valid credit card required for shipping verification ($1.99 fee)
- Offer limited to first 100 respondents

Act now before it's too late!

Amazon Rewards Team""",
        "is_phishing": True,
        "indicators": ["too_good_to_be_true", "urgency", "suspicious_link", "request_for_payment"]
    },
    {
        "subject": "Invoice #INV-2024-8847 Payment Required",
        "sender": "billing@quickbooks-invoices.com",
        "content": """Dear Customer,

Please find attached your invoice #INV-2024-8847 for services rendered.

Amount Due: $3,847.00
Due Date: December 6, 2025

To avoid late fees and service interruption, please process payment immediately using the secure link below:

PAY NOW: http://quickbooks-pay-secure.com/invoice/INV-2024-8847

If you believe this invoice is incorrect, please contact our billing department within 24 hours.

Note: Failure to pay will result in:
- 15% late fee
- Service termination
- Collection agency referral

Best regards,
QuickBooks Billing Department

This is an automated message. Do not reply directly.""",
        "is_phishing": True,
        "indicators": ["fake_invoice", "urgency", "threat_of_action", "suspicious_link"]
    },
    {
        "subject": "Your Netflix Subscription Has Expired",
        "sender": "no-reply@netflix-billing.com",
        "content": """Hi there,

We were unable to process your payment for your Netflix subscription. As a result, your account has been suspended.

To continue enjoying unlimited movies and TV shows, please update your payment information:

UPDATE PAYMENT: http://netflix-account-update.com/billing

If payment is not received within 48 hours, your account and all saved preferences will be permanently deleted.

Current Plan: Premium (4 screens)
Amount Due: $22.99

We value your membership and hope to see you back soon!

The Netflix Team

P.S. Don't lose your viewing history and personalized recommendations!""",
        "is_phishing": True,
        "indicators": ["account_suspended", "urgency", "suspicious_link", "data_loss_threat"]
    },
    {
        "subject": "IT Department: Password Reset Required",
        "sender": "it-support@company-helpdesk.net",
        "content": """IMPORTANT: Immediate Action Required

Dear Employee,

Our security systems have detected that your corporate password has not been changed in 90 days. According to company policy, you must reset your password immediately.

Click here to reset your password: http://company-password-reset.com/reset?user=employee

Your current password will expire in 2 hours. After expiration, you will be locked out of:
- Email
- VPN access
- All corporate applications

Please complete this reset immediately to avoid work disruption.

IT Support Team
Company IT Department

Note: This is an automated security message.""",
        "is_phishing": True,
        "indicators": ["impersonation", "urgency", "suspicious_link", "corporate_spear_phishing"]
    },
    {
        "subject": "Shipping Notification: Your Package is Waiting",
        "sender": "delivery@fedex-tracking.net",
        "content": """FedEx Delivery Notification

Dear Customer,

We attempted to deliver your package today but were unable to complete the delivery.

Tracking Number: 7892341567890
Delivery Status: HELD AT FACILITY

To schedule a redelivery or pick up your package, please confirm your address:

SCHEDULE DELIVERY: http://fedex-redelivery.com/schedule?track=7892341567890

If not claimed within 5 business days, your package will be returned to sender.

Package Details:
- Weight: 2.3 lbs
- Origin: Los Angeles, CA
- Estimated Value: $299.99

Click here to track: http://fedex-package-track.com/track

Thank you for choosing FedEx.

FedEx Customer Service""",
        "is_phishing": True,
        "indicators": ["delivery_scam", "suspicious_link", "urgency", "spoofed_brand"]
    },
    {
        "subject": "Your Apple ID has been locked",
        "sender": "appleid@apple-support-verify.com",
        "content": """Dear Apple Customer,

For your protection, your Apple ID has been automatically locked. We detected an unauthorized sign-in attempt from:

Location: Moscow, Russia
Device: Unknown Windows PC
Time: December 4, 2025 at 3:42 AM

If this wasn't you, your account may be compromised. Please verify your identity immediately:

VERIFY NOW: http://appleid-verify-support.com/unlock

If you don't verify within 24 hours, your Apple ID will be permanently disabled and you will lose access to:
- iCloud data
- App Store purchases
- Apple Music library

Stay protected,
Apple Support Team

Apple ID | Support | Privacy Policy""",
        "is_phishing": True,
        "indicators": ["account_locked", "urgency", "suspicious_link", "fear_tactics"]
    },
    {
        "subject": "DocuSign: Document Ready for Signature",
        "sender": "documents@docusign-secure.net",
        "content": """DocuSign

John Smith has sent you a document to review and sign.

Document: Employment_Contract_2025.pdf
Sent by: HR Department (hr@yourcompany.com)

REVIEW DOCUMENT: http://docusign-view-document.com/sign?doc=abc123xyz

This document requires your signature by December 6, 2025.

Message from sender:
"Please review and sign the attached employment contract at your earliest convenience. This is time-sensitive."

Don't have a DocuSign account? You can still sign - click the link above.

Questions? Contact support@docusign.com

DocuSign, Inc.""",
        "is_phishing": True,
        "indicators": ["document_scam", "suspicious_link", "impersonation", "urgency"]
    }
]

LEGITIMATE_SAMPLES = [
    {
        "subject": "Your Amazon.com order has shipped",
        "sender": "ship-confirm@amazon.com",
        "content": """Hello,

Your package has shipped! Here are the details:

Order #111-2345678-9012345
Shipped via UPS

Items in this shipment:
- Wireless Bluetooth Headphones (Qty: 1)
- USB-C Charging Cable 6ft (Qty: 2)

Estimated delivery: December 6-8, 2025

Track your package:
https://www.amazon.com/gp/your-account/order-history

We hope to see you again soon.
Amazon.com""",
        "is_phishing": False,
        "indicators": []
    },
    {
        "subject": "Your monthly statement is ready",
        "sender": "statements@chase.com",
        "content": """Dear Customer,

Your Chase credit card statement for November 2025 is now available.

Statement Period: November 1-30, 2025
New Balance: $1,234.56
Minimum Payment Due: $35.00
Payment Due Date: December 25, 2025

View your statement by logging into chase.com or the Chase Mobile app.

If you have questions about your account, call the number on the back of your card.

Thank you for being a Chase customer.

Chase Bank""",
        "is_phishing": False,
        "indicators": []
    },
    {
        "subject": "Meeting reminder: Project Review Tomorrow",
        "sender": "calendar-noreply@google.com",
        "content": """Reminder: Project Review Meeting

When: December 5, 2025 at 2:00 PM EST
Where: Conference Room B / Google Meet

Attendees:
- John Smith
- Sarah Johnson
- Mike Williams

Agenda:
1. Q4 progress review
2. Budget discussion
3. Timeline adjustments
4. Next steps

Join Google Meet: meet.google.com/abc-defg-hij

See you there!""",
        "is_phishing": False,
        "indicators": []
    },
    {
        "subject": "Weekly Newsletter: Tech Updates",
        "sender": "newsletter@techcrunch.com",
        "content": """TechCrunch Weekly

Top Stories This Week:

1. AI Breakthrough: New Language Model Sets Records
Read more at techcrunch.com/ai-breakthrough

2. Startup Raises $50M for Climate Tech
Read more at techcrunch.com/climate-startup

3. Apple Announces New Product Line
Read more at techcrunch.com/apple-products

Thank you for subscribing to our newsletter.

Unsubscribe | Manage Preferences | Privacy Policy

TechCrunch Media
San Francisco, CA""",
        "is_phishing": False,
        "indicators": []
    },
    {
        "subject": "Your flight confirmation - AA1234",
        "sender": "reservations@aa.com",
        "content": """American Airlines

Confirmation Code: ABC123

Flight Details:
December 20, 2025
AA1234
New York (JFK) → Los Angeles (LAX)
Depart: 8:00 AM | Arrive: 11:30 AM

Passenger: John Smith
Seat: 14A (Window)
Class: Economy

Check-in opens 24 hours before departure at aa.com

Add trip to your calendar | Manage reservation

Thank you for flying American Airlines.

American Airlines
Fort Worth, TX""",
        "is_phishing": False,
        "indicators": []
    },
    {
        "subject": "Your GitHub notification",
        "sender": "notifications@github.com",
        "content": """[GitHub] New pull request in your repository

@developer123 opened a pull request in username/project:

#42 Fix bug in authentication module

This PR fixes the login issue reported in #41. Changes include:
- Updated password validation
- Added error handling
- Updated unit tests

View pull request: https://github.com/username/project/pull/42

You're receiving this because you're watching this repository.
Unsubscribe from these notifications.

GitHub, Inc.
San Francisco, CA""",
        "is_phishing": False,
        "indicators": []
    }
]


class TestDataLoader:
    """Loads and manages test data for phishing detection testing."""
    
    def __init__(self):
        self.phishing_samples = PHISHING_SAMPLES.copy()
        self.legitimate_samples = LEGITIMATE_SAMPLES.copy()
        self.test_results = []
    
    def get_random_phishing(self, count: int = 1) -> List[Dict]:
        """Get random phishing email samples."""
        return random.sample(self.phishing_samples, min(count, len(self.phishing_samples)))
    
    def get_random_legitimate(self, count: int = 1) -> List[Dict]:
        """Get random legitimate email samples."""
        return random.sample(self.legitimate_samples, min(count, len(self.legitimate_samples)))
    
    def get_mixed_batch(self, total: int = 10) -> List[Dict]:
        """Get a mixed batch of phishing and legitimate emails."""
        phishing_count = total // 2
        legitimate_count = total - phishing_count
        
        batch = []
        batch.extend(self.get_random_phishing(phishing_count))
        batch.extend(self.get_random_legitimate(legitimate_count))
        
        random.shuffle(batch)
        return batch
    
    def get_all_samples(self) -> Dict:
        """Get all available test samples."""
        return {
            "phishing": self.phishing_samples,
            "legitimate": self.legitimate_samples,
            "total_phishing": len(self.phishing_samples),
            "total_legitimate": len(self.legitimate_samples)
        }
    
    def record_test_result(self, sample: Dict, prediction: Dict) -> Dict:
        """Record a test result for analysis."""
        result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sample_subject": sample.get("subject"),
            "actual_label": sample.get("is_phishing"),
            "predicted_label": prediction.get("is_phishing"),
            "confidence": prediction.get("confidence"),
            "severity": prediction.get("severity"),
            "correct": sample.get("is_phishing") == prediction.get("is_phishing"),
            "indicators_expected": sample.get("indicators", []),
        }
        self.test_results.append(result)
        return result
    
    def get_test_summary(self) -> Dict:
        """Get summary of all test results."""
        if not self.test_results:
            return {"message": "No tests run yet"}
        
        total = len(self.test_results)
        correct = sum(1 for r in self.test_results if r["correct"])
        
        # Calculate metrics
        tp = sum(1 for r in self.test_results if r["actual_label"] and r["predicted_label"])
        fp = sum(1 for r in self.test_results if not r["actual_label"] and r["predicted_label"])
        fn = sum(1 for r in self.test_results if r["actual_label"] and not r["predicted_label"])
        tn = sum(1 for r in self.test_results if not r["actual_label"] and not r["predicted_label"])
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            "total_tests": total,
            "correct_predictions": correct,
            "accuracy": correct / total if total > 0 else 0,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "confusion_matrix": {
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
                "true_negatives": tn
            },
            "results": self.test_results[-10:]  # Last 10 results
        }
    
    def clear_results(self):
        """Clear all recorded test results."""
        self.test_results = []


# Singleton instance
_test_data_loader = None

def get_test_data_loader() -> TestDataLoader:
    """Get the singleton test data loader instance."""
    global _test_data_loader
    if _test_data_loader is None:
        _test_data_loader = TestDataLoader()
    return _test_data_loader
