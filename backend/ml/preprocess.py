"""
Text Preprocessing Module for Phishing Detection
=================================================
Unified preprocessing pipeline - NO NLTK required.
MUST match the preprocessing used during model training.

Version: 2.0.0
"""

import re
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ============================================================
# CONSTANTS - Phishing Indicators
# ============================================================

URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'asap', 'now', 'expire', 'expires',
    'limited', 'act now', 'hurry', 'quick', 'fast', 'deadline',
    'within 24 hours', 'within 48 hours', 'today only'
]

THREAT_KEYWORDS = [
    'suspended', 'terminated', 'blocked', 'locked', 'disabled',
    'unauthorized', 'unusual activity', 'security alert', 'compromised',
    'violation', 'illegal', 'fraud', 'breach'
]

ACTION_KEYWORDS = [
    'verify', 'confirm', 'update', 'click here', 'click below',
    'login', 'sign in', 'validate', 'submit', 'enter your',
    'provide your', 'send your'
]

REWARD_KEYWORDS = [
    'winner', 'won', 'prize', 'congratulations', 'selected',
    'lucky', 'reward', 'gift', 'free', 'bonus', 'discount',
    'refund', 'claim'
]

FINANCIAL_KEYWORDS = [
    'bank', 'account', 'password', 'credit card', 'ssn',
    'social security', 'wire transfer', 'payment', 'invoice',
    'paypal', 'apple', 'microsoft', 'amazon', 'netflix', 'google'
]


# ============================================================
# PREPROCESSING FUNCTIONS - Must Match Training
# ============================================================

def preprocess_text(text: str) -> str:
    """
    Unified text preprocessing for email content.
    
    ⚠️ CRITICAL: This function MUST match ml_training/phishingmodel.ipynb
    
    Args:
        text: Raw email text content
        
    Returns:
        Cleaned and preprocessed text ready for model prediction
    """
    if not isinstance(text, str) or not text.strip():
        return ""
    
    # Lowercase
    text = text.lower()
    
    # Replace URLs with token (preserve as indicator)
    text = re.sub(r'http[s]?://\S+|www\.\S+', ' URL_TOKEN ', text)
    
    # Replace email addresses with token
    text = re.sub(r'\S+@\S+\.\S+', ' EMAIL_TOKEN ', text)
    
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)
    
    # Keep alphanumeric and spaces only
    text = re.sub(r'[^a-zA-Z0-9\s]', ' ', text)
    
    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text


def preprocess_file(file_path: str) -> str:
    """
    Read and preprocess text content from a file.
    
    Args:
        file_path: Path to the file to process
        
    Returns:
        Preprocessed text content
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return preprocess_text(content)
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return ""


# ============================================================
# IOC EXTRACTION FUNCTIONS
# ============================================================

def extract_urls(text: str) -> List[str]:
    """Extract all URLs from text."""
    if not text:
        return []
    url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
    return list(set(re.findall(url_pattern, text, re.IGNORECASE)))


def extract_domains(text: str) -> List[str]:
    """Extract unique domains from URLs and email addresses."""
    domains = set()
    
    # From URLs
    urls = extract_urls(text)
    for url in urls:
        match = re.search(r'https?://([^/\s]+)', url)
        if match:
            domains.add(match.group(1).lower())
    
    # From email addresses
    emails = extract_email_addresses(text)
    for email in emails:
        if '@' in email:
            domain = email.split('@')[1].lower()
            domains.add(domain)
    
    return list(domains)


def extract_email_addresses(text: str) -> List[str]:
    """Extract all email addresses from text."""
    if not text:
        return []
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return list(set(re.findall(email_pattern, text)))


def extract_keywords(text: str, keyword_list: List[str]) -> List[str]:
    """Extract matching keywords from text."""
    if not text:
        return []
    text_lower = text.lower()
    return [kw for kw in keyword_list if kw in text_lower]


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_email_features(email_content: str) -> Dict[str, Any]:
    """
    Extract features from email content for enhanced detection.
    
    Args:
        email_content: Raw email content
        
    Returns:
        Dictionary of extracted features
    """
    if not email_content:
        return {
            'url_count': 0,
            'email_count': 0,
            'domain_count': 0,
            'has_html': False,
            'urgency_count': 0,
            'threat_count': 0,
            'action_count': 0,
            'reward_count': 0,
            'financial_count': 0,
            'suspicious_keywords': [],
            'text_length': 0
        }
    
    content_lower = email_content.lower()
    
    # Extract IOCs
    urls = extract_urls(email_content)
    emails = extract_email_addresses(email_content)
    domains = extract_domains(email_content)
    
    # Extract keyword matches
    urgency = extract_keywords(content_lower, URGENCY_KEYWORDS)
    threats = extract_keywords(content_lower, THREAT_KEYWORDS)
    actions = extract_keywords(content_lower, ACTION_KEYWORDS)
    rewards = extract_keywords(content_lower, REWARD_KEYWORDS)
    financial = extract_keywords(content_lower, FINANCIAL_KEYWORDS)
    
    # All suspicious keywords
    all_suspicious = list(set(urgency + threats + actions + rewards + financial))
    
    return {
        'url_count': len(urls),
        'email_count': len(emails),
        'domain_count': len(domains),
        'has_html': bool(re.search(r'<[^>]+>', email_content)),
        'urgency_count': len(urgency),
        'threat_count': len(threats),
        'action_count': len(actions),
        'reward_count': len(rewards),
        'financial_count': len(financial),
        'suspicious_keywords': all_suspicious,
        'text_length': len(email_content)
    }


# ============================================================
# RISK SCORING
# ============================================================

def calculate_risk_score(confidence: float, features: Dict[str, Any]) -> int:
    """
    Calculate risk score (0-100) based on ML confidence and features.
    
    Formula:
        risk_score = (confidence × 40) + (ioc_score × 20) + (keyword_score × 40)
    
    Args:
        confidence: ML model confidence (0.0 to 1.0)
        features: Extracted email features
        
    Returns:
        Risk score as integer (0-100)
    """
    # Base score from ML confidence (40% weight)
    confidence_score = confidence * 40
    
    # IOC score (20% weight)
    url_score = min(features.get('url_count', 0) * 3, 10)
    domain_score = min(features.get('domain_count', 0) * 2, 5)
    html_score = 5 if features.get('has_html', False) else 0
    ioc_score = (url_score + domain_score + html_score)
    
    # Keyword score (40% weight)
    urgency_score = min(features.get('urgency_count', 0) * 5, 15)
    threat_score = min(features.get('threat_count', 0) * 5, 15)
    action_score = min(features.get('action_count', 0) * 3, 10)
    keyword_score = urgency_score + threat_score + action_score
    
    total_score = confidence_score + ioc_score + keyword_score
    
    return min(int(total_score), 100)


def get_severity(risk_score: int) -> str:
    """
    Map risk score to severity level.
    
    Args:
        risk_score: Risk score (0-100)
        
    Returns:
        Severity: "LOW", "MEDIUM", or "HIGH"
    """
    if risk_score >= 70:
        return "HIGH"
    elif risk_score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


# ============================================================
# EMAIL PREPROCESSOR CLASS
# ============================================================

@dataclass
class ProcessedEmail:
    """Dataclass for processed email results."""
    preprocessed_text: str
    features: Dict[str, Any]
    iocs: Dict[str, List[str]]
    risk_score: int
    severity: str
    error: Optional[str] = None


class EmailPreprocessor:
    """
    Class-based preprocessor for batch processing of emails.
    """
    
    def __init__(self):
        self.processed_count = 0
        self.error_count = 0
    
    def process(self, content: str, confidence: float = 0.5) -> ProcessedEmail:
        """
        Process a single email and return full analysis.
        
        Args:
            content: Raw email content
            confidence: ML model confidence (optional, for risk calculation)
            
        Returns:
            ProcessedEmail dataclass with all extracted information
        """
        try:
            # Preprocess text
            preprocessed = preprocess_text(content)
            
            # Extract features
            features = extract_email_features(content)
            
            # Extract IOCs
            iocs = {
                'urls': extract_urls(content),
                'domains': extract_domains(content),
                'emails': extract_email_addresses(content),
                'keywords': features.get('suspicious_keywords', [])
            }
            
            # Calculate risk
            risk_score = calculate_risk_score(confidence, features)
            severity = get_severity(risk_score)
            
            self.processed_count += 1
            
            return ProcessedEmail(
                preprocessed_text=preprocessed,
                features=features,
                iocs=iocs,
                risk_score=risk_score,
                severity=severity
            )
            
        except Exception as e:
            self.error_count += 1
            logger.error(f"Error processing email: {e}")
            return ProcessedEmail(
                preprocessed_text='',
                features={},
                iocs={},
                risk_score=0,
                severity='LOW',
                error=str(e)
            )
    
    def process_batch(self, contents: List[str], confidences: Optional[List[float]] = None) -> List[ProcessedEmail]:
        """
        Process multiple emails.
        
        Args:
            contents: List of raw email contents
            confidences: Optional list of ML confidences
            
        Returns:
            List of ProcessedEmail results
        """
        if confidences is None:
            confidences = [0.5] * len(contents)
        
        return [
            self.process(content, conf) 
            for content, conf in zip(contents, confidences)
        ]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processing statistics."""
        total = self.processed_count + self.error_count
        return {
            'processed_count': self.processed_count,
            'error_count': self.error_count,
            'total': total,
            'success_rate': self.processed_count / total if total > 0 else 0
        }


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    'preprocess_text',
    'preprocess_file',
    'extract_urls',
    'extract_domains',
    'extract_email_addresses',
    'extract_email_features',
    'calculate_risk_score',
    'get_severity',
    'EmailPreprocessor',
    'ProcessedEmail',
    'URGENCY_KEYWORDS',
    'THREAT_KEYWORDS',
    'ACTION_KEYWORDS',
    'REWARD_KEYWORDS',
    'FINANCIAL_KEYWORDS'
]
