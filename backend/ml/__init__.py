"""
ML Package
==========
Machine learning components for phishing detection.

Version: 2.0.0 - TF-IDF + Logistic Regression Architecture
"""

from .preprocess import (
    preprocess_text, 
    preprocess_file, 
    EmailPreprocessor,
    extract_urls,
    extract_domains,
    extract_email_addresses,
    extract_email_features,
    calculate_risk_score,
    get_severity,
    ProcessedEmail,
    URGENCY_KEYWORDS,
    THREAT_KEYWORDS,
    ACTION_KEYWORDS,
    REWARD_KEYWORDS,
    FINANCIAL_KEYWORDS
)

# Lazy import for phishing_service to avoid circular imports
def get_phishing_service():
    """Get the phishing detection service (lazy import)."""
    from .phishing_service import get_phishing_service as _get_service
    return _get_service()

def get_detection_service():
    """Alias for get_phishing_service."""
    return get_phishing_service()

__all__ = [
    # Preprocessing
    'preprocess_text',
    'preprocess_file', 
    'EmailPreprocessor',
    'ProcessedEmail',
    
    # IOC extraction
    'extract_urls',
    'extract_domains',
    'extract_email_addresses',
    'extract_email_features',
    
    # Scoring
    'calculate_risk_score',
    'get_severity',
    
    # Keywords
    'URGENCY_KEYWORDS',
    'THREAT_KEYWORDS',
    'ACTION_KEYWORDS',
    'REWARD_KEYWORDS',
    'FINANCIAL_KEYWORDS',
    
    # Service
    'get_phishing_service',
    'get_detection_service',
]

__version__ = '2.0.0'
