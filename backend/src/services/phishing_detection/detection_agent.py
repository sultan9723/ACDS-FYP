import logging
import re
from typing import Dict, Any, List, Optional
from .models import Email
import os
import joblib # For loading potential ML models later
from sklearn.feature_extraction.text import TfidfVectorizer # Example ML dependency
from sklearn.linear_model import LogisticRegression # Example ML dependency

logger = logging.getLogger(__name__)

# --- Rule-based Phishing Indicators ---
PHISHING_KEYWORDS = [
    "urgent action required", "verify your account", "account suspended", 
    "password reset", "security alert", "invoice due", "payment failed", 
    "unusual activity", "click here", "update your information", 
    "your order is on its way", # Common for scam, but can be legitimate
    "confirm your identity"
]

SUSPICIOUS_URL_PATTERNS = [
    r"https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", # IP address in URL
    r"bit\.ly", r"tinyurl\.com", r"goo\.gl", # Common URL shorteners
    # Add more complex regex for domain impersonation, etc., as needed
]

# --- Placeholder ML Model (for future use or expansion) ---
class PlaceholderPhishingModel:
    def __init__(self):
        # In a real scenario, load a pre-trained model and vectorizer
        # For now, it's a placeholder
        self.model = None
        self.vectorizer = None
        logger.info("PlaceholderPhishingModel initialized. No actual ML model loaded.")

    def predict_proba(self, text: str) -> List[float]:
        # Placeholder prediction: random scores
        import random
        return [random.uniform(0.1, 0.9), random.uniform(0.1, 0.9)] # [proba_non_phishing, proba_phishing]

    def _load_model_assets(self, model_path: str, vectorizer_path: str):
        if os.path.exists(model_path) and os.path.exists(vectorizer_path):
            self.model = joblib.load(model_path)
            self.vectorizer = joblib.load(vectorizer_path)
            logger.info("Actual ML model and vectorizer loaded.")
        else:
            logger.warning(f"ML model or vectorizer not found at {model_path}, {vectorizer_path}. Using placeholder.")
            self.model = PlaceholderPhishingModel() # Fallback to placeholder if not found
            self.vectorizer = TfidfVectorizer() # Dummy vectorizer

# --- Detection Agent ---
class DetectionAgent:
    """
    Agent responsible for detecting phishing indicators in emails.
    """
    def __init__(self, use_ml: bool = False, ml_model_path: Optional[str] = None, ml_vectorizer_path: Optional[str] = None):
        self.use_ml = use_ml
        self.ml_model = None
        if self.use_ml:
            self.ml_model = PlaceholderPhishingModel() # Initialize placeholder or load real ML model
            # In a real scenario, the model and vectorizer would be loaded from paths
            # self.ml_model._load_model_assets(ml_model_path, ml_vectorizer_path)
        logger.info(f"DetectionAgent initialized. ML enabled: {use_ml}")

    def _check_keywords(self, text: str) -> List[str]:
        """Checks text for known phishing keywords."""
        found_keywords = []
        text_lower = text.lower()
        for keyword in PHISHING_KEYWORDS:
            if keyword in text_lower:
                found_keywords.append(keyword)
        return found_keywords

    def _extract_urls(self, text: str) -> List[str]:
        """Extracts URLs from text."""
        # Simple regex to find URLs, can be improved
        urls = re.findall(r'http[s]?:\/\/[^\s\/$.?#].[^\s]*', text)
        return urls

    def _check_suspicious_urls(self, text: str) -> List[str]:
        """Checks for suspicious URL patterns in text."""
        suspicious_urls = []
        urls = self._extract_urls(text)
        for url in urls:
            for pattern in SUSPICIOUS_URL_PATTERNS:
                if re.search(pattern, url):
                    suspicious_urls.append(url)
                    break # Only add once per URL
        return suspicious_urls
    
    def detect_phishing(self, email: Email) -> Dict[str, Any]:
        """
        Detects phishing indicators in an email.
        Returns a dictionary with detection results and confidence.
        """
        reasons = []
        rule_score = 0.0 # Keep rule score separate initially
        is_phishing_by_rules = False

        # Rule-based detection
        email_content_to_check = email.subject + " " + email.body + " " + " ".join(email.headers.values()) # Check all relevant parts

        found_keywords = self._check_keywords(email_content_to_check)
        if found_keywords:
            reasons.append(f"Found phishing keywords: {', '.join(found_keywords)}")
            rule_score = max(rule_score, 0.4) # At least moderate score if keywords found
            is_phishing_by_rules = True

        found_suspicious_urls = self._check_suspicious_urls(email_content_to_check)
        if found_suspicious_urls:
            reasons.append(f"Found suspicious URLs: {', '.join(found_suspicious_urls)}")
            rule_score = max(rule_score, 0.5) # Higher score if URLs found
            is_phishing_by_rules = True
        
        final_confidence_score = min(rule_score, 1.0) # Cap at 1.0

        # Placeholder ML-based detection (if enabled)
        if self.use_ml and self.ml_model:
            full_text_for_ml = email.subject + " " + email.body + " " + " ".join(email.headers.values())
            try:
                ml_proba = self.ml_model.predict_proba(full_text_for_ml)
                phishing_confidence_ml = ml_proba[1] # Confidence for phishing class
                
                # If ML is more confident, let it influence the decision/score
                if phishing_confidence_ml > final_confidence_score:
                    final_confidence_score = phishing_confidence_ml
                
                # If ML strongly indicates phishing, set is_phishing to true, regardless of rules
                # Assuming PHISHING_CONFIDENCE_THRESHOLD might be defined in settings for a real model
                if phishing_confidence_ml > 0.6: # Placeholder threshold
                    reasons.append(f"ML model predicted phishing with confidence: {phishing_confidence_ml:.2f}")
                    is_phishing_by_rules = True # ML can override initial rule-based decision
            except Exception as e:
                logger.error(f"Error during ML prediction: {e}")
                reasons.append("ML model prediction failed, relying on rule-based detection.")
        
        # Final decision: if any rule or ML makes it true
        is_phishing = is_phishing_by_rules
        
        return {
            "is_phishing": is_phishing,
            "confidence_score": min(final_confidence_score, 1.0),
            "matched_indicators": reasons,
            "detection_agent_id": "RuleBased_ML_Placeholder_Agent"
        }

def get_detection_agent(use_ml: bool = False) -> DetectionAgent:
    """Returns a singleton-like instance of the DetectionAgent."""
    # In a real application, consider proper dependency injection or a true singleton pattern
    return DetectionAgent(use_ml=use_ml)
