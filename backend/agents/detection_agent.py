"""
Detection Agent
===============
Agent responsible for phishing detection using ML model (TF-IDF + Logistic Regression).

Standard Output Contract:
{
    "agent": "detection",
    "status": "success" | "error",
    "email_id": str,
    "is_phishing": bool,
    "confidence": float (0.0 - 1.0),
    "risk_score": int (0 - 100),
    "severity": "LOW" | "MEDIUM" | "HIGH",
    "preprocessed_text": str,
    "timestamp": ISO8601 str,
    "model_used": bool,
    "error": str | null
}

Version: 2.0.0
"""

# Suppress sklearn version warnings
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
try:
    from sklearn.exceptions import InconsistentVersionWarning
    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except ImportError:
    pass

import os
import uuid
import joblib
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, asdict

# Import from project structure with fallbacks
try:
    from ml.preprocess import (
        preprocess_text, extract_email_features,
        calculate_risk_score, get_severity
    )
    from core.logger import get_logger
    from config.settings import MODEL_PATH, PHISHING_CONFIDENCE_THRESHOLD
except ImportError:
    try:
        from backend.ml.preprocess import (
            preprocess_text, extract_email_features,
            calculate_risk_score, get_severity
        )
        from backend.core.logger import get_logger
        from backend.config.settings import MODEL_PATH, PHISHING_CONFIDENCE_THRESHOLD
    except ImportError:
        try:
            from ..ml.preprocess import (
                preprocess_text, extract_email_features,
                calculate_risk_score, get_severity
            )
            from ..core.logger import get_logger
            from ..config.settings import MODEL_PATH, PHISHING_CONFIDENCE_THRESHOLD
        except ImportError:
            # Development fallbacks
            import re
            MODEL_PATH = "ml/models/phishing_model.pkl"
            PHISHING_CONFIDENCE_THRESHOLD = 0.5
            logging.basicConfig(level=logging.INFO)
            
            def get_logger(name):
                return logging.getLogger(name)
            
            def preprocess_text(text):
                if not text:
                    return ""
                text = text.lower()
                text = re.sub(r'http[s]?://\S+|www\.\S+', ' URL_TOKEN ', text)
                text = re.sub(r'\S+@\S+\.\S+', ' EMAIL_TOKEN ', text)
                text = re.sub(r'<[^>]+>', ' ', text)
                text = re.sub(r'[^a-zA-Z0-9\s]', ' ', text)
                text = re.sub(r'\s+', ' ', text).strip()
                return text
            
            def extract_email_features(content):
                return {'url_count': 0, 'urgency_count': 0, 'threat_count': 0}
            
            def calculate_risk_score(confidence, features):
                return int(confidence * 100)
            
            def get_severity(risk_score):
                if risk_score >= 70:
                    return "HIGH"
                elif risk_score >= 40:
                    return "MEDIUM"
                return "LOW"


@dataclass
class DetectionResult:
    """Dataclass for detection agent output."""
    agent: str = "detection"
    status: str = "success"
    email_id: str = ""
    is_phishing: bool = False
    confidence: float = 0.0
    risk_score: int = 0
    severity: str = "LOW"
    preprocessed_text: str = ""
    timestamp: str = ""
    model_used: bool = False
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, excluding None values for error."""
        result = asdict(self)
        if result['error'] is None:
            del result['error']
        return result


class DetectionAgent:
    """
    Detection Agent for phishing classification.
    
    Uses TF-IDF + Logistic Regression model for prediction.
    Falls back to rule-based detection if model unavailable.
    """
    
    AGENT_NAME = "detection"
    VERSION = "2.0.0"
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the Detection Agent.
        
        Args:
            model_path: Optional custom path to model file
        """
        self.logger = get_logger(__name__)
        self.model_path = model_path or MODEL_PATH
        self.model = None
        self.threshold = PHISHING_CONFIDENCE_THRESHOLD
        
        self._load_model()
        
        # Statistics
        self.stats = {
            'total_processed': 0,
            'phishing_detected': 0,
            'errors': 0
        }
    
    def _load_model(self) -> None:
        """Load ML model from disk."""
        # Try multiple potential paths
        paths_to_try = [
            self.model_path,
            os.path.join(os.path.dirname(__file__), '..', 'ml', 'models', 'phishing_model.pkl'),
            os.path.join('backend', 'ml', 'models', 'phishing_model.pkl'),
            os.path.join('ml', 'models', 'phishing_model.pkl'),
        ]
        
        for path in paths_to_try:
            if os.path.exists(path):
                try:
                    self.model = joblib.load(path)
                    self.logger.info(f"Loaded detection model from {path}")
                    return
                except Exception as e:
                    self.logger.warning(f"Failed to load model from {path}: {e}")
        
        self.logger.warning("No model file found. Running in fallback mode.")
    
    def is_model_loaded(self) -> bool:
        """Check if ML model is available."""
        return self.model is not None
    
    def analyze(self, email_content: str, email_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze email content for phishing.
        
        Args:
            email_content: Raw email text
            email_id: Optional email identifier
            
        Returns:
            Standard detection result dictionary
        """
        # Generate email_id if not provided
        if not email_id:
            email_id = f"email_{uuid.uuid4().hex[:12]}"
        
        result = DetectionResult(
            email_id=email_id,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        
        self.stats['total_processed'] += 1
        
        try:
            # Preprocess the email text
            preprocessed = preprocess_text(email_content)
            result.preprocessed_text = preprocessed
            
            if not preprocessed.strip():
                result.status = "error"
                result.error = "Empty content after preprocessing"
                self.stats['errors'] += 1
                return result.to_dict()
            
            # Extract features for risk calculation
            features = extract_email_features(email_content)
            
            # Get prediction
            if self.model:
                confidence = self._predict_with_model(preprocessed)
                result.model_used = True
            else:
                confidence = self._fallback_detection(email_content, features)
                result.model_used = False
            
            # Determine if phishing
            is_phishing = confidence >= self.threshold
            
            # Calculate risk score and severity
            risk_score = calculate_risk_score(confidence, features)
            severity = get_severity(risk_score)
            
            # Populate result
            result.is_phishing = is_phishing
            result.confidence = round(confidence, 4)
            result.risk_score = risk_score
            result.severity = severity
            
            # Update stats
            if is_phishing:
                self.stats['phishing_detected'] += 1
            
            self.logger.info(
                f"Detection [{email_id}]: phishing={is_phishing}, "
                f"confidence={confidence:.4f}, severity={severity}"
            )
            
        except Exception as e:
            result.status = "error"
            result.error = str(e)
            self.stats['errors'] += 1
            self.logger.error(f"Detection error for {email_id}: {e}")
        
        return result.to_dict()
    
    def _predict_with_model(self, preprocessed_text: str) -> float:
        """
        Get prediction confidence from ML model.
        
        Args:
            preprocessed_text: Preprocessed email text
            
        Returns:
            Confidence score (0.0 to 1.0)
        """
        if hasattr(self.model, 'predict_proba'):
            proba = self.model.predict_proba([preprocessed_text])
            return float(proba[0][1])
        else:
            prediction = self.model.predict([preprocessed_text])
            return 1.0 if prediction[0] == 1 else 0.0
    
    def _fallback_detection(self, content: str, features: Dict[str, Any]) -> float:
        """
        Rule-based fallback detection when model unavailable.
        
        Args:
            content: Raw email content
            features: Extracted email features
            
        Returns:
            Confidence score based on heuristics
        """
        content_lower = content.lower()
        score = 0.0
        
        # Keyword-based scoring - expanded for better demo detection
        phishing_indicators = [
            ('urgent', 0.15), ('verify your account', 0.20), ('click here', 0.15),
            ('password', 0.12), ('suspended', 0.20), ('expire', 0.15),
            ('confirm your', 0.15), ('unusual activity', 0.20), ('immediately', 0.15),
            ('prize', 0.18), ('winner', 0.18), ('congratulations', 0.15),
            ('bank account', 0.18), ('credit card', 0.18), ('login', 0.12),
            ('compromised', 0.22), ('limited', 0.15), ('verify', 0.12),
            ('action required', 0.18), ('account will be', 0.18),
            ('within 24 hours', 0.20), ('within 48 hours', 0.20),
            ('update your', 0.15), ('confirm your information', 0.20),
            ('secure portal', 0.18), ('tax refund', 0.22),
            ('payment failed', 0.18), ('unusual sign-in', 0.20),
            ('delivery problem', 0.15), ('storage full', 0.12),
            ('permanently closed', 0.22), ('service interruption', 0.18),
        ]
        
        for keyword, weight in phishing_indicators:
            if keyword in content_lower:
                score += weight
        
        # Check for suspicious domains (common in phishing)
        suspicious_domain_patterns = [
            '-verify', '-secure', '-login', '-update', '-confirm',
            '.xyz', '.info', '.co', '.net',
        ]
        for pattern in suspicious_domain_patterns:
            if pattern in content_lower:
                score += 0.12
        
        # Feature-based additions
        score += min(features.get('url_count', 0) * 0.08, 0.20)
        score += min(features.get('urgency_count', 0) * 0.10, 0.25)
        score += min(features.get('threat_count', 0) * 0.10, 0.25)
        
        return min(score, 0.98)
    
    def analyze_batch(self, emails: list, email_ids: Optional[list] = None) -> list:
        """
        Analyze multiple emails.
        
        Args:
            emails: List of email contents
            email_ids: Optional list of email identifiers
            
        Returns:
            List of detection results
        """
        if email_ids is None:
            email_ids = [None] * len(emails)
        
        return [
            self.analyze(content, eid)
            for content, eid in zip(emails, email_ids)
        ]
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze email from file.
        
        Args:
            file_path: Path to email file
            
        Returns:
            Detection result dictionary
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            email_id = os.path.basename(file_path)
            return self.analyze(content, email_id)
            
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
            return DetectionResult(
                email_id=os.path.basename(file_path),
                timestamp=datetime.now(timezone.utc).isoformat(),
                status="error",
                error=f"Failed to read file: {e}"
            ).to_dict()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get agent statistics."""
        return {
            'agent': self.AGENT_NAME,
            'version': self.VERSION,
            'model_loaded': self.is_model_loaded(),
            'threshold': self.threshold,
            **self.stats
        }


# Factory function for agent creation
def create_detection_agent(model_path: Optional[str] = None) -> DetectionAgent:
    """
    Factory function to create a DetectionAgent instance.
    
    Args:
        model_path: Optional custom model path
        
    Returns:
        Configured DetectionAgent
    """
    return DetectionAgent(model_path=model_path)


# Module-level singleton
_agent_instance: Optional[DetectionAgent] = None


def get_detection_agent() -> DetectionAgent:
    """Get or create detection agent singleton."""
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = DetectionAgent()
    return _agent_instance


# Direct execution for testing
if __name__ == "__main__":
    agent = DetectionAgent()
    
    test_email = """
    URGENT: Your account has been suspended!
    
    Dear Customer,
    
    We noticed unusual activity in your account. Your account will be terminated 
    within 24 hours unless you verify your identity.
    
    Click here to verify: http://suspicious-link.com/verify
    
    Enter your password and SSN to confirm.
    
    Best regards,
    Security Team
    """
    
    result = agent.analyze(test_email)
    print("Detection Result:")
    for key, value in result.items():
        print(f"  {key}: {value}")
