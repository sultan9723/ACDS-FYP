"""
Phishing Detection Service
===========================
Wraps the ML model for phishing email detection with full API support.

Version: 2.0.0 - TF-IDF + Logistic Regression Architecture
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
import json
import joblib
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

# Try multiple import paths to support different running contexts
try:
    from ml.preprocess import (
        preprocess_text, extract_email_features, EmailPreprocessor,
        extract_urls, extract_domains, extract_email_addresses,
        calculate_risk_score, get_severity
    )
    from config.settings import MODEL_PATH, MODEL_INFO_PATH, PHISHING_CONFIDENCE_THRESHOLD
    from core.logger import get_logger
except ImportError:
    try:
        from backend.ml.preprocess import (
            preprocess_text, extract_email_features, EmailPreprocessor,
            extract_urls, extract_domains, extract_email_addresses,
            calculate_risk_score, get_severity
        )
        from backend.config.settings import MODEL_PATH, MODEL_INFO_PATH, PHISHING_CONFIDENCE_THRESHOLD
        from backend.core.logger import get_logger
    except ImportError:
        try:
            from .preprocess import (
                preprocess_text, extract_email_features, EmailPreprocessor,
                extract_urls, extract_domains, extract_email_addresses,
                calculate_risk_score, get_severity
            )
            from ..config.settings import MODEL_PATH, MODEL_INFO_PATH, PHISHING_CONFIDENCE_THRESHOLD
            from ..core.logger import get_logger
        except ImportError:
            # Development fallbacks
            from preprocess import (
                preprocess_text, extract_email_features, EmailPreprocessor,
                extract_urls, extract_domains, extract_email_addresses,
                calculate_risk_score, get_severity
            )
            MODEL_PATH = "ml/models/phishing_model.pkl"
            MODEL_INFO_PATH = "ml/models/model_info.json"
            PHISHING_CONFIDENCE_THRESHOLD = 0.5
            logging.basicConfig(level=logging.INFO)
            def get_logger(name):
                return logging.getLogger(name)


class PhishingDetectionService:
    """
    Service class for phishing email detection using trained ML model.
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the phishing detection service.
        
        Args:
            model_path: Optional custom path to the model file
        """
        self.logger = get_logger(__name__)
        self.model_path = model_path or MODEL_PATH
        self.model = None
        self.model_info = None
        self.preprocessor = EmailPreprocessor()
        self._load_model()
        self._load_model_info()
        
        # Statistics
        self.stats = {
            'total_scans': 0,
            'phishing_detected': 0,
            'safe_detected': 0,
            'errors': 0,
            'avg_confidence': 0.0,
        }
    
    def _load_model(self) -> None:
        """Load the ML model from disk."""
        # Try multiple potential paths
        paths_to_try = [
            self.model_path,
            os.path.join(os.path.dirname(__file__), 'models', 'phishing_model.pkl'),
            os.path.join(os.path.dirname(__file__), '..', 'ml', 'models', 'phishing_model.pkl'),
            os.path.join('backend', 'ml', 'models', 'phishing_model.pkl'),
            os.path.join('ml', 'models', 'phishing_model.pkl'),
        ]
        
        for path in paths_to_try:
            if os.path.exists(path):
                try:
                    self.model = joblib.load(path)
                    self.logger.info(f"Successfully loaded ML model from {path}")
                    return
                except Exception as e:
                    self.logger.warning(f"Failed to load model from {path}: {e}")
        
        self.logger.warning(f"Model file not found. Running in fallback mode.")
    
    def _load_model_info(self) -> None:
        """Load model metadata if available."""
        info_path = MODEL_INFO_PATH
        if os.path.exists(info_path):
            try:
                with open(info_path, 'r') as f:
                    self.model_info = json.load(f)
                self.logger.info("Model info loaded successfully")
            except Exception as e:
                self.logger.error(f"Failed to load model info: {e}")
    
    def is_model_loaded(self) -> bool:
        """Check if model is loaded and ready."""
        return self.model is not None
    
    def predict(self, email_content: str) -> Dict[str, Any]:
        """
        Analyze an email for phishing indicators.
        
        Args:
            email_content: Raw email text content
            
        Returns:
            Dictionary with prediction results
        """
        self.stats['total_scans'] += 1
        
        result = {
            'id': f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'is_phishing': False,
            'confidence': 0.0,
            'severity': 'LOW',
            'risk_score': 0,
            'features': {},
            'iocs': {},
            'indicators': [],
            'recommendation': '',
            'model_used': self.is_model_loaded(),
        }
        
        try:
            # Preprocess the email
            preprocessed = preprocess_text(email_content)
            features = extract_email_features(email_content)
            result['features'] = features
            
            # Extract IOCs
            result['iocs'] = {
                'urls': extract_urls(email_content),
                'domains': extract_domains(email_content),
                'emails': extract_email_addresses(email_content),
                'keywords': features.get('suspicious_keywords', [])
            }
            
            if self.model:
                # Use ML model for prediction
                if hasattr(self.model, 'predict_proba'):
                    proba = self.model.predict_proba([preprocessed])
                    confidence = float(proba[0][1])  # Probability of phishing
                else:
                    prediction = self.model.predict([preprocessed])
                    confidence = 1.0 if prediction[0] == 1 else 0.0
                
                is_phishing = confidence >= PHISHING_CONFIDENCE_THRESHOLD
            else:
                # Fallback: Rule-based detection
                confidence, is_phishing = self._fallback_detection(email_content, features)
                result['model_used'] = False
            
            result['is_phishing'] = is_phishing
            result['confidence'] = round(confidence, 4)
            
            # Use unified risk score and severity from preprocess module
            result['risk_score'] = calculate_risk_score(confidence, features)
            result['severity'] = get_severity(result['risk_score'])
            
            result['indicators'] = self._get_indicators(features, confidence)
            result['recommendation'] = self._get_recommendation(is_phishing, result['severity'])
            
            # Update statistics
            if is_phishing:
                self.stats['phishing_detected'] += 1
            else:
                self.stats['safe_detected'] += 1
            
            # Update running average confidence
            total = self.stats['total_scans']
            self.stats['avg_confidence'] = (
                (self.stats['avg_confidence'] * (total - 1) + confidence) / total
            )
            
        except Exception as e:
            self.logger.error(f"Error during prediction: {e}")
            self.stats['errors'] += 1
            result['error'] = str(e)
        
        return result
    
    def predict_batch(self, emails: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze multiple emails for phishing.
        
        Args:
            emails: List of raw email contents
            
        Returns:
            List of prediction results
        """
        return [self.predict(email) for email in emails]
    
    def _fallback_detection(self, content: str, features: dict) -> tuple:
        """
        Rule-based fallback detection when model is not available.
        
        Returns:
            Tuple of (confidence, is_phishing)
        """
        content_lower = content.lower()
        score = 0.0
        
        # Check for phishing keywords
        phishing_keywords = [
            ('urgent', 0.15), ('verify your account', 0.2), ('click here', 0.15),
            ('password', 0.1), ('suspended', 0.2), ('expire', 0.15),
            ('confirm your', 0.15), ('unusual activity', 0.2), ('immediately', 0.15),
            ('prize', 0.2), ('winner', 0.2), ('congratulations', 0.15),
        ]
        
        for keyword, weight in phishing_keywords:
            if keyword in content_lower:
                score += weight
        
        # Add feature-based scoring
        score += features.get('urgency_score', 0) * 0.1
        score += len(features.get('suspicious_keywords', [])) * 0.05
        
        if features.get('url_count', 0) > 3:
            score += 0.15
        
        confidence = min(score, 0.95)
        is_phishing = confidence >= PHISHING_CONFIDENCE_THRESHOLD
        
        return confidence, is_phishing
    
    def _get_indicators(self, features: dict, confidence: float) -> List[str]:
        """Generate list of threat indicators found."""
        indicators = []
        
        if features.get('url_count', 0) > 0:
            indicators.append(f"Contains {features['url_count']} URL(s)")
        
        if features.get('urgency_count', 0) > 0:
            indicators.append(f"Urgency language detected (count: {features['urgency_count']})")
        
        if features.get('threat_count', 0) > 0:
            indicators.append(f"Threat keywords found (count: {features['threat_count']})")
        
        if features.get('action_count', 0) > 0:
            indicators.append(f"Action keywords detected (count: {features['action_count']})")
        
        if features.get('suspicious_keywords'):
            kw_list = features['suspicious_keywords'][:5]
            indicators.append(f"Suspicious keywords: {', '.join(kw_list)}")
        
        if features.get('has_html'):
            indicators.append("Contains HTML content")
        
        if confidence >= 0.75:
            indicators.append("High-confidence phishing pattern detected")
        
        return indicators
    
    def _get_recommendation(self, is_phishing: bool, severity: str) -> str:
        """Generate action recommendation based on severity."""
        if is_phishing:
            if severity == 'HIGH':
                return "IMMEDIATE ACTION: Quarantine email, block sender, and alert security team."
            elif severity == 'MEDIUM':
                return "HIGH PRIORITY: Quarantine email and review sender reputation."
            else:
                return "REVIEW REQUIRED: Mark as suspicious and monitor for similar patterns."
        else:
            return "SAFE: No significant phishing indicators detected."
    
    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics."""
        return {
            **self.stats,
            'model_loaded': self.is_model_loaded(),
            'model_info': self.model_info,
            'preprocessor_stats': self.preprocessor.get_stats(),
        }
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the loaded model."""
        return {
            'model_loaded': self.is_model_loaded(),
            'model_path': self.model_path,
            'model_info': self.model_info,
            'threshold': PHISHING_CONFIDENCE_THRESHOLD,
        }


# Singleton instance for API use
_service_instance: Optional[PhishingDetectionService] = None


def get_phishing_service() -> PhishingDetectionService:
    """Get or create the phishing detection service singleton."""
    global _service_instance
    if _service_instance is None:
        _service_instance = PhishingDetectionService()
    return _service_instance
