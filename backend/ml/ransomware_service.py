"""
Ransomware Detection Service
==============================
Wraps the ML model for ransomware command detection with full API support.

Version: 1.0.0 - TF-IDF + Random Forest Architecture
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
    from ml.ransomware_preprocess import (
        preprocess_command, extract_command_features, CommandPreprocessor,
        extract_ips, extract_urls, extract_file_paths, extract_registry_keys,
        calculate_risk_score, get_severity
    )
    from config.settings import RANSOMWARE_MODEL_PATH, RANSOMWARE_MODEL_INFO_PATH, RANSOMWARE_CONFIDENCE_THRESHOLD
    from core.logger import get_logger

except ImportError:
    try:
        from backend.ml.ransomware_preprocess import (
            preprocess_command, extract_command_features, CommandPreprocessor,
            extract_ips, extract_urls, extract_file_paths, extract_registry_keys,
            calculate_risk_score, get_severity
        )
        from backend.config.settings import RANSOMWARE_MODEL_PATH, RANSOMWARE_MODEL_INFO_PATH, RANSOMWARE_CONFIDENCE_THRESHOLD
        from backend.core.logger import get_logger

    except ImportError:
        try:
            from .ransomware_preprocess import (
                preprocess_command, extract_command_features, CommandPreprocessor,
                extract_ips, extract_urls, extract_file_paths, extract_registry_keys,
                calculate_risk_score, get_severity
            )
            from ..config.settings import RANSOMWARE_MODEL_PATH, RANSOMWARE_MODEL_INFO_PATH, RANSOMWARE_CONFIDENCE_THRESHOLD
            from ..core.logger import get_logger

        except ImportError:
            # Development fallbacks
            from ransomware_preprocess import (
                preprocess_command, extract_command_features, CommandPreprocessor,
                extract_ips, extract_urls, extract_file_paths, extract_registry_keys,
                calculate_risk_score, get_severity
            )
            RANSOMWARE_MODEL_PATH      = "ml/models/ransomware_model.pkl"
            RANSOMWARE_MODEL_INFO_PATH = "ml/models/ransomware_model_info.json"
            RANSOMWARE_CONFIDENCE_THRESHOLD = 0.5
            logging.basicConfig(level=logging.INFO)
            def get_logger(name):
                return logging.getLogger(name)


class RansomwareDetectionService:
    """
    Service class for ransomware detection using trained ML model.
    """

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the ransomware detection service.

        Args:
            model_path: Optional custom path to the model file
        """
        self.logger     = get_logger(__name__)
        self.model_path = model_path or RANSOMWARE_MODEL_PATH
        self.model      = None
        self.model_info = None
        self.preprocessor = CommandPreprocessor()
        self._load_model()
        self._load_model_info()

        # Statistics
        self.stats = {
            'total_scans':       0,
            'ransomware_detected': 0,
            'benign_detected':   0,
            'errors':            0,
            'avg_confidence':    0.0,
        }

    def _load_model(self) -> None:
        """Load the ML model from disk."""
        paths_to_try = [
            self.model_path,
            os.path.join(os.path.dirname(__file__), 'models', 'ransomware_model.pkl'),
            os.path.join(os.path.dirname(__file__), '..', 'ml', 'models', 'ransomware_model.pkl'),
            os.path.join('backend', 'ml', 'models', 'ransomware_model.pkl'),
            os.path.join('ml', 'models', 'ransomware_model.pkl'),
        ]

        for path in paths_to_try:
            if os.path.exists(path):
                try:
                    self.model = joblib.load(path)
                    self.logger.info(f"Successfully loaded ML model from {path}")
                    return
                except Exception as e:
                    self.logger.warning(f"Failed to load model from {path}: {e}")

        self.logger.warning("Ransomware model file not found. Running in fallback mode.")

    def _load_model_info(self) -> None:
        """Load model metadata if available."""
        info_path = RANSOMWARE_MODEL_INFO_PATH
        if os.path.exists(info_path):
            try:
                with open(info_path, 'r') as f:
                    self.model_info = json.load(f)
                self.logger.info("Ransomware model info loaded successfully")
            except Exception as e:
                self.logger.error(f"Failed to load model info: {e}")

    def is_model_loaded(self) -> bool:
        """Check if model is loaded and ready."""
        return self.model is not None

    def predict(self, command: str) -> Dict[str, Any]:
        """
        Analyze a process/command string for ransomware indicators.

        Args:
            command: Raw process/command string

        Returns:
            Dictionary with prediction results
        """
        self.stats['total_scans'] += 1

        result = {
            'id':              f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
            'timestamp':       datetime.now(timezone.utc).isoformat(),
            'is_ransomware':   False,
            'confidence':      0.0,
            'severity':        'LOW',
            'risk_score':      0,
            'features':        {},
            'iocs':            {},
            'indicators':      [],
            'recommendation':  '',
            'model_used':      self.is_model_loaded(),
        }

        try:
            # Preprocess the command
            preprocessed = preprocess_command(command)
            features      = extract_command_features(command)
            result['features'] = features

            # Extract IOCs
            result['iocs'] = {
                'ips':           extract_ips(command),
                'urls':          extract_urls(command),
                'file_paths':    extract_file_paths(command),
                'registry_keys': extract_registry_keys(command),
                'keywords':      features.get('suspicious_keywords', [])
            }

            if self.model:
                # Use ML model for prediction
                if hasattr(self.model, 'predict_proba'):
                    proba      = self.model.predict_proba([preprocessed])
                    confidence = float(proba[0][1])  # Probability of ransomware
                else:
                    prediction = self.model.predict([preprocessed])
                    confidence = 1.0 if prediction[0] == 1 else 0.0

                is_ransomware = confidence >= RANSOMWARE_CONFIDENCE_THRESHOLD
            else:
                # Fallback: Rule-based detection
                confidence, is_ransomware = self._fallback_detection(command, features)
                result['model_used'] = False

            result['is_ransomware'] = is_ransomware
            result['confidence']    = round(confidence, 4)
            result['risk_score']    = calculate_risk_score(confidence, features)
            result['severity']      = get_severity(result['risk_score'])
            result['indicators']    = self._get_indicators(features, confidence)
            result['recommendation'] = self._get_recommendation(is_ransomware, result['severity'])

            # Update statistics
            if is_ransomware:
                self.stats['ransomware_detected'] += 1
            else:
                self.stats['benign_detected'] += 1

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

    def predict_batch(self, commands: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze multiple commands for ransomware.

        Args:
            commands: List of raw command strings

        Returns:
            List of prediction results
        """
        return [self.predict(cmd) for cmd in commands]

    def _fallback_detection(self, command: str, features: dict) -> tuple:
        """
        Rule-based fallback detection when model is not available.

        Returns:
            Tuple of (confidence, is_ransomware)
        """
        command_lower = command.lower()
        score = 0.0

        ransomware_indicators = [
            ('vssadmin',           0.25),
            ('shadowcopy delete',  0.25),
            ('wbadmin delete',     0.25),
            ('bcdedit',            0.20),
            ('recoveryenabled no', 0.25),
            ('mimikatz',           0.30),
            ('sekurlsa',           0.25),
            ('cipher /w',         0.20),
            ('ransom',             0.20),
            ('decrypt',            0.15),
            ('encrypt',            0.15),
            ('-nop -w hidden',     0.20),
            ('bypass',             0.15),
            ('psexec',             0.15),
            ('certutil -decode',   0.20),
        ]

        for keyword, weight in ransomware_indicators:
            if keyword in command_lower:
                score += weight

        # Feature-based additions
        score += min(features.get('shadow_count',      0) * 0.15, 0.30)
        score += min(features.get('boot_count',        0) * 0.10, 0.20)
        score += min(features.get('credential_count',  0) * 0.15, 0.30)
        score += min(features.get('obfuscation_count', 0) * 0.10, 0.20)

        confidence    = min(score, 0.98)
        is_ransomware = confidence >= RANSOMWARE_CONFIDENCE_THRESHOLD
        return confidence, is_ransomware

    def _get_indicators(self, features: dict, confidence: float) -> List[str]:
        """Generate list of threat indicators found."""
        indicators = []

        if features.get('shadow_count', 0) > 0:
            indicators.append(f"Shadow copy deletion attempt detected")
        if features.get('boot_count', 0) > 0:
            indicators.append(f"Boot recovery disabled")
        if features.get('service_kill_count', 0) > 0:
            indicators.append(f"Critical service termination ({features['service_kill_count']} matches)")
        if features.get('credential_count', 0) > 0:
            indicators.append(f"Credential harvesting tool detected")
        if features.get('obfuscation_count', 0) > 0:
            indicators.append(f"Command obfuscation detected ({features['obfuscation_count']} matches)")
        if features.get('persistence_count', 0) > 0:
            indicators.append(f"Persistence mechanism detected")
        if features.get('lateral_count', 0) > 0:
            indicators.append(f"Lateral movement attempt detected")
        if features.get('ransom_note_count', 0) > 0:
            indicators.append(f"Ransom note delivery detected")
        if features.get('ip_count', 0) > 0:
            indicators.append(f"Contains {features['ip_count']} IP address(es) — possible C2")
        if features.get('url_count', 0) > 0:
            indicators.append(f"Contains {features['url_count']} URL(s) — possible payload download")
        if features.get('suspicious_keywords'):
            kw_list = features['suspicious_keywords'][:5]
            indicators.append(f"Suspicious keywords: {', '.join(kw_list)}")
        if confidence >= 0.75:
            indicators.append("High-confidence ransomware pattern detected")

        return indicators

    def _get_recommendation(self, is_ransomware: bool, severity: str) -> str:
        """Generate action recommendation based on severity."""
        if is_ransomware:
            if severity == 'HIGH':
                return "IMMEDIATE ACTION: Kill process, isolate host, block hash, and alert SOC."
            elif severity == 'MEDIUM':
                return "HIGH PRIORITY: Kill process, block command hash, and review endpoint."
            else:
                return "REVIEW REQUIRED: Flag process as suspicious and monitor endpoint activity."
        else:
            return "SAFE: No significant ransomware indicators detected."

    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics."""
        return {
            **self.stats,
            'model_loaded':      self.is_model_loaded(),
            'model_info':        self.model_info,
            'preprocessor_stats': self.preprocessor.get_stats(),
        }

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the loaded model."""
        return {
            'model_loaded': self.is_model_loaded(),
            'model_path':   self.model_path,
            'model_info':   self.model_info,
            'threshold':    RANSOMWARE_CONFIDENCE_THRESHOLD,
        }


# Singleton instance for API use
_service_instance: Optional[RansomwareDetectionService] = None


def get_ransomware_service() -> RansomwareDetectionService:
    """Get or create the ransomware detection service singleton."""
    global _service_instance
    if _service_instance is None:
        _service_instance = RansomwareDetectionService()
    return _service_instance
