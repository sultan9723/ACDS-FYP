"""
Text Preprocessing Module for Ransomware Detection
====================================================
Unified preprocessing pipeline - NO NLTK required.
MUST match the preprocessing used during model training.

Version: 1.0.0
"""

import re
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ============================================================
# CONSTANTS - Ransomware Indicators
# ============================================================

SHADOW_KEYWORDS = [
    'vssadmin', 'shadowcopy', 'wbadmin', 'shadow',
    'delete shadows', 'delete catalog', 'delete systemstatebackup'
]

BOOT_KEYWORDS = [
    'bcdedit', 'recoveryenabled', 'bootstatuspolicy',
    'ignoreallfailures', 'ignoreshutdownfailures'
]

SERVICE_KILL_KEYWORDS = [
    'net stop', 'taskkill', 'sc delete', 'sc stop',
    'sqlbrowser', 'mysqld', 'oracle', 'vss', 'swprv',
    'volume shadow', 'windows backup', 'sql server'
]

PERSISTENCE_KEYWORDS = [
    'schtasks', 'reg add', 'sc create', 'startup',
    'currentversion\\run', 'currentversion\\runonce',
    'onlogon', 'onstart', 'onstartup'
]

LATERAL_KEYWORDS = [
    'psexec', 'net use', 'wmic process call create',
    'xcopy', 'expand', 'robocopy /mir'
]

OBFUSCATION_KEYWORDS = [
    'certutil -decode', 'powershell -enc', 'powershell -nop',
    'bypass', 'hidden', 'base64', 'mshta', 'regsvr32',
    'rundll32', 'bitsadmin', '-windowstyle hidden'
]

CREDENTIAL_KEYWORDS = [
    'mimikatz', 'sekurlsa', 'logonpasswords', 'lsadump',
    'hashdump', 'wce.exe', 'pwdump', 'fgdump'
]

RANSOM_NOTE_KEYWORDS = [
    'readme_to_decrypt', 'how_to_decrypt', 'ransom_note',
    'your_files_are_encrypted', 'restore_files',
    'decrypt_instructions', 'read_this'
]

# ============================================================
# PREPROCESSING FUNCTIONS - Must Match Training
# ============================================================

def preprocess_command(text: str) -> str:
    """
    Unified preprocessing for process/command strings.

    ⚠️ CRITICAL: This function MUST match ml_training/ransomware_model.ipynb

    Args:
        text: Raw process command string

    Returns:
        Cleaned and preprocessed text ready for model prediction
    """
    if not isinstance(text, str) or not text.strip():
        return ""

    # Lowercase
    text = text.lower()

    # Replace IPs with token (preserve as ransomware indicator)
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ' IP_TOKEN ', text)

    # Replace URLs / C2 addresses with token
    text = re.sub(r'http[s]?://\S+|www\.\S+', ' URL_TOKEN ', text)

    # Replace Base64-like blobs with token
    text = re.sub(r'[A-Za-z0-9+/]{30,}={0,2}', ' BASE64_TOKEN ', text)

    # Replace hex strings with token
    text = re.sub(r'\b[0-9a-fA-F]{8,}\b', ' HEX_TOKEN ', text)

    # Keep alphanumeric, backslash, spaces, underscore
    text = re.sub(r'[^a-zA-Z0-9\s_\\]', ' ', text)

    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text).strip()

    return text


# ============================================================
# IOC EXTRACTION FUNCTIONS
# ============================================================

def extract_ips(text: str) -> List[str]:
    """Extract all IP addresses from command text."""
    if not text:
        return []
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return list(set(re.findall(pattern, text)))


def extract_urls(text: str) -> List[str]:
    """Extract all URLs from command text."""
    if not text:
        return []
    pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
    return list(set(re.findall(pattern, text, re.IGNORECASE)))


def extract_file_paths(text: str) -> List[str]:
    """Extract Windows file paths from command text."""
    if not text:
        return []
    pattern = r'[a-zA-Z]:\\(?:[^\s<>"|?*\n\\]+\\)*[^\s<>"|?*\n\\]*'
    return list(set(re.findall(pattern, text)))


def extract_registry_keys(text: str) -> List[str]:
    """Extract registry key paths from command text."""
    if not text:
        return []
    pattern = r'HK(?:EY_)?(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|LM|CU)\\[^\s]+'
    return list(set(re.findall(pattern, text, re.IGNORECASE)))


def extract_keywords(text: str, keyword_list: List[str]) -> List[str]:
    """Extract matching keywords from text."""
    if not text:
        return []
    text_lower = text.lower()
    return [kw for kw in keyword_list if kw in text_lower]


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_command_features(command: str) -> Dict[str, Any]:
    """
    Extract features from a command string for enhanced detection.

    Args:
        command: Raw process/command string

    Returns:
        Dictionary of extracted features
    """
    if not command:
        return {
            'ip_count':              0,
            'url_count':             0,
            'file_path_count':       0,
            'registry_key_count':    0,
            'shadow_keywords':       0,
            'boot_keywords':         0,
            'service_kill_keywords': 0,
            'persistence_keywords': 0,
            'lateral_keywords':      0,
            'obfuscation_keywords':  0,
            'credential_keywords':   0,
            'ransom_note_keywords':  0,
            'suspicious_keywords':   [],
            'command_length':        0,
        }

    command_lower = command.lower()

    # Extract IOCs
    ips          = extract_ips(command)
    urls         = extract_urls(command)
    file_paths   = extract_file_paths(command)
    registry_keys = extract_registry_keys(command)

    # Extract keyword category matches
    shadow      = extract_keywords(command_lower, SHADOW_KEYWORDS)
    boot        = extract_keywords(command_lower, BOOT_KEYWORDS)
    svc_kill    = extract_keywords(command_lower, SERVICE_KILL_KEYWORDS)
    persistence = extract_keywords(command_lower, PERSISTENCE_KEYWORDS)
    lateral     = extract_keywords(command_lower, LATERAL_KEYWORDS)
    obfuscation = extract_keywords(command_lower, OBFUSCATION_KEYWORDS)
    credential  = extract_keywords(command_lower, CREDENTIAL_KEYWORDS)
    ransom_note = extract_keywords(command_lower, RANSOM_NOTE_KEYWORDS)

    all_suspicious = list(set(
        shadow + boot + svc_kill + persistence +
        lateral + obfuscation + credential + ransom_note
    ))

    return {
        'ip_count':              len(ips),
        'url_count':             len(urls),
        'file_path_count':       len(file_paths),
        'registry_key_count':    len(registry_keys),
        'shadow_keywords':       len(shadow),
        'boot_keywords':         len(boot),
        'service_kill_keywords': len(svc_kill),
        'persistence_keywords':  len(persistence),
        'lateral_keywords':      len(lateral),
        'obfuscation_keywords':  len(obfuscation),
        'credential_keywords':   len(credential),
        'ransom_note_keywords':  len(ransom_note),
        'suspicious_keywords':   all_suspicious,
        'command_length':        len(command),
    }


# ============================================================
# RISK SCORING
# ============================================================

def calculate_risk_score(confidence: float, features: Dict[str, Any]) -> int:
    """
    Calculate risk score (0-100) based on ML confidence and features.

    Formula:
        risk_score = (confidence × 40) + (ioc_score × 20) + (behavior_score × 40)

    Args:
        confidence: ML model confidence (0.0 to 1.0)
        features:   Extracted command features

    Returns:
        Risk score as integer (0-100)
    """
    # Base score from ML confidence (40% weight)
    confidence_score = confidence * 40

    # IOC score (20% weight)
    ip_score   = min(features.get('ip_count',  0) * 5, 10)
    url_score  = min(features.get('url_count', 0) * 5, 10)
    ioc_score  = ip_score + url_score

    # Behavior score (40% weight)
    shadow_score      = min(features.get('shadow_keywords',       0) * 8, 15)
    boot_score        = min(features.get('boot_keywords',         0) * 6, 10)
    obfuscation_score = min(features.get('obfuscation_keywords',  0) * 5, 10)
    credential_score  = min(features.get('credential_keywords',   0) * 8, 10)
    behavior_score    = shadow_score + boot_score + obfuscation_score + credential_score

    total_score = confidence_score + ioc_score + behavior_score
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
# COMMAND PREPROCESSOR CLASS
# ============================================================

@dataclass
class ProcessedCommand:
    """Dataclass for processed command results."""
    preprocessed_text: str
    features:          Dict[str, Any]
    iocs:              Dict[str, List[str]]
    risk_score:        int
    severity:          str
    error:             Optional[str] = None


class CommandPreprocessor:
    """
    Class-based preprocessor for batch processing of commands.
    """

    def __init__(self):
        self.processed_count = 0
        self.error_count     = 0

    def process(self, command: str, confidence: float = 0.5) -> ProcessedCommand:
        """
        Process a single command string and return full analysis.

        Args:
            command:    Raw process/command string
            confidence: ML model confidence (optional, for risk calculation)

        Returns:
            ProcessedCommand dataclass with all extracted information
        """
        try:
            preprocessed = preprocess_command(command)
            features      = extract_command_features(command)

            iocs = {
                'ips':          extract_ips(command),
                'urls':         extract_urls(command),
                'file_paths':   extract_file_paths(command),
                'registry_keys': extract_registry_keys(command),
                'keywords':     features.get('suspicious_keywords', [])
            }

            risk_score = calculate_risk_score(confidence, features)
            severity   = get_severity(risk_score)

            self.processed_count += 1

            return ProcessedCommand(
                preprocessed_text=preprocessed,
                features=features,
                iocs=iocs,
                risk_score=risk_score,
                severity=severity
            )

        except Exception as e:
            self.error_count += 1
            logger.error(f"Error processing command: {e}")
            return ProcessedCommand(
                preprocessed_text='',
                features={},
                iocs={},
                risk_score=0,
                severity='LOW',
                error=str(e)
            )

    def process_batch(
        self,
        commands:    List[str],
        confidences: Optional[List[float]] = None
    ) -> List[ProcessedCommand]:
        """
        Process multiple commands.

        Args:
            commands:    List of raw command strings
            confidences: Optional list of ML confidences

        Returns:
            List of ProcessedCommand results
        """
        if confidences is None:
            confidences = [0.5] * len(commands)
        return [
            self.process(cmd, conf)
            for cmd, conf in zip(commands, confidences)
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Get processing statistics."""
        total = self.processed_count + self.error_count
        return {
            'processed_count': self.processed_count,
            'error_count':     self.error_count,
            'total':           total,
            'success_rate':    self.processed_count / total if total > 0 else 0
        }


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    'preprocess_command',
    'extract_ips',
    'extract_urls',
    'extract_file_paths',
    'extract_registry_keys',
    'extract_command_features',
    'calculate_risk_score',
    'get_severity',
    'CommandPreprocessor',
    'ProcessedCommand',
    'SHADOW_KEYWORDS',
    'BOOT_KEYWORDS',
    'SERVICE_KILL_KEYWORDS',
    'PERSISTENCE_KEYWORDS',
    'LATERAL_KEYWORDS',
    'OBFUSCATION_KEYWORDS',
    'CREDENTIAL_KEYWORDS',
    'RANSOM_NOTE_KEYWORDS',
]
