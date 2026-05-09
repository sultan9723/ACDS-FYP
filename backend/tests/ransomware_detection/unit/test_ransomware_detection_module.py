import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from backend.ml.ransomware_preprocess import (
    preprocess_command,
    extract_ips,
    extract_urls,
    extract_file_paths,
    extract_registry_keys,
    extract_keywords,
    extract_command_features,
    calculate_risk_score,
    get_severity,
    SHADOW_KEYWORDS,
    BOOT_KEYWORDS,
    SERVICE_KILL_KEYWORDS,
    OBFUSCATION_KEYWORDS,
    CREDENTIAL_KEYWORDS,
    RANSOM_NOTE_KEYWORDS,
)
from backend.agents.ransomware_detection_agent import RansomwareDetectionAgent


# =============================================================================
# Tests for Preprocessing
# =============================================================================

def test_preprocess_lowercases_command():
    result = preprocess_command("VSSADMIN DELETE SHADOWS")
    assert result == result.lower()

def test_preprocess_replaces_ip_with_token():
    result = preprocess_command("connect to 192.168.1.1")
    assert "IP_TOKEN" in result
    assert "192.168.1.1" not in result

def test_preprocess_replaces_url_with_token():
    result = preprocess_command("download http://evil.com/payload")
    assert "URL_TOKEN" in result

def test_preprocess_replaces_base64_with_token():
    result = preprocess_command("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")
    assert "BASE64_TOKEN" in result

def test_preprocess_empty_command():
    result = preprocess_command("")
    assert result == ""

def test_extract_ips_finds_valid_ip():
    result = extract_ips("connect to 192.168.1.100")
    assert "192.168.1.100" in result

def test_extract_ips_returns_empty_for_no_ip():
    result = extract_ips("notepad.exe document.txt")
    assert result == []

def test_extract_urls_finds_http():
    result = extract_urls("download from http://evil.com/file.exe")
    assert len(result) > 0

def test_extract_urls_returns_empty_for_no_url():
    result = extract_urls("vssadmin delete shadows /all")
    assert result == []

def test_extract_file_paths_finds_windows_path():
    result = extract_file_paths("copy C:\\Windows\\System32\\cmd.exe C:\\temp\\")
    assert len(result) > 0

def test_extract_registry_keys_finds_hklm():
    result = extract_registry_keys(
        "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    )
    assert len(result) > 0

def test_extract_keywords_finds_shadow_keyword():
    result = extract_keywords("vssadmin delete shadows /all", SHADOW_KEYWORDS)
    assert len(result) > 0

def test_extract_keywords_finds_boot_keyword():
    result = extract_keywords("bcdedit /set {default} recoveryenabled No", BOOT_KEYWORDS)
    assert len(result) > 0

def test_extract_keywords_case_insensitive():
    result = extract_keywords("VSSADMIN DELETE SHADOWS", SHADOW_KEYWORDS)
    assert len(result) > 0

def test_extract_keywords_no_match_returns_empty():
    result = extract_keywords("notepad.exe", SHADOW_KEYWORDS)
    assert result == []

def test_extract_command_features_returns_dict():
    result = extract_command_features("vssadmin delete shadows /all")
    assert isinstance(result, dict)

def test_extract_command_features_shadow_count():
    result = extract_command_features("vssadmin delete shadows /all /quiet")
    assert result.get('shadow_keywords', 0) > 0

def test_extract_command_features_boot_count():
    result = extract_command_features("bcdedit /set {default} recoveryenabled No")
    assert result.get('boot_keywords', 0) > 0

def test_extract_command_features_safe_command_zero():
    result = extract_command_features("notepad.exe")
    total = sum([
        result.get('shadow_keywords', 0),
        result.get('boot_keywords', 0),
        result.get('service_kill_keywords', 0),
        result.get('ransom_note_keywords', 0),
    ])
    assert total == 0

def test_extract_command_features_has_all_keys():
    result = extract_command_features("test command")
    required_keys = [
        'shadow_keywords', 'boot_keywords', 'service_kill_keywords',
        'persistence_keywords', 'lateral_keywords', 'obfuscation_keywords',
        'credential_keywords', 'ransom_note_keywords'
    ]
    for key in required_keys:
        assert key in result, f"Missing key: {key}"

def test_calculate_risk_score_returns_int():
    features = {'ip_count': 1, 'url_count': 1, 'shadow_keywords': 3, 'boot_keywords': 0, 'service_kill_keywords': 0, 'persistence_keywords': 0, 'lateral_keywords': 0, 'obfuscation_keywords': 0, 'credential_keywords': 0, 'ransom_note_keywords': 0}
    score = calculate_risk_score(0.9, features)
    assert isinstance(score, int)

def test_calculate_risk_score_between_0_and_100():
    features = {'ip_count': 1, 'url_count': 1, 'shadow_keywords': 3, 'boot_keywords': 0, 'service_kill_keywords': 0, 'persistence_keywords': 0, 'lateral_keywords': 0, 'obfuscation_keywords': 0, 'credential_keywords': 0, 'ransom_note_keywords': 0}
    score = calculate_risk_score(0.9, features)
    assert 0 <= score <= 100

def test_calculate_risk_score_zero_inputs():
    features = {'ip_count': 0, 'url_count': 0, 'shadow_keywords': 0, 'boot_keywords': 0, 'service_kill_keywords': 0, 'persistence_keywords': 0, 'lateral_keywords': 0, 'obfuscation_keywords': 0, 'credential_keywords': 0, 'ransom_note_keywords': 0}
    score = calculate_risk_score(0.0, features)
    assert score == 0

def test_get_severity_high():
    assert get_severity(75) == "HIGH"

def test_get_severity_medium():
    assert get_severity(50) == "MEDIUM"

def test_get_severity_low():
    assert get_severity(20) == "LOW"

def test_get_severity_boundary_70_is_high():
    assert get_severity(70) == "HIGH"

def test_get_severity_boundary_40_is_medium():
    assert get_severity(40) == "MEDIUM"

def test_get_severity_boundary_39_is_low():
    assert get_severity(39) == "LOW"


# =============================================================================
# Tests for RansomwareDetectionAgent (Rule-based)
# =============================================================================

@pytest.fixture
def detection_agent():
    """Detection agent with no ML service (rule-based mode)."""
    agent = RansomwareDetectionAgent()
    # Mock the service property to return None to force rule-based mode
    agent._service = None
    agent.is_model_loaded = MagicMock(return_value=False)
    return agent


@pytest.fixture
def detection_agent_with_mock_ml():
    """Detection agent with mocked ML service."""
    agent = RansomwareDetectionAgent()
    mock_service = MagicMock()
    mock_service.is_model_loaded.return_value = True
    mock_service.predict.return_value = {
        'is_ransomware': True,
        'confidence': 0.92,
        'risk_score': 75,
        'severity': 'HIGH'
    }
    agent._service = mock_service
    return agent


def test_detection_agent_safe_command(detection_agent):
    """Safe command should not be detected as ransomware."""
    result = detection_agent.analyze("notepad.exe")
    assert result['is_ransomware'] == False
    assert result['confidence'] < 0.4
    assert result['severity'] == "LOW"


def test_detection_agent_ransomware_shadow_deletion(detection_agent):
    """Shadow deletion command should be flagged as ransomware."""
    result = detection_agent.analyze("vssadmin delete shadows /all /quiet")
    assert result['is_ransomware'] == True
    assert result['confidence'] > 0.0


def test_detection_agent_ransomware_boot_modification(detection_agent):
    """Boot configuration tampering should be flagged."""
    result = detection_agent.analyze("bcdedit /set {default} recoveryenabled No")
    assert result['is_ransomware'] == True


def test_detection_agent_returns_required_fields(detection_agent):
    """Output must contain all required contract fields."""
    result = detection_agent.analyze("notepad.exe")
    required = [
        'agent', 'status', 'command_id', 'is_ransomware',
        'confidence', 'risk_score', 'severity', 'model_used',
        'features', 'processing_time_ms', 'timestamp'
    ]
    for key in required:
        assert key in result, f"Missing key: {key}"


def test_detection_agent_uses_rule_based_when_no_model(detection_agent):
    """Without ML model, should use rule-based fallback."""
    result = detection_agent.analyze("vssadmin delete shadows /all")
    assert result['model_used'] == "rule_based"


def test_detection_agent_uses_ml_model_when_loaded(detection_agent_with_mock_ml):
    """With ML model loaded, should use ml_model."""
    result = detection_agent_with_mock_ml.analyze("vssadmin delete shadows /all")
    assert result['model_used'] == "ml_model"
    assert result['is_ransomware'] == True
    assert result['confidence'] >= 0.5


def test_detection_agent_status_is_success(detection_agent):
    result = detection_agent.analyze("notepad.exe")
    assert result['status'] == "success"


def test_detection_agent_severity_is_valid(detection_agent):
    result = detection_agent.analyze("vssadmin delete shadows /all")
    assert result['severity'] in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']


def test_detection_agent_confidence_between_0_and_1(detection_agent):
    result = detection_agent.analyze("vssadmin delete shadows /all")
    assert 0.0 <= result['confidence'] <= 1.0


def test_detection_agent_stats_increment(detection_agent):
    before = detection_agent.stats['total_analyzed']
    detection_agent.analyze("notepad.exe")
    assert detection_agent.stats['total_analyzed'] == before + 1


def test_detection_agent_batch_returns_list(detection_agent):
    commands = ["notepad.exe", "vssadmin delete shadows /all"]
    results = detection_agent.analyze_batch(commands)
    assert isinstance(results, list)
    assert len(results) == 2


def test_detection_agent_critical_threshold():
    agent = RansomwareDetectionAgent()
    assert agent._get_severity_from_confidence(0.95, True) == "CRITICAL"


def test_detection_agent_high_threshold():
    agent = RansomwareDetectionAgent()
    assert agent._get_severity_from_confidence(0.80, True) == "HIGH"


def test_detection_agent_not_ransomware_always_low():
    agent = RansomwareDetectionAgent()
    assert agent._get_severity_from_confidence(0.99, False) == "LOW"
