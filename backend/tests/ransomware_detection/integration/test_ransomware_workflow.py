import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from backend.agents.ransomware_detection_agent import RansomwareDetectionAgent
from backend.agents.ransomware_explainability_agent import RansomwareExplainabilityAgent
from backend.agents.ransomware_response_agent import RansomwareResponseAgent
from backend.agents.ransomware_orchestrator_agent import RansomwareOrchestratorAgent


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_detection_agent():
    """Mock for RansomwareDetectionAgent."""
    agent = MagicMock(spec=RansomwareDetectionAgent)
    agent.analyze.return_value = {
        'agent': 'ransomware_detection',
        'status': 'success',
        'command_id': 'cmd_test_001',
        'is_ransomware': True,
        'confidence': 0.92,
        'risk_score': 75,
        'severity': 'HIGH',
        'model_used': 'ml_model',
        'features': {'shadow_keywords': 2, 'boot_keywords': 0},
        'processing_time_ms': 100,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    return agent


@pytest.fixture
def mock_explainability_agent():
    """Mock for RansomwareExplainabilityAgent."""
    agent = MagicMock(spec=RansomwareExplainabilityAgent)
    agent.analyze.return_value = {
        'agent': 'ransomware_explainability',
        'status': 'success',
        'command_id': 'cmd_test_001',
        'behavior_categories': ['shadow_deletion', 'service_kill'],
        'attack_stage': 'impact',
        'mitre_tactics': ['T1490: Inhibit System Recovery', 'T1489: Service Stop'],
        'iocs': {
            'ips': [],
            'urls': [],
            'file_paths': [],
            'registry_keys': [],
            'suspicious_keywords': ['vssadmin', 'shadow', 'delete']
        },
        'evidence': [
            'Shadow copy / backup deletion detected',
            'Security/backup service termination'
        ],
        'explanation': 'This command exhibits 2 ransomware behavior patterns with 92% confidence.',
        'processing_time_ms': 50,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    return agent


@pytest.fixture
def mock_response_agent():
    """Mock for RansomwareResponseAgent."""
    agent = MagicMock(spec=RansomwareResponseAgent)
    agent.generate_response.return_value = {
        'agent': 'ransomware_response',
        'status': 'success',
        'incident_id': 'RAN_TEST001',
        'command_id': 'cmd_test_001',
        'severity': 'HIGH',
        'actions_executed': [
            'Terminated malicious process',
            'File hash added to blocklist',
            'SOC team alerted'
        ],
        'response_summary': 'Automated response executed for HIGH severity threat.',
        'blocked_hashes': ['hash_RAN_TEST0'],
        'isolated_hosts': [],
        'processing_time_ms': 30,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    return agent


@pytest.fixture
def orchestrator():
    """Fresh orchestrator for each test."""
    return RansomwareOrchestratorAgent()


@pytest.fixture
def orchestrator_with_mocks(orchestrator, mock_detection_agent, mock_explainability_agent, mock_response_agent):
    """Orchestrator with all agents mocked."""
    orchestrator._detection_agent = mock_detection_agent
    orchestrator._explainability_agent = mock_explainability_agent
    orchestrator._response_agent = mock_response_agent
    orchestrator._alert_agent = MagicMock()
    return orchestrator


# =============================================================================
# Integration Test — Full Ransomware Workflow
# =============================================================================

def test_end_to_end_ransomware_workflow(
    orchestrator_with_mocks,
    mock_detection_agent,
    mock_explainability_agent,
    mock_response_agent
):
    """
    Tests the complete end-to-end workflow for handling a ransomware incident.
    Mirrors test_end_to_end_phishing_workflow pattern.
    """
    print(f"\n--- Starting E2E Workflow Test for Ransomware Detection ---")

    test_command = "vssadmin delete shadows /all /quiet"

    # Step 1 — Process command through full pipeline
    print("Step 1: Processing command through orchestrator pipeline...")
    result = orchestrator_with_mocks.process_command(test_command)

    assert result is not None
    assert result['status'] == 'success'
    assert result['incident_id'].startswith("RAN_")
    print(f"Incident {result['incident_id']} created successfully.")

    # Step 2 — Verify detection was called
    print("Step 2: Verifying Detection Agent was called...")
    mock_detection_agent.analyze.assert_called_once_with(
        test_command,
        result['command_id']
    )
    detection = result['pipeline_results']['detection']
    assert detection['is_ransomware'] == True
    assert detection['confidence'] == 0.92
    assert detection['severity'] == 'HIGH'
    print(f"Detection: is_ransomware={detection['is_ransomware']}, confidence={detection['confidence']}")

    # Step 3 — Verify explainability was called
    print("Step 3: Verifying Explainability Agent was called...")
    mock_explainability_agent.analyze.assert_called_once()
    explain = result['pipeline_results']['explainability']
    assert 'shadow_deletion' in explain['behavior_categories']
    assert explain['attack_stage'] == 'impact'
    assert len(explain['mitre_tactics']) > 0
    print(f"Behaviors: {explain['behavior_categories']}")
    print(f"Attack Stage: {explain['attack_stage']}")
    print(f"MITRE Tactics: {explain['mitre_tactics']}")

    # Step 4 — Verify response was triggered (ransomware detected)
    print("Step 4: Verifying Response Agent was called...")
    mock_response_agent.generate_response.assert_called_once()
    response = result['pipeline_results']['response']
    assert len(response['actions_executed']) > 0
    assert 'Terminated malicious process' in response['actions_executed']
    print(f"Response actions: {response['actions_executed']}")

    # Step 5 — Verify lifecycle state is reported
    print("Step 5: Verifying incident lifecycle state...")
    assert result['lifecycle_state'] == 'reported'
    print(f"Lifecycle state: {result['lifecycle_state']}")

    # Step 6 — Verify actions_taken log
    print("Step 6: Verifying actions taken log...")
    assert isinstance(result['actions_taken'], list)
    assert len(result['actions_taken']) > 0
    print(f"Actions taken: {result['actions_taken']}")

    # Step 7 — Verify stats updated
    print("Step 7: Verifying orchestrator stats updated...")
    assert orchestrator_with_mocks.stats['ransomware_incidents'] == 1
    assert orchestrator_with_mocks.stats['total_incidents'] == 1
    print(f"Stats: {orchestrator_with_mocks.get_stats()}")

    print("\n--- E2E Ransomware Workflow Test Complete ---")


def test_safe_command_workflow(orchestrator_with_mocks, mock_detection_agent):
    """
    Tests workflow for a safe (non-ransomware) command.
    Response agent should NOT be called.
    """
    print(f"\n--- Starting Safe Command Workflow Test ---")

    # Override mock to return safe result
    mock_detection_agent.analyze.return_value = {
        'agent': 'ransomware_detection',
        'status': 'success',
        'command_id': 'cmd_safe_001',
        'is_ransomware': False,
        'confidence': 0.05,
        'risk_score': 5,
        'severity': 'LOW',
        'model_used': 'ml_model',
        'features': {},
        'processing_time_ms': 10,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }

    result = orchestrator_with_mocks.process_command("notepad.exe")

    assert result['status'] == 'success'
    assert result['lifecycle_state'] == 'reported'

    # Response agent should NOT be called for safe commands
    orchestrator_with_mocks._response_agent.generate_response.assert_not_called()

    # Safe commands stat should increment
    assert orchestrator_with_mocks.stats['safe_commands'] == 1

    print(f"Safe command processed correctly. State: {result['lifecycle_state']}")
    print("\n--- Safe Command Workflow Test Complete ---")


def test_detection_agent_called_with_correct_args(orchestrator_with_mocks, mock_detection_agent):
    """Detection agent must be called with the command string."""
    test_command = "bcdedit /set {default} recoveryenabled No"
    orchestrator_with_mocks.process_command(test_command)
    # First argument to analyze() should be the command
    call_args = mock_detection_agent.analyze.call_args
    assert call_args[0][0] == test_command


def test_explainability_called_after_detection(orchestrator_with_mocks, mock_explainability_agent):
    """Explainability agent must be called after detection."""
    orchestrator_with_mocks.process_command("vssadmin delete shadows /all")
    mock_explainability_agent.analyze.assert_called_once()


def test_response_called_only_for_ransomware(orchestrator_with_mocks, mock_detection_agent, mock_response_agent):
    """Response agent should only be called when ransomware is detected."""
    # Safe command
    mock_detection_agent.analyze.return_value = {
        'agent': 'ransomware_detection',
        'status': 'success',
        'command_id': 'cmd_safe',
        'is_ransomware': False,
        'confidence': 0.02,
        'risk_score': 2,
        'severity': 'LOW',
        'model_used': 'ml_model',
        'features': {},
        'processing_time_ms': 5,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    orchestrator_with_mocks.process_command("explorer.exe")
    mock_response_agent.generate_response.assert_not_called()


def test_incident_id_format(orchestrator_with_mocks):
    """Incident ID must follow RAN_ prefix format."""
    result = orchestrator_with_mocks.process_command("vssadmin delete shadows /all")
    assert result['incident_id'].startswith("RAN_")
    assert len(result['incident_id']) > 4


def test_pipeline_results_contains_all_stages(orchestrator_with_mocks):
    """For ransomware detection, all 3 pipeline stages should be present."""
    result = orchestrator_with_mocks.process_command("vssadmin delete shadows /all")
    assert 'detection' in result['pipeline_results']
    assert 'explainability' in result['pipeline_results']
    assert 'response' in result['pipeline_results']


def test_orchestrator_stats_after_multiple_scans(orchestrator_with_mocks, mock_detection_agent):
    """Stats should correctly track multiple scans."""
    # 2 ransomware commands
    orchestrator_with_mocks.process_command("vssadmin delete shadows /all")
    orchestrator_with_mocks.process_command("bcdedit /set {default} recoveryenabled No")

    # 1 safe command
    mock_detection_agent.analyze.return_value = {
        'agent': 'ransomware_detection',
        'status': 'success',
        'command_id': 'cmd_safe',
        'is_ransomware': False,
        'confidence': 0.02,
        'risk_score': 2,
        'severity': 'LOW',
        'model_used': 'ml_model',
        'features': {},
        'processing_time_ms': 5,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    orchestrator_with_mocks.process_command("notepad.exe")

    assert orchestrator_with_mocks.stats['total_incidents'] == 3
    assert orchestrator_with_mocks.stats['ransomware_incidents'] == 2
    assert orchestrator_with_mocks.stats['safe_commands'] == 1


def test_get_stats_structure(orchestrator_with_mocks):
    """get_stats() should return complete stats structure."""
    stats = orchestrator_with_mocks.get_stats()
    assert stats['agent'] == 'ransomware_orchestrator'
    assert 'agents_available' in stats
    assert 'detection' in stats['agents_available']
    assert 'explainability' in stats['agents_available']
    assert 'response' in stats['agents_available']
