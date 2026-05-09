"""
Ransomware Explainability Agent
================================
Extracts IOCs (Indicators of Compromise) from detected ransomware commands
and generates human-readable explanations.

Standard Output Contract:
{
    "agent": "ransomware_explainability",
    "status": "success" | "error",
    "command_id": str,
    "iocs": {
        "ips": [str],
        "urls": [str],
        "file_paths": [str],
        "registry_keys": [str],
        "suspicious_keywords": [str]
    },
    "behavior_categories": [str],
    "explanation": str,
    "evidence": [str],
    "attack_stage": str,
    "mitre_tactics": [str],
    "processing_time_ms": int,
    "timestamp": ISO8601 str,
    "error": str | null
}

Version: 1.0.0
"""

import time
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field

try:
    from ml.ransomware_preprocess import (
        extract_ips, extract_urls, extract_file_paths,
        extract_registry_keys, extract_keywords,
        SHADOW_KEYWORDS, BOOT_KEYWORDS, SERVICE_KILL_KEYWORDS,
        PERSISTENCE_KEYWORDS, LATERAL_KEYWORDS,
        OBFUSCATION_KEYWORDS, CREDENTIAL_KEYWORDS, RANSOM_NOTE_KEYWORDS
    )
    from core.logger import get_logger
except ImportError:
    try:
        from backend.ml.ransomware_preprocess import (
            extract_ips, extract_urls, extract_file_paths,
            extract_registry_keys, extract_keywords,
            SHADOW_KEYWORDS, BOOT_KEYWORDS, SERVICE_KILL_KEYWORDS,
            PERSISTENCE_KEYWORDS, LATERAL_KEYWORDS,
            OBFUSCATION_KEYWORDS, CREDENTIAL_KEYWORDS, RANSOM_NOTE_KEYWORDS
        )
        from backend.core.logger import get_logger
    except ImportError:
        logging.basicConfig(level=logging.INFO)

        def get_logger(name):
            return logging.getLogger(name)

        SHADOW_KEYWORDS = []
        BOOT_KEYWORDS = []
        SERVICE_KILL_KEYWORDS = []
        PERSISTENCE_KEYWORDS = []
        LATERAL_KEYWORDS = []
        OBFUSCATION_KEYWORDS = []
        CREDENTIAL_KEYWORDS = []
        RANSOM_NOTE_KEYWORDS = []

        def extract_ips(cmd): return []
        def extract_urls(cmd): return []
        def extract_file_paths(cmd): return []
        def extract_registry_keys(cmd): return []
        def extract_keywords(cmd, keywords): return []


# MITRE ATT&CK mapping for ransomware behaviors
MITRE_TACTIC_MAP = {
    'shadow_deletion':      ('T1490', 'Inhibit System Recovery'),
    'boot_modification':    ('T1542', 'Pre-OS Boot'),
    'service_kill':         ('T1489', 'Service Stop'),
    'persistence':          ('T1547', 'Boot or Logon Autostart Execution'),
    'lateral_movement':     ('T1021', 'Remote Services'),
    'obfuscation':          ('T1027', 'Obfuscated Files or Information'),
    'credential_theft':     ('T1003', 'OS Credential Dumping'),
    'ransom_note':          ('T1486', 'Data Encrypted for Impact'),
}

# Human-readable behavior descriptions
BEHAVIOR_DESCRIPTIONS = {
    'shadow_deletion':   'Shadow copy / backup deletion detected — prevents system recovery',
    'boot_modification': 'Boot configuration modification — disables recovery mode',
    'service_kill':      'Security/backup service termination — disables defenses',
    'persistence':       'Persistence mechanism established — survives reboots',
    'lateral_movement':  'Lateral movement behavior — spreads across network',
    'obfuscation':       'Command obfuscation detected — evades detection',
    'credential_theft':  'Credential harvesting behavior — enables privilege escalation',
    'ransom_note':       'Ransom note / encryption behavior — direct ransomware indicator',
}


@dataclass
class ExplainabilityResult:
    """Dataclass for ransomware explainability output."""
    agent: str = "ransomware_explainability"
    status: str = "success"
    command_id: str = ""
    iocs: Dict[str, Any] = field(default_factory=dict)
    behavior_categories: List[str] = field(default_factory=list)
    explanation: str = ""
    evidence: List[str] = field(default_factory=list)
    attack_stage: str = "unknown"
    mitre_tactics: List[str] = field(default_factory=list)
    processing_time_ms: int = 0
    timestamp: str = ""
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        if result['error'] is None:
            del result['error']
        return result


class RansomwareExplainabilityAgent:
    """
    Ransomware Explainability Agent.

    Extracts IOCs, identifies behavior categories, maps to MITRE ATT&CK
    tactics, and generates human-readable explanations for detected threats.
    """

    AGENT_NAME = "ransomware_explainability"
    VERSION = "1.0.0"

    def __init__(self):
        """Initialize the Ransomware Explainability Agent."""
        self.logger = get_logger(__name__)

        self.stats = {
            'total_analyzed': 0,
            'iocs_extracted': 0,
            'errors': 0
        }

    def analyze(
        self,
        command: str,
        command_id: str,
        detection_result: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Analyze a command and generate explainability output.

        Args:
            command: The command string to analyze
            command_id: Command identifier
            detection_result: Optional detection result from detection agent

        Returns:
            Explainability result dictionary
        """
        start_time = time.time()

        result = ExplainabilityResult(
            command_id=command_id,
            timestamp=datetime.now(timezone.utc).isoformat()
        )

        self.stats['total_analyzed'] += 1

        try:
            # === Extract IOCs ===
            ips = extract_ips(command)
            urls = extract_urls(command)
            file_paths = extract_file_paths(command)
            registry_keys = extract_registry_keys(command)

            # Extract keyword matches per category
            shadow_hits = extract_keywords(command, SHADOW_KEYWORDS)
            boot_hits = extract_keywords(command, BOOT_KEYWORDS)
            service_hits = extract_keywords(command, SERVICE_KILL_KEYWORDS)
            persistence_hits = extract_keywords(command, PERSISTENCE_KEYWORDS)
            lateral_hits = extract_keywords(command, LATERAL_KEYWORDS)
            obfuscation_hits = extract_keywords(command, OBFUSCATION_KEYWORDS)
            credential_hits = extract_keywords(command, CREDENTIAL_KEYWORDS)
            ransom_hits = extract_keywords(command, RANSOM_NOTE_KEYWORDS)

            all_suspicious = list(set(
                shadow_hits + boot_hits + service_hits + persistence_hits +
                lateral_hits + obfuscation_hits + credential_hits + ransom_hits
            ))

            result.iocs = {
                'ips': ips,
                'urls': urls,
                'file_paths': file_paths,
                'registry_keys': registry_keys,
                'suspicious_keywords': all_suspicious
            }

            total_iocs = len(ips) + len(urls) + len(file_paths) + len(registry_keys)
            self.stats['iocs_extracted'] += total_iocs

            # === Identify Behavior Categories ===
            categories = []
            if shadow_hits:
                categories.append('shadow_deletion')
            if boot_hits:
                categories.append('boot_modification')
            if service_hits:
                categories.append('service_kill')
            if persistence_hits:
                categories.append('persistence')
            if lateral_hits:
                categories.append('lateral_movement')
            if obfuscation_hits:
                categories.append('obfuscation')
            if credential_hits:
                categories.append('credential_theft')
            if ransom_hits:
                categories.append('ransom_note')

            result.behavior_categories = categories

            # === Map to MITRE ATT&CK ===
            mitre_tactics = []
            for cat in categories:
                if cat in MITRE_TACTIC_MAP:
                    tactic_id, tactic_name = MITRE_TACTIC_MAP[cat]
                    mitre_tactics.append(f"{tactic_id}: {tactic_name}")
            result.mitre_tactics = mitre_tactics

            # === Determine Attack Stage ===
            result.attack_stage = self._determine_attack_stage(categories)

            # === Build Evidence List ===
            evidence = []
            for cat in categories:
                desc = BEHAVIOR_DESCRIPTIONS.get(cat, cat)
                evidence.append(desc)
            if ips:
                evidence.append(f"Suspicious IPs found: {', '.join(ips)}")
            if urls:
                evidence.append(f"Suspicious URLs found: {', '.join(urls)}")
            if registry_keys:
                evidence.append(f"Registry keys accessed: {', '.join(registry_keys[:3])}")
            result.evidence = evidence

            # === Generate Human-Readable Explanation ===
            result.explanation = self._generate_explanation(
                command, categories, result.attack_stage, detection_result
            )

        except Exception as e:
            result.status = "error"
            result.error = str(e)
            self.stats['errors'] += 1
            self.logger.error(f"Explainability error for {command_id}: {e}")

        processing_time = int((time.time() - start_time) * 1000)
        result.processing_time_ms = processing_time

        self.logger.info(
            f"Explainability [{command_id}]: categories={result.behavior_categories}, "
            f"stage={result.attack_stage}, time={processing_time}ms"
        )

        return result.to_dict()

    def _determine_attack_stage(self, categories: List[str]) -> str:
        """
        Determine the ransomware attack stage based on behavior categories.

        Ransomware Kill Chain:
        1. initial_access → 2. execution → 3. defense_evasion
        4. credential_access → 5. lateral_movement → 6. impact
        """
        if 'ransom_note' in categories or 'shadow_deletion' in categories:
            return "impact"  # Final stage — encryption / ransom demand
        elif 'lateral_movement' in categories:
            return "lateral_movement"
        elif 'credential_theft' in categories:
            return "credential_access"
        elif 'obfuscation' in categories or 'service_kill' in categories:
            return "defense_evasion"
        elif 'persistence' in categories:
            return "persistence"
        elif 'boot_modification' in categories:
            return "execution"
        else:
            return "reconnaissance"

    def _generate_explanation(
        self,
        command: str,
        categories: List[str],
        attack_stage: str,
        detection_result: Optional[Dict[str, Any]]
    ) -> str:
        """Generate a human-readable explanation of the threat."""
        if not categories:
            return "No specific ransomware behavior patterns detected in this command."

        # Opening line
        confidence = detection_result.get('confidence', 0) if detection_result else 0
        severity = detection_result.get('severity', 'UNKNOWN') if detection_result else 'UNKNOWN'

        explanation_parts = [
            f"This command exhibits {len(categories)} ransomware behavior pattern(s) "
            f"with {confidence:.0%} confidence (Severity: {severity})."
        ]

        # Behavior descriptions
        explanation_parts.append("Detected behaviors:")
        for cat in categories:
            desc = BEHAVIOR_DESCRIPTIONS.get(cat, cat)
            explanation_parts.append(f"  • {desc}")

        # Attack stage context
        stage_context = {
            'impact': "This is a late-stage ransomware action. Immediate isolation recommended.",
            'lateral_movement': "The attacker is spreading across the network. Contain now.",
            'credential_access': "Credentials may be compromised. Reset passwords immediately.",
            'defense_evasion': "The attacker is disabling defenses. Alert SOC immediately.",
            'persistence': "A persistence mechanism is being established.",
            'execution': "Malicious code execution is in progress.",
            'reconnaissance': "Early-stage probing behavior detected.",
        }
        explanation_parts.append(
            f"\nAttack Stage ({attack_stage}): {stage_context.get(attack_stage, '')}"
        )

        return " ".join(explanation_parts[:1]) + "\n" + "\n".join(explanation_parts[1:])

    def get_stats(self) -> Dict[str, Any]:
        """Get explainability agent statistics."""
        return {
            'agent': self.AGENT_NAME,
            'version': self.VERSION,
            **self.stats
        }


# Module-level singleton
_agent_instance: Optional[RansomwareExplainabilityAgent] = None


def get_ransomware_explainability_agent() -> RansomwareExplainabilityAgent:
    """Get or create ransomware explainability agent singleton."""
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = RansomwareExplainabilityAgent()
    return _agent_instance


if __name__ == "__main__":
    agent = RansomwareExplainabilityAgent()

    test_command = "vssadmin delete shadows /all /quiet && bcdedit /set {default} recoveryenabled No"

    result = agent.analyze(test_command, "cmd_test_001")

    print("=" * 60)
    print("EXPLAINABILITY RESULT")
    print("=" * 60)
    print(f"Behavior Categories : {result['behavior_categories']}")
    print(f"Attack Stage        : {result['attack_stage']}")
    print(f"MITRE Tactics       : {result['mitre_tactics']}")
    print(f"\nExplanation:\n{result['explanation']}")
    print(f"\nEvidence:")
    for e in result['evidence']:
        print(f"  - {e}")
