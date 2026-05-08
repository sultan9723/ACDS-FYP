"""
Explainability Agent
====================
Agent responsible for generating explanations and evidence for phishing detections.
Extracts IOCs, provides keyword analysis, and creates human-readable explanations.

Standard Output Contract:
{
    "agent": "explainability",
    "status": "success" | "error",
    "email_id": str,
    "iocs": {
        "urls": [str],
        "domains": [str],
        "emails": [str],
        "keywords": [str]
    },
    "keyword_analysis": {
        "urgency": [str],
        "threats": [str],
        "actions": [str],
        "rewards": [str],
        "financial": [str]
    },
    "feature_scores": {
        "url_score": int,
        "keyword_score": int,
        "html_score": int,
        "total": int
    },
    "explanation": str,
    "evidence": [str],
    "timestamp": ISO8601 str,
    "error": str | null
}

Version: 2.0.0
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field

# Import from project structure with fallbacks
try:
    from ml.preprocess import (
        extract_urls, extract_domains, extract_email_addresses,
        extract_email_features, extract_keywords,
        URGENCY_KEYWORDS, THREAT_KEYWORDS, ACTION_KEYWORDS,
        REWARD_KEYWORDS, FINANCIAL_KEYWORDS
    )
    from core.logger import get_logger
except ImportError:
    try:
        from backend.ml.preprocess import (
            extract_urls, extract_domains, extract_email_addresses,
            extract_email_features, extract_keywords,
            URGENCY_KEYWORDS, THREAT_KEYWORDS, ACTION_KEYWORDS,
            REWARD_KEYWORDS, FINANCIAL_KEYWORDS
        )
        from backend.core.logger import get_logger
    except ImportError:
        try:
            from ..ml.preprocess import (
                extract_urls, extract_domains, extract_email_addresses,
                extract_email_features, extract_keywords,
                URGENCY_KEYWORDS, THREAT_KEYWORDS, ACTION_KEYWORDS,
                REWARD_KEYWORDS, FINANCIAL_KEYWORDS
            )
            from ..core.logger import get_logger
        except ImportError:
            # Development fallbacks
            import re
            logging.basicConfig(level=logging.INFO)
            
            def get_logger(name):
                return logging.getLogger(name)
            
            URGENCY_KEYWORDS = ['urgent', 'immediately', 'asap', 'expire']
            THREAT_KEYWORDS = ['suspended', 'terminated', 'blocked', 'compromised']
            ACTION_KEYWORDS = ['verify', 'confirm', 'click here', 'login']
            REWARD_KEYWORDS = ['winner', 'prize', 'congratulations', 'free']
            FINANCIAL_KEYWORDS = ['bank', 'password', 'credit card', 'account']
            
            def extract_urls(text):
                return list(set(re.findall(r'https?://[^\s<>"\'{}|\\^`\[\]]+', text or '')))
            
            def extract_domains(text):
                urls = extract_urls(text)
                domains = set()
                for url in urls:
                    match = re.search(r'https?://([^/\s]+)', url)
                    if match:
                        domains.add(match.group(1).lower())
                return list(domains)
            
            def extract_email_addresses(text):
                return list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text or '')))
            
            def extract_keywords(text, keyword_list):
                text_lower = (text or '').lower()
                return [kw for kw in keyword_list if kw in text_lower]
            
            def extract_email_features(content):
                return {'url_count': 0, 'has_html': False}


@dataclass
class ExplainabilityResult:
    """Dataclass for explainability agent output."""
    agent: str = "explainability"
    status: str = "success"
    email_id: str = ""
    iocs: Dict[str, List[str]] = field(default_factory=dict)
    keyword_analysis: Dict[str, List[str]] = field(default_factory=dict)
    feature_scores: Dict[str, int] = field(default_factory=dict)
    explanation: str = ""
    evidence: List[str] = field(default_factory=list)
    timestamp: str = ""
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        if result['error'] is None:
            del result['error']
        return result


class ExplainabilityAgent:
    """
    Explainability Agent for phishing detection analysis.
    
    Provides detailed explanations of why an email was classified
    as phishing, including IOC extraction and keyword analysis.
    """
    
    AGENT_NAME = "explainability"
    VERSION = "2.0.0"
    
    def __init__(self):
        """Initialize the Explainability Agent."""
        self.logger = get_logger(__name__)
        self.stats = {
            'total_processed': 0,
            'iocs_extracted': 0,
            'errors': 0
        }
    
    def analyze(
        self, 
        email_content: str, 
        email_id: str,
        detection_result: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate explanations for a phishing detection.
        
        Args:
            email_content: Raw email text
            email_id: Email identifier (from detection agent)
            detection_result: Optional detection results to incorporate
            
        Returns:
            Standard explainability result dictionary
        """
        result = ExplainabilityResult(
            email_id=email_id,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        
        self.stats['total_processed'] += 1
        
        try:
            # Extract IOCs
            iocs = self._extract_iocs(email_content)
            result.iocs = iocs
            
            # Perform keyword analysis
            keyword_analysis = self._analyze_keywords(email_content)
            result.keyword_analysis = keyword_analysis
            
            # Calculate feature scores
            feature_scores = self._calculate_feature_scores(iocs, keyword_analysis, email_content)
            result.feature_scores = feature_scores
            
            # Generate evidence list
            evidence = self._generate_evidence(iocs, keyword_analysis)
            result.evidence = evidence
            
            # Generate human-readable explanation
            explanation = self._generate_explanation(
                iocs, keyword_analysis, feature_scores, detection_result
            )
            result.explanation = explanation
            
            # Update stats
            total_iocs = sum(len(v) for v in iocs.values())
            if total_iocs > 0:
                self.stats['iocs_extracted'] += total_iocs
            
            self.logger.info(f"Explainability [{email_id}]: {len(evidence)} evidence items found")
            
        except Exception as e:
            result.status = "error"
            result.error = str(e)
            self.stats['errors'] += 1
            self.logger.error(f"Explainability error for {email_id}: {e}")
        
        return result.to_dict()
    
    def _extract_iocs(self, content: str) -> Dict[str, List[str]]:
        """
        Extract Indicators of Compromise from email content.
        
        Args:
            content: Raw email content
            
        Returns:
            Dictionary of IOC types and values
        """
        return {
            'urls': extract_urls(content),
            'domains': extract_domains(content),
            'emails': extract_email_addresses(content),
            'keywords': self._get_all_suspicious_keywords(content)
        }
    
    def _analyze_keywords(self, content: str) -> Dict[str, List[str]]:
        """
        Categorized keyword analysis.
        
        Args:
            content: Raw email content
            
        Returns:
            Dictionary of keyword categories and matches
        """
        content_lower = content.lower() if content else ""
        
        return {
            'urgency': extract_keywords(content_lower, URGENCY_KEYWORDS),
            'threats': extract_keywords(content_lower, THREAT_KEYWORDS),
            'actions': extract_keywords(content_lower, ACTION_KEYWORDS),
            'rewards': extract_keywords(content_lower, REWARD_KEYWORDS),
            'financial': extract_keywords(content_lower, FINANCIAL_KEYWORDS)
        }
    
    def _get_all_suspicious_keywords(self, content: str) -> List[str]:
        """Get all suspicious keywords found in content."""
        content_lower = content.lower() if content else ""
        all_keywords = (
            URGENCY_KEYWORDS + THREAT_KEYWORDS + ACTION_KEYWORDS +
            REWARD_KEYWORDS + FINANCIAL_KEYWORDS
        )
        return list(set(kw for kw in all_keywords if kw in content_lower))
    
    def _calculate_feature_scores(
        self, 
        iocs: Dict[str, List[str]], 
        keyword_analysis: Dict[str, List[str]],
        content: str
    ) -> Dict[str, int]:
        """
        Calculate feature-based scores.
        
        Args:
            iocs: Extracted IOCs
            keyword_analysis: Keyword analysis results
            content: Raw email content
            
        Returns:
            Dictionary of feature scores
        """
        # URL score (0-20)
        url_score = min(len(iocs.get('urls', [])) * 5, 20)
        
        # Keyword score (0-40)
        keyword_count = sum(len(v) for v in keyword_analysis.values())
        keyword_score = min(keyword_count * 5, 40)
        
        # HTML score (0-10)
        has_html = '<' in content and '>' in content if content else False
        html_score = 10 if has_html else 0
        
        total = url_score + keyword_score + html_score
        
        return {
            'url_score': url_score,
            'keyword_score': keyword_score,
            'html_score': html_score,
            'total': total
        }
    
    def _generate_evidence(
        self, 
        iocs: Dict[str, List[str]], 
        keyword_analysis: Dict[str, List[str]]
    ) -> List[str]:
        """
        Generate list of evidence items.
        
        Args:
            iocs: Extracted IOCs
            keyword_analysis: Keyword analysis results
            
        Returns:
            List of evidence strings
        """
        evidence = []
        
        # URL evidence
        urls = iocs.get('urls', [])
        if urls:
            evidence.append(f"Found {len(urls)} URL(s): {', '.join(urls[:3])}")
        
        # Domain evidence
        domains = iocs.get('domains', [])
        if domains:
            evidence.append(f"External domains detected: {', '.join(domains[:3])}")
        
        # Urgency keywords
        urgency = keyword_analysis.get('urgency', [])
        if urgency:
            evidence.append(f"Urgency language: {', '.join(urgency[:3])}")
        
        # Threat keywords
        threats = keyword_analysis.get('threats', [])
        if threats:
            evidence.append(f"Threat indicators: {', '.join(threats[:3])}")
        
        # Action keywords
        actions = keyword_analysis.get('actions', [])
        if actions:
            evidence.append(f"Action requests: {', '.join(actions[:3])}")
        
        # Reward keywords
        rewards = keyword_analysis.get('rewards', [])
        if rewards:
            evidence.append(f"Reward/prize language: {', '.join(rewards[:3])}")
        
        # Financial keywords
        financial = keyword_analysis.get('financial', [])
        if financial:
            evidence.append(f"Financial/sensitive terms: {', '.join(financial[:3])}")
        
        return evidence
    
    def _generate_explanation(
        self,
        iocs: Dict[str, List[str]],
        keyword_analysis: Dict[str, List[str]],
        feature_scores: Dict[str, int],
        detection_result: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generate human-readable explanation.
        
        Args:
            iocs: Extracted IOCs
            keyword_analysis: Keyword analysis results
            feature_scores: Calculated feature scores
            detection_result: Optional detection results
            
        Returns:
            Explanation string
        """
        parts = []
        
        # Detection summary if available
        if detection_result:
            is_phishing = detection_result.get('is_phishing', False)
            confidence = detection_result.get('confidence', 0)
            severity = detection_result.get('severity', 'LOW')
            
            if is_phishing:
                parts.append(
                    f"This email has been classified as PHISHING with {confidence:.1%} confidence "
                    f"(Severity: {severity})."
                )
            else:
                parts.append(
                    f"This email appears to be LEGITIMATE with {1-confidence:.1%} confidence."
                )
        
        # IOC summary
        url_count = len(iocs.get('urls', []))
        domain_count = len(iocs.get('domains', []))
        
        if url_count > 0:
            parts.append(f"The email contains {url_count} URL(s) pointing to {domain_count} domain(s).")
        
        # Keyword summary
        urgency_count = len(keyword_analysis.get('urgency', []))
        threat_count = len(keyword_analysis.get('threats', []))
        action_count = len(keyword_analysis.get('actions', []))
        
        indicators = []
        if urgency_count > 0:
            indicators.append(f"urgency language ({urgency_count})")
        if threat_count > 0:
            indicators.append(f"threatening language ({threat_count})")
        if action_count > 0:
            indicators.append(f"action requests ({action_count})")
        
        if indicators:
            parts.append(f"Detected phishing indicators: {', '.join(indicators)}.")
        
        # Risk assessment
        total_score = feature_scores.get('total', 0)
        if total_score >= 50:
            parts.append("HIGH RISK: Multiple strong phishing indicators present.")
        elif total_score >= 25:
            parts.append("MEDIUM RISK: Some phishing indicators detected.")
        elif total_score > 0:
            parts.append("LOW RISK: Minor indicators present, but likely safe.")
        else:
            parts.append("NO RISK: No phishing indicators detected.")
        
        return " ".join(parts)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get agent statistics."""
        return {
            'agent': self.AGENT_NAME,
            'version': self.VERSION,
            **self.stats
        }


# Factory function
def create_explainability_agent() -> ExplainabilityAgent:
    """Create an ExplainabilityAgent instance."""
    return ExplainabilityAgent()


# Module-level singleton
_agent_instance: Optional[ExplainabilityAgent] = None


def get_explainability_agent() -> ExplainabilityAgent:
    """Get or create explainability agent singleton."""
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = ExplainabilityAgent()
    return _agent_instance


# Direct execution for testing
if __name__ == "__main__":
    agent = ExplainabilityAgent()
    
    test_email = """
    URGENT: Your account has been suspended!
    
    Dear Customer,
    
    We noticed unusual activity in your bank account. Your account will be terminated 
    within 24 hours unless you verify your identity immediately.
    
    Click here to verify: http://suspicious-link.com/verify
    Enter your password and credit card to confirm.
    
    Congratulations! You've also won a $1000 prize!
    
    Best regards,
    Security Team
    """
    
    mock_detection = {
        'is_phishing': True,
        'confidence': 0.92,
        'severity': 'HIGH'
    }
    
    result = agent.analyze(test_email, "test_email_001", mock_detection)
    
    print("Explainability Result:")
    print(f"  Status: {result['status']}")
    print(f"  Email ID: {result['email_id']}")
    print(f"\n  IOCs:")
    for key, values in result['iocs'].items():
        print(f"    {key}: {values}")
    print(f"\n  Keyword Analysis:")
    for key, values in result['keyword_analysis'].items():
        print(f"    {key}: {values}")
    print(f"\n  Feature Scores: {result['feature_scores']}")
    print(f"\n  Evidence:")
    for ev in result['evidence']:
        print(f"    - {ev}")
    print(f"\n  Explanation: {result['explanation']}")
