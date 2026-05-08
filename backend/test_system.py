"""
Comprehensive System Test Script
=================================
Tests all components of the ACDS phishing detection system.
"""

import sys
import json
import time
from datetime import datetime

def print_header(title):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)

def print_result(test_name, passed, details=""):
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"  {status}: {test_name}")
    if details:
        print(f"         {details}")

def test_ml_model():
    """Test 1: ML Model Loading and Predictions"""
    print_header("TEST 1: ML MODEL LOADING & PREDICTIONS")
    
    try:
        from ml.phishing_service import PhishingDetectionService
        
        detector = PhishingDetectionService()
        
        # Check model loaded
        model_loaded = detector.model is not None
        print_result("Model loaded", model_loaded)
        
        # Check model info
        info_loaded = detector.model_info is not None
        print_result("Model info loaded", info_loaded)
        
        if detector.model_info:
            version = detector.model_info.get("model_version", "unknown")
            accuracy = detector.model_info.get("metrics", {}).get("accuracy", 0) * 100
            print(f"         Version: {version}, Accuracy: {accuracy:.2f}%")
        
        # Test predictions
        test_emails = [
            ("URGENT: Your account compromised! Click http://evil.com to verify", True),
            ("Hi team, meeting at 3pm tomorrow in Room B", False),
            ("Your PayPal account has been suspended. Verify now: http://paypa1-verify.com", True),
            ("Please review the attached quarterly report", False),
        ]
        
        all_correct = True
        print("\n  Prediction Tests:")
        for email, expected_phishing in test_emails:
            result = detector.predict(email)
            correct = result["is_phishing"] == expected_phishing
            if not correct:
                all_correct = False
            expected = "Phishing" if expected_phishing else "Safe"
            actual = "Phishing" if result["is_phishing"] else "Safe"
            status = "✅" if correct else "❌"
            print(f"    {status} Expected: {expected}, Got: {actual} ({result['confidence']*100:.1f}%)")
        
        print_result("All predictions correct", all_correct)
        
        return model_loaded and info_loaded and all_correct
        
    except Exception as e:
        print_result("ML Model Test", False, str(e))
        return False


def test_detection_agent():
    """Test 2: Detection Agent"""
    print_header("TEST 2: DETECTION AGENT")
    
    try:
        from agents.detection_agent import DetectionAgent
        
        agent = DetectionAgent()
        
        # Check initialization
        print_result("Agent initialized", True)
        print_result("Model loaded", agent.model is not None)
        
        # Test detection - method is 'analyze' not 'detect'
        test_email = "URGENT: Verify your PayPal account at http://paypa1.com/verify"
        result = agent.analyze(test_email)
        
        # Validate response structure
        required_fields = ["agent", "status", "email_id", "is_phishing", "confidence", 
                         "risk_score", "severity", "timestamp"]
        
        has_all_fields = all(field in result for field in required_fields)
        print_result("Response has required fields", has_all_fields)
        
        # Check detection result
        is_correct = result["is_phishing"] == True and result["confidence"] > 0.5
        print_result("Correctly detected phishing", is_correct, 
                    f"confidence={result['confidence']:.2f}, severity={result['severity']}")
        
        # Check model used (not fallback)
        model_used = result.get("model_used", False)
        print_result("Using trained model (not fallback)", model_used)
        
        return has_all_fields and is_correct and model_used
        
    except Exception as e:
        print_result("Detection Agent Test", False, str(e))
        import traceback
        traceback.print_exc()
        return False


def test_explainability_agent():
    """Test 3: Explainability Agent"""
    print_header("TEST 3: EXPLAINABILITY AGENT")
    
    try:
        from agents.explainability_agent import ExplainabilityAgent
        
        agent = ExplainabilityAgent()
        print_result("Agent initialized", True)
        
        # Test explainability - method is 'analyze' not 'explain'
        test_email = "Click here http://malicious.com to verify your account before it gets suspended!"
        detection_result = {
            "is_phishing": True,
            "confidence": 0.85,
            "severity": "HIGH"
        }
        
        result = agent.analyze(test_email, detection_result)
        
        # Validate response structure
        required_fields = ["agent", "status", "email_id", "iocs", "keyword_analysis",
                         "explanation", "evidence", "timestamp"]
        
        has_all_fields = all(field in result for field in required_fields)
        print_result("Response has required fields", has_all_fields)
        
        # Check IOC extraction
        iocs = result.get("iocs", {})
        found_url = len(iocs.get("urls", [])) > 0
        print_result("URLs extracted", found_url, f"Found: {iocs.get('urls', [])}")
        
        found_domain = len(iocs.get("domains", [])) > 0
        print_result("Domains extracted", found_domain, f"Found: {iocs.get('domains', [])}")
        
        found_keywords = len(iocs.get("keywords", [])) > 0
        print_result("Keywords extracted", found_keywords, f"Found: {iocs.get('keywords', [])}")
        
        # Check evidence generated
        has_evidence = len(result.get("evidence", [])) > 0
        print_result("Evidence generated", has_evidence, f"Count: {len(result.get('evidence', []))}")
        
        return has_all_fields and found_url and found_domain and found_keywords
        
    except Exception as e:
        print_result("Explainability Agent Test", False, str(e))
        import traceback
        traceback.print_exc()
        return False


def test_response_agent():
    """Test 4: Response Agent"""
    print_header("TEST 4: RESPONSE AGENT")
    
    try:
        from agents.response_agent import create_response_agent, ResponseAgent
        
        # Test factory function
        agent = create_response_agent()
        print_result("Agent created via factory", agent is not None)
        
        # Test direct instantiation
        agent2 = ResponseAgent()
        print_result("Agent direct instantiation", agent2 is not None)
        
        # Test response generation - respond takes a single threat_data dict
        threat_data = {
            "incident_id": "INC_TEST_001",
            "is_phishing": True,
            "confidence": 0.9,
            "severity": "HIGH",
            "email_id": "test_email_123",
            "iocs": {
                "urls": ["http://evil.com"],
                "domains": ["evil.com"],
                "emails": [],
                "keywords": ["urgent", "verify"]
            },
            "evidence": ["Found suspicious URL"]
        }
        
        result = agent.respond(threat_data)
        
        # Validate response structure (actual response agent output)
        required_fields = ["response_id", "timestamp", "threat_id", 
                         "actions_taken", "success"]
        
        has_all_fields = all(field in result for field in required_fields)
        print_result("Response has required fields", has_all_fields)
        
        # Check actions taken (may include notification actions)
        actions = result.get("actions_taken", [])
        has_actions = len(actions) > 0
        print_result("Actions taken", has_actions, f"Actions: {[a.get('action', a) for a in actions]}")
        
        # Check success flag
        is_success = result.get("success", False)
        print_result("Response successful", is_success)
        
        return has_all_fields and is_success
        
    except Exception as e:
        print_result("Response Agent Test", False, str(e))
        import traceback
        traceback.print_exc()
        return False


def test_orchestrator():
    """Test 5: Orchestrator Agent - Full Pipeline"""
    print_header("TEST 5: ORCHESTRATOR AGENT (FULL PIPELINE)")
    
    try:
        from agents.orchestrator_agent import OrchestratorAgent
        
        agent = OrchestratorAgent()
        print_result("Orchestrator initialized", True)
        
        # Test full pipeline with phishing email
        test_email = """
        URGENT SECURITY ALERT!
        
        Your bank account has been compromised. Immediate action required!
        
        Click here to verify your identity: http://secure-bank-verify.com/login
        
        If you don't verify within 24 hours, your account will be permanently suspended.
        
        Best regards,
        Security Team
        """
        
        start_time = time.time()
        result = agent.process_email(test_email)
        processing_time = (time.time() - start_time) * 1000
        
        # Validate response structure
        required_fields = ["agent", "status", "incident_id", "email_id", 
                         "lifecycle_state", "pipeline_results", "severity", 
                         "actions_taken", "timestamp"]
        
        has_all_fields = all(field in result for field in required_fields)
        print_result("Response has required fields", has_all_fields)
        
        # Check pipeline results
        pipeline = result.get("pipeline_results", {})
        has_detection = "detection" in pipeline
        has_explainability = "explainability" in pipeline
        has_response = "response" in pipeline
        
        print_result("Detection pipeline ran", has_detection)
        print_result("Explainability pipeline ran", has_explainability)
        print_result("Response pipeline ran", has_response)
        
        # Check detection result
        if has_detection:
            det = pipeline["detection"]
            is_phishing = det.get("is_phishing", False)
            confidence = det.get("confidence", 0)
            print_result("Correctly identified as phishing", is_phishing, 
                        f"confidence={confidence:.2f}")
        
        # Check lifecycle state
        lifecycle_state = result.get("lifecycle_state", "")
        completed = lifecycle_state in ["responded", "resolved", "reported"]
        print_result("Lifecycle completed", completed, f"state={lifecycle_state}")
        
        # Check incident ID format
        incident_id = result.get("incident_id", "")
        valid_id = incident_id.startswith("INC_")
        print_result("Valid incident ID generated", valid_id, f"id={incident_id}")
        
        # Check processing time
        print(f"\n  Processing time: {processing_time:.0f}ms")
        
        # Check actions taken
        actions = result.get("actions_taken", [])
        print(f"  Actions taken: {len(actions)}")
        for action in actions[:5]:  # Show first 5 actions
            print(f"    - {action}")
        
        return (has_all_fields and has_detection and has_explainability and 
                has_response and completed and valid_id)
        
    except Exception as e:
        print_result("Orchestrator Test", False, str(e))
        import traceback
        traceback.print_exc()
        return False


def test_safe_email_flow():
    """Test 6: Safe Email Flow"""
    print_header("TEST 6: SAFE EMAIL FLOW")
    
    try:
        from agents.orchestrator_agent import OrchestratorAgent
        
        agent = OrchestratorAgent()
        
        # Test with safe email
        safe_email = """
        Hi Team,
        
        Just a reminder that our weekly standup is tomorrow at 10am.
        Please review the sprint backlog before the meeting.
        
        Thanks,
        John
        """
        
        result = agent.process_email(safe_email)
        
        # Check detection result
        pipeline = result.get("pipeline_results", {})
        detection = pipeline.get("detection", {})
        
        is_safe = detection.get("is_phishing", True) == False
        print_result("Correctly identified as safe", is_safe,
                    f"confidence={detection.get('confidence', 0):.2f}")
        
        severity = detection.get("severity", "")
        low_severity = severity == "LOW"
        print_result("Low severity assigned", low_severity, f"severity={severity}")
        
        # For safe emails, response should be minimal
        response = pipeline.get("response", {})
        actions = response.get("actions_executed", [])
        print(f"  Actions for safe email: {actions}")
        
        return is_safe and low_severity
        
    except Exception as e:
        print_result("Safe Email Flow Test", False, str(e))
        import traceback
        traceback.print_exc()
        return False


def test_api_imports():
    """Test 7: API Route Imports"""
    print_header("TEST 7: API ROUTE IMPORTS")
    
    try:
        from api.routes.threats import router as threats_router
        print_result("Threats router imported", True)
        
        # Check routes exist
        routes = [r.path for r in threats_router.routes]
        print(f"  Available routes: {routes}")
        
        has_scan = any("/scan" in r for r in routes)
        print_result("/scan endpoint exists", has_scan)
        
        has_incidents = any("incidents" in r for r in routes)
        print_result("Incident management endpoints exist", has_incidents)
        
        return has_scan and has_incidents
        
    except Exception as e:
        print_result("API Import Test", False, str(e))
        import traceback
        traceback.print_exc()
        return False


def test_config():
    """Test 8: Configuration"""
    print_header("TEST 8: CONFIGURATION")
    
    try:
        from config.settings import (
            MODEL_PATH, MODEL_INFO_PATH, PHISHING_CONFIDENCE_THRESHOLD,
            THREAT_SEVERITY_LEVELS
        )
        import os
        
        # Check model paths
        model_exists = os.path.exists(MODEL_PATH)
        print_result("Model file exists", model_exists, f"path={MODEL_PATH}")
        
        info_exists = os.path.exists(MODEL_INFO_PATH)
        print_result("Model info file exists", info_exists, f"path={MODEL_INFO_PATH}")
        
        # Check threshold
        valid_threshold = 0 < PHISHING_CONFIDENCE_THRESHOLD < 1
        print_result("Valid confidence threshold", valid_threshold, 
                    f"threshold={PHISHING_CONFIDENCE_THRESHOLD}")
        
        # Check severity thresholds
        has_severity = all(k in THREAT_SEVERITY_LEVELS for k in ["LOW", "MEDIUM", "HIGH"])
        print_result("Severity thresholds configured", has_severity, 
                    f"thresholds={THREAT_SEVERITY_LEVELS}")
        
        return model_exists and info_exists and valid_threshold
        
    except Exception as e:
        print_result("Config Test", False, str(e))
        import traceback
        traceback.print_exc()
        return False


def run_all_tests():
    """Run all tests and print summary"""
    print("\n" + "=" * 60)
    print("  ACDS PHISHING DETECTION SYSTEM - COMPREHENSIVE TEST")
    print("=" * 60)
    print(f"  Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    tests = [
        ("ML Model", test_ml_model),
        ("Detection Agent", test_detection_agent),
        ("Explainability Agent", test_explainability_agent),
        ("Response Agent", test_response_agent),
        ("Orchestrator Pipeline", test_orchestrator),
        ("Safe Email Flow", test_safe_email_flow),
        ("API Routes", test_api_imports),
        ("Configuration", test_config),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            passed = test_func()
            results.append((name, passed))
        except Exception as e:
            results.append((name, False))
            print(f"  ERROR in {name}: {e}")
    
    # Print summary
    print_header("TEST SUMMARY")
    
    passed_count = sum(1 for _, p in results if p)
    total_count = len(results)
    
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {status}: {name}")
    
    print("\n" + "-" * 60)
    print(f"  Total: {passed_count}/{total_count} tests passed")
    
    if passed_count == total_count:
        print("\n  🎉 ALL TESTS PASSED! System is ready.")
    else:
        print(f"\n  ⚠️  {total_count - passed_count} test(s) failed. Please review.")
    
    print("=" * 60 + "\n")
    
    return passed_count == total_count


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
