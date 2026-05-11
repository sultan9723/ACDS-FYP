# ACDS Test Cases Documentation

## Overview
This directory contains comprehensive test cases for all ACDS modules as per documentation requirements.

## Test Coverage
1. Admin Authentication
2. Data Ingestion
3. Phishing Detection
4. Ransomware Detection
5. Malware Detection
6. Credential Stuffing Detection
7. Automated Response
8. Dashboard Visualization
9. AI Report Generation
10. Analyst Feedback

## Test Execution
Each module has:
- Unit tests (individual function testing)
- Integration tests (end-to-end workflow testing)
- Performance tests (load and stress testing)

## Running Tests
```bash
# Run all tests
pytest test_cases/

# Run specific module
pytest test_cases/test_admin_authentication.py

# Run with coverage
pytest --cov=backend test_cases/
```

## Test Report Format
Each test case includes:
- Test ID
- Test Name
- Objective
- Preconditions
- Test Steps
- Expected Result
- Actual Result
- Status (Pass/Fail)
- Priority (High/Medium/Low)
