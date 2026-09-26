import sys
from pathlib import Path

# Allow imports from the project root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from abac_engine import ABACEngine


engine = ABACEngine()


def test_researcher_confidential_read():
    request = {
        "request_id": "TEST001",
        "user_id": "TEST_USER",
        "role": "researcher",
        "department": "AI",
        "clearance": "CONFIDENTIAL",
        "resource": "gait_analysis_dataset",
        "classification": "CONFIDENTIAL",
        "action": "READ",
        "purpose": "research",
        "location": "campus"
    }

    result = engine.evaluate(request)

    assert result["decision"] == "ALLOW"
    assert result["policy_id"] == "P001"


def test_student_confidential_access_denied():
    request = {
        "request_id": "TEST002",
        "user_id": "TEST_STUDENT",
        "role": "student",
        "department": "AI",
        "clearance": "PUBLIC",
        "resource": "patient_gait_dataset",
        "classification": "CONFIDENTIAL",
        "action": "READ",
        "purpose": "academic",
        "location": "campus"
    }

    result = engine.evaluate(request)

    assert result["decision"] == "DENY"
    assert result["policy_id"] == "P100"


def test_default_deny():
    request = {
        "request_id": "TEST003",
        "user_id": "UNKNOWN",
        "role": "guest",
        "department": "Unknown",
        "clearance": "PUBLIC",
        "resource": "internal_dataset",
        "classification": "INTERNAL",
        "action": "READ",
        "purpose": "unknown",
        "location": "remote"
    }

    result = engine.evaluate(request)

    assert result["decision"] == "DENY"
    assert result["policy_id"] is None


def test_student_public_dataset_allowed():
    request = {
        "request_id": "TEST004",
        "user_id": "TEST_STUDENT",
        "role": "student",
        "department": "AI",
        "clearance": "PUBLIC",
        "resource": "public_ai_dataset",
        "classification": "PUBLIC",
        "action": "READ",
        "purpose": "academic",
        "location": "campus"
    }

    result = engine.evaluate(request)

    assert result["decision"] == "ALLOW"
    assert result["policy_id"] == "P002"


def test_data_scientist_internal_access():
    request = {
        "request_id": "TEST005",
        "user_id": "TEST_DS",
        "role": "data_scientist",
        "department": "AI",
        "clearance": "INTERNAL",
        "resource": "model_training_dataset",
        "classification": "INTERNAL",
        "action": "READ",
        "purpose": "model_development",
        "location": "lab"
    }

    result = engine.evaluate(request)

    assert result["decision"] == "ALLOW"
    assert result["policy_id"] == "P004"


def test_researcher_write_access():
    request = {
        "request_id": "TEST006",
        "user_id": "TEST_RESEARCHER",
        "role": "researcher",
        "department": "AI",
        "clearance": "CONFIDENTIAL",
        "resource": "research_dataset",
        "classification": "INTERNAL",
        "action": "WRITE",
        "purpose": "research",
        "location": "lab"
    }

    result = engine.evaluate(request)

    assert result["decision"] == "ALLOW"
    assert result["policy_id"] == "P006"