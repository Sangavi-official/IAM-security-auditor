"""
Sanity tests for privesc_detector. Run with:  pytest tests/
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cloudsplaining.scan.policy_document import PolicyDocument
from privesc_detector import find_passrole_blind_spots


def _blind_spots_for(policy_document: dict) -> list:
    pd = PolicyDocument(policy_document)
    flagged = {f["type"] for f in pd.allows_privilege_escalation}
    return find_passrole_blind_spots(policy_document, flagged)


def test_fully_unrestricted_passrole_is_not_a_blind_spot():
    """Cloudsplaining already catches literal '*' -- should NOT be reported as a blind spot."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"},
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
        ],
    }
    assert _blind_spots_for(policy) == []


def test_account_wide_role_wildcard_is_a_blind_spot():
    """role/* still means 'any role' -- Cloudsplaining misses this, our detector should not."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"},
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::123456789012:role/*"},
        ],
    }
    findings = _blind_spots_for(policy)
    assert len(findings) == 1
    assert findings[0]["method"] == "CreateEC2WithExistingIP"


def test_genuinely_scoped_passrole_is_not_flagged():
    """A single named role is real least-privilege -- must not false-positive."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"},
            {"Effect": "Allow", "Action": "iam:PassRole",
             "Resource": "arn:aws:iam::123456789012:role/only-this-role"},
        ],
    }
    assert _blind_spots_for(policy) == []


def test_prefix_scoped_passrole_is_not_flagged():
    """Prefix restriction (role/prod-*) is real scoping, not a bare wildcard -- must not flag."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"},
            {"Effect": "Allow", "Action": "iam:PassRole",
             "Resource": "arn:aws:iam::123456789012:role/prod-*"},
        ],
    }
    assert _blind_spots_for(policy) == []


def test_no_passrole_at_all_means_no_blind_spots():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"},
        ],
    }
    assert _blind_spots_for(policy) == []


if __name__ == "__main__":
    import subprocess
    subprocess.run([sys.executable, "-m", "pytest", __file__, "-v"])
