import pytest

from saq.remediation.service import RemediationService

@pytest.mark.unit
def test_remediation_service():
    """Test the remediation service."""
    remediation_service = RemediationService()