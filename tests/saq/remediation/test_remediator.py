import pytest

from saq.remediation.remediator import Remediator
from saq.remediation.types import RemediationWorkItem, RemediatorResult, RemediatorStatus

pytestmark = pytest.mark.no_collect

class TestRemediator(Remediator):
    def remove(self, target: RemediationWorkItem) -> RemediatorResult:
        return RemediatorResult(status=RemediatorStatus.SUCCESS, message="TestRemediator.remove", restore_key="restore_key")

    def restore(self, target: RemediationWorkItem) -> RemediatorResult:
        return RemediatorResult(status=RemediatorStatus.SUCCESS, message="TestRemediator.restore")

