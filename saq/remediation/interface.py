from typing import Protocol

from saq.remediation.types import RemediationWorkItem

class RemediationListener(Protocol):
    def handle_remediation_request(self, remediation: RemediationWorkItem):
        ...