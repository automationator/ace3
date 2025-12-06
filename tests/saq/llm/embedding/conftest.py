import pytest
from saq.configuration.config import get_service_config
from saq.constants import SERVICE_LLM_EMBEDDING

#
# when we run *these* tests, we *do* want to be vectorizing the root analysis objects
#

@pytest.fixture(autouse=True)
def mock_get_config(monkeypatch):
    monkeypatch.setattr(get_service_config(SERVICE_LLM_EMBEDDING), "enabled", True)
