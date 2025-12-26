import pytest
from unittest.mock import MagicMock, patch

from saq.configuration.schema import RemediatorConfig
from saq.constants import F_TEST
from saq.remediation.collector import RemediationCollector
from saq.remediation.manager import RemediationManager
from saq.remediation.worker import RemediationWorker
from tests.saq.remediation.test_remediator import TestRemediator


@pytest.fixture
def manager():
    return RemediationManager()


@pytest.fixture
def test_worker():
    """Creates a test RemediationWorker for testing."""
    return RemediationWorker(TestRemediator(
        RemediatorConfig(
            name="test_worker",
            display_name="Test Worker",
            description="Test worker for unit tests",
            observable_type=F_TEST,
            python_module="test_module",
            python_class="TestRemediator"
        )))


@pytest.fixture
def another_test_worker():
    """Creates another test RemediationWorker with a different name."""
    return RemediationWorker(TestRemediator(
        RemediatorConfig(
            name="another_worker",
            display_name="Another Worker",
            description="Another test worker for unit tests",
            observable_type=F_TEST,
            python_module="test_module",
            python_class="TestRemediator"
        )))


@pytest.mark.unit
def test_remediation_manager(manager):
    assert not manager.workers
    assert isinstance(manager.collector, RemediationCollector)


@pytest.mark.unit
def test_add_worker(manager, test_worker):
    """Test adding a worker to the manager."""
    manager.add_worker(test_worker)

    # verify worker was added
    assert "test_worker" in manager.workers
    assert manager.workers["test_worker"] == test_worker

    # verify collector was registered
    assert "test_worker" in manager.collector.listeners


@pytest.mark.unit
def test_add_worker_duplicate_name(manager, test_worker):
    """Test that adding a worker with a duplicate name raises ValueError."""
    manager.add_worker(test_worker)

    # create another worker with the same name
    duplicate_worker = RemediationWorker(TestRemediator(
        RemediatorConfig(
            name="test_worker",  # same name
            display_name="Test Worker",
            description="Test worker for unit tests",
            observable_type=F_TEST,
            python_module="test_module",
            python_class="TestRemediator"
        )))

    # should raise ValueError
    with pytest.raises(ValueError, match="worker test_worker already exists"):
        manager.add_worker(duplicate_worker)


@pytest.mark.unit
def test_add_multiple_workers(manager, test_worker, another_test_worker):
    """Test adding multiple workers with different names."""
    manager.add_worker(test_worker)
    manager.add_worker(another_test_worker)

    # verify both workers were added
    assert len(manager.workers) == 2
    assert "test_worker" in manager.workers
    assert "another_worker" in manager.workers
    assert manager.workers["test_worker"] == test_worker
    assert manager.workers["another_worker"] == another_test_worker


@pytest.mark.unit
@patch("saq.remediation.manager.get_config")
def test_load_workers(mock_get_config, manager):
    """Test loading workers from configuration."""
    # create mock remediator configs
    config1 = RemediatorConfig(
        name="config_worker_1",
        display_name="Config Worker 1",
        description="First config worker for testing",
        observable_type=F_TEST,
        python_module="tests.saq.remediation.test_remediator",
        python_class="TestRemediator"
    )
    config2 = RemediatorConfig(
        name="config_worker_2",
        display_name="Config Worker 2",
        description="Second config worker for testing",
        observable_type=F_TEST,
        python_module="tests.saq.remediation.test_remediator",
        python_class="TestRemediator"
    )

    # mock the config to return two remediator configs
    mock_config = MagicMock()
    mock_config.remediators = [config1, config2]
    mock_get_config.return_value = mock_config

    # call load_workers
    manager.load_workers()

    # verify get_config was called
    mock_get_config.assert_called_once()

    # verify workers were added to manager
    assert len(manager.workers) == 2
    assert "config_worker_1" in manager.workers
    assert "config_worker_2" in manager.workers


@pytest.mark.unit
@patch("saq.remediation.manager.get_config")
def test_load_workers_empty_config(mock_get_config, manager):
    """Test loading workers when configuration has no remediators."""
    # mock the config to return empty list
    mock_config = MagicMock()
    mock_config.remediators = []
    mock_get_config.return_value = mock_config

    # call load_workers
    manager.load_workers()

    # verify get_config was called
    mock_get_config.assert_called_once()

    # verify no workers were added
    assert len(manager.workers) == 0