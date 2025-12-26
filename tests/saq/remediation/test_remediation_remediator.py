import pytest

from saq.configuration.schema import RemediatorConfig
from saq.remediation.remediator import load_remediator_from_config
from saq.remediation.types import RemediationAction, RemediationWorkItem, RemediatorResult, RemediatorStatus
from tests.saq.remediation.test_remediator import TestRemediator

pytestmark = pytest.mark.unit


class TestRemediatorClass:
    """Tests for the Remediator class properties and methods."""

    def test_init(self):
        """Test Remediator initialization with config."""
        config = RemediatorConfig(
            name="test_remediator",
            display_name="Test Remediator",
            description="Test remediator for unit tests",
            observable_type="ipv4",
            python_module="tests.saq.remediation.test_remediator",
            python_class="TestRemediator",
        )

        remediator = TestRemediator(config)

        assert remediator.config == config

    def test_observable_type_property(self):
        """Test observable_type property returns config observable_type."""
        config = RemediatorConfig(
            name="test_remediator",
            display_name="Test Remediator",
            description="Test remediator for unit tests",
            observable_type="fqdn",
            python_module="tests.saq.remediation.test_remediator",
            python_class="TestRemediator",
        )

        remediator = TestRemediator(config)

        assert remediator.observable_type == "fqdn"
        assert remediator.observable_type == config.observable_type

    def test_name_property(self):
        """Test name property returns config name."""
        config = RemediatorConfig(
            name="my_custom_remediator",
            display_name="My Custom Remediator",
            description="Custom remediator for unit tests",
            observable_type="ipv4",
            python_module="tests.saq.remediation.test_remediator",
            python_class="TestRemediator",
        )

        remediator = TestRemediator(config)

        assert remediator.name == "my_custom_remediator"
        assert remediator.name == config.name

    def test_remediate_remove_action(self):
        """Test remediate method with REMOVE action calls remove method."""
        config = RemediatorConfig(
            name="test_remediator",
            display_name="Test Remediator",
            description="Test remediator for unit tests",
            observable_type="ipv4",
            python_module="tests.saq.remediation.test_remediator",
            python_class="TestRemediator",
        )

        remediator = TestRemediator(config)
        work_item = RemediationWorkItem(
            id=1,
            action=RemediationAction.REMOVE,
            name="test_remediator",
            type="ipv4",
            key="192.168.1.1",
        )

        result = remediator.remediate(work_item)

        assert isinstance(result, RemediatorResult)
        assert result.status == RemediatorStatus.SUCCESS
        assert result.message == "TestRemediator.remove"
        assert result.restore_key == "restore_key"

    def test_remediate_restore_action(self):
        """Test remediate method with RESTORE action calls restore method."""
        config = RemediatorConfig(
            name="test_remediator",
            display_name="Test Remediator",
            description="Test remediator for unit tests",
            observable_type="ipv4",
            python_module="tests.saq.remediation.test_remediator",
            python_class="TestRemediator",
        )

        remediator = TestRemediator(config)
        work_item = RemediationWorkItem(
            id=1,
            action=RemediationAction.RESTORE,
            name="test_remediator",
            type="ipv4",
            key="192.168.1.1",
            restore_key="restore_key",
        )

        result = remediator.remediate(work_item)

        assert isinstance(result, RemediatorResult)
        assert result.status == RemediatorStatus.SUCCESS
        assert result.message == "TestRemediator.restore"
        assert result.restore_key is None

    def test_remediate_invalid_action(self):
        """Test remediate method with invalid action raises ValueError."""
        config = RemediatorConfig(
            name="test_remediator",
            display_name="Test Remediator",
            description="Test remediator for unit tests",
            observable_type="ipv4",
            python_module="tests.saq.remediation.test_remediator",
            python_class="TestRemediator",
        )

        remediator = TestRemediator(config)
        # Create a work item with an invalid action by manually setting it
        work_item = RemediationWorkItem(
            id=1,
            action=RemediationAction.REMOVE,
            name="test_remediator",
            type="ipv4",
            key="192.168.1.1",
        )
        # Manually override the action to something invalid
        work_item.action = "invalid_action"

        with pytest.raises(ValueError, match="invalid action"):
            remediator.remediate(work_item)

    def test_remediate_with_different_observable_types(self):
        """Test remediate works with different observable types."""
        observable_types = ["ipv4", "fqdn", "url", "email_address"]

        for obs_type in observable_types:
            config = RemediatorConfig(
                name=f"test_remediator_{obs_type}",
                display_name=f"Test Remediator {obs_type}",
                description=f"Test remediator for {obs_type} observable type",
                observable_type=obs_type,
                python_module="tests.saq.remediation.test_remediator",
                python_class="TestRemediator",
            )

            remediator = TestRemediator(config)
            work_item = RemediationWorkItem(
                id=1,
                action=RemediationAction.REMOVE,
                name=f"test_remediator_{obs_type}",
                type=obs_type,
                key=f"test_{obs_type}_value",
            )

            result = remediator.remediate(work_item)

            assert result.status == RemediatorStatus.SUCCESS
            assert result.restore_key == "restore_key"


class TestLoadRemediatorFromConfig:
    """Tests for the load_remediator_from_config function."""

    def test_load_valid_remediator(self):
        """Test loading a valid remediator from config."""
        config = RemediatorConfig(
            name="test_remediator",
            display_name="Test Remediator",
            description="Test remediator for unit tests",
            observable_type="ipv4",
            python_module="tests.saq.remediation.test_remediator",
            python_class="TestRemediator",
        )

        remediator = load_remediator_from_config(config)

        assert remediator is not None
        assert remediator.name == "test_remediator"
        assert remediator.observable_type == "ipv4"
        assert remediator.config == config

    def test_load_remediator_with_custom_thread_count(self):
        """Test loading a remediator with custom thread count."""
        config = RemediatorConfig(
            name="test_remediator",
            display_name="Test Remediator",
            description="Test remediator for unit tests",
            observable_type="fqdn",
            python_module="tests.saq.remediation.test_remediator",
            python_class="TestRemediator",
            thread_count=5,
        )

        remediator = load_remediator_from_config(config)

        assert remediator is not None
        assert remediator.config.thread_count == 5

    def test_load_remediator_invalid_module(self):
        """Test loading a remediator with an invalid module raises ModuleNotFoundError."""
        config = RemediatorConfig(
            name="test_remediator",
            display_name="Test Remediator",
            description="Test remediator for unit tests",
            observable_type="ipv4",
            python_module="tests.saq.remediation.nonexistent_module",
            python_class="TestRemediator",
        )

        with pytest.raises(ModuleNotFoundError):
            load_remediator_from_config(config)

    def test_load_remediator_invalid_class(self):
        """Test loading a remediator with an invalid class raises AttributeError."""
        config = RemediatorConfig(
            name="test_remediator",
            display_name="Test Remediator",
            description="Test remediator for unit tests",
            observable_type="ipv4",
            python_module="tests.saq.remediation.test_remediator",
            python_class="NonexistentClass",
        )

        with pytest.raises(AttributeError):
            load_remediator_from_config(config)

    def test_load_remediator_different_observable_types(self):
        """Test loading remediators for different observable types."""
        observable_types = ["ipv4", "fqdn", "url", "email_address", "file"]

        for obs_type in observable_types:
            config = RemediatorConfig(
                name=f"test_remediator_{obs_type}",
                display_name=f"Test Remediator {obs_type}",
                description=f"Test remediator for {obs_type} observable type",
                observable_type=obs_type,
                python_module="tests.saq.remediation.test_remediator",
                python_class="TestRemediator",
            )

            remediator = load_remediator_from_config(config)

            assert remediator.observable_type == obs_type
            assert remediator.name == f"test_remediator_{obs_type}"
