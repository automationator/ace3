"""
Integration tests to verify AnalysisModule uses the state repository correctly.
"""

import pytest

from saq.analysis.root import RootAnalysis
from saq.analysis.adapter import RootAnalysisAdapter
from saq.modules.base_module import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.state_repository import InMemoryStateRepository
from tests.saq.test_util import create_test_context


class TestAnalysisModule(AnalysisModule):
    """Simple test analysis module for testing state management."""
    __test__ = False

    def execute_analysis(self, observable):
        """Simple implementation to satisfy the abstract method."""
        return True


@pytest.mark.integration
class TestAnalysisModuleStateIntegration:
    """Integration tests for AnalysisModule state management via repository."""
    
    def test_analysis_module_state_with_default_repository(self):
        """Test that AnalysisModule creates a default repository when none is provided."""
        root_analysis = RootAnalysis()
        context = create_test_context(root=root_analysis)
        
        # Create analysis module
        module = TestAnalysisModule(AnalysisModuleConfig(
            name="test_module",
            python_module="tests.saq.modules.test_analysis_module_state_integration",
            python_class="TestAnalysisModule",
            instance="test_instance",
            enabled=True,
        ), context=context)
        
        # Test state operations
        test_state = {"test_key": "test_value", "counter": 42}
        
        # Initially no state
        assert module.state is None
        
        # Set state
        module.state = test_state
        assert module.state == test_state
        
        # Verify it's stored in the root analysis (backward compatibility)
        assert root_analysis.state[module.name] == test_state
    
    def test_analysis_module_initialize_state(self):
        """Test the initialize_state method works with the repository."""
        root_analysis = RootAnalysis()
        context = create_test_context(root=root_analysis)
        
        module = TestAnalysisModule(AnalysisModuleConfig(
            name="test_module",
            python_module="tests.saq.modules.test_analysis_module_state_integration",
            python_class="TestAnalysisModule",
            instance="test_instance",
            enabled=True,
        ), context=context)
        
        # Initialize with custom state
        initial_state = {"initialized": True, "version": 1}
        module.initialize_state(initial_state)
        
        assert module.state == initial_state
        
        # Try to initialize again (should not overwrite)
        module.initialize_state({"should_not": "overwrite"})
        assert module.state == initial_state
    
    def test_analysis_module_initialize_state_default(self):
        """Test initialize_state with default empty dict."""
        root_analysis = RootAnalysis()
        context = create_test_context(root=root_analysis)
        
        module = TestAnalysisModule(AnalysisModuleConfig(
            name="test_module",
            python_module="tests.saq.modules.test_analysis_module_state_integration",
            python_class="TestAnalysisModule",
            instance="test_instance",
            enabled=True,
        ), context=context)
        
        # Initialize with default (empty dict)
        module.initialize_state()
        
        assert module.state == {}
    
    def test_analysis_module_with_custom_repository(self):
        """Test that AnalysisModule can use a custom repository."""
        root_analysis = RootAnalysis()
        custom_repository = InMemoryStateRepository()
        
        # Manually create context with custom repository
        from saq.filesystem.adapter import FileSystemAdapter
        from saq.modules.context import AnalysisModuleContext
        
        context = AnalysisModuleContext(
            root=RootAnalysisAdapter(root_analysis),
            filesystem=FileSystemAdapter(),
            state_repository=custom_repository
        )
        
        module = TestAnalysisModule(AnalysisModuleConfig(
            name="test_module",
            python_module="tests.saq.modules.test_analysis_module_state_integration",
            python_class="TestAnalysisModule",
            instance="test_instance",
            enabled=True,
        ), context=context)
        
        # Test state operations
        test_state = {"custom_repo": True}
        module.state = test_state
        
        assert module.state == test_state
        
        # Verify it's stored in the custom repository, not root analysis
        assert custom_repository.get_state(module.name) == test_state
        # The root analysis should NOT have this state
        assert module.name not in root_analysis.state
    
    def test_multiple_modules_separate_state(self):
        """Test that multiple modules maintain separate state."""
        root_analysis = RootAnalysis()
        context = create_test_context(root=root_analysis)
        
        module1 = TestAnalysisModule(AnalysisModuleConfig(
            name="test_module1",
            python_module="tests.saq.modules.test_analysis_module_state_integration",
            python_class="TestAnalysisModule",
            instance="instance1",
            enabled=True,
        ), context=context)
        module2 = TestAnalysisModule(AnalysisModuleConfig(
            name="test_module2",
            python_module="tests.saq.modules.test_analysis_module_state_integration",
            python_class="TestAnalysisModule",
            instance="instance2",
            enabled=True,
        ), context=context)
        
        # Set different state for each module
        module1.state = {"module": "one", "data": [1, 2, 3]}
        module2.state = {"module": "two", "data": {"key": "value"}}
        
        # Verify they maintain separate state
        assert module1.state["module"] == "one"
        assert module2.state["module"] == "two"
        
        # Modify one, verify the other is unchanged
        module1.state = {"modified": True}
        assert module2.state["module"] == "two"
    
    def test_state_persistence_across_analysis_runs(self):
        """Test that state persists across different analysis runs (contexts)."""
        root_analysis = RootAnalysis()
        
        # First analysis run
        context1 = create_test_context(root=root_analysis)
        module1 = TestAnalysisModule(AnalysisModuleConfig(
            name="test_module",
            python_module="tests.saq.modules.test_analysis_module_state_integration",
            python_class="TestAnalysisModule",
            instance="persistent_test",
            enabled=True,
        ), context=context1)
        
        test_state = {"persistent_data": "should_survive", "run_count": 1}
        module1.state = test_state
        
        # Second analysis run (new context, same root analysis)
        context2 = create_test_context(root=root_analysis)
        module2 = TestAnalysisModule(AnalysisModuleConfig(
            name="test_module",
            python_module="tests.saq.modules.test_analysis_module_state_integration",
            python_class="TestAnalysisModule",
            instance="persistent_test",
            enabled=True,
        ), context=context2)
        
        # State should persist
        assert module2.state == test_state
        
        # Modify and verify persistence
        module2.state["run_count"] = 2
        
        # Third analysis run
        context3 = create_test_context(root=root_analysis)
        module3 = TestAnalysisModule(AnalysisModuleConfig(
            name="test_module",
            python_module="tests.saq.modules.test_analysis_module_state_integration",
            python_class="TestAnalysisModule",
            instance="persistent_test",
            enabled=True,
        ), context=context3)
        
        assert module3.state["run_count"] == 2
    
    def test_backward_compatibility_with_existing_state(self):
        """Test that existing state set directly on root analysis is accessible."""
        root_analysis = RootAnalysis()
        context = create_test_context(root=root_analysis)
        
        module = TestAnalysisModule(AnalysisModuleConfig(
            name="test_module",
            python_module="tests.saq.modules.test_analysis_module_state_integration",
            python_class="TestAnalysisModule",
            instance="legacy_test",
            enabled=True,
        ), context=context)
        
        # Simulate legacy code setting state directly on root analysis
        legacy_state = {"legacy": True, "set_directly": "on_root"}
        root_analysis.state[module.name] = legacy_state
        
        # Module should be able to access this state
        assert module.state == legacy_state
        
        # Module should be able to modify it
        module.state["updated_by"] = "module"
        
        # Changes should be reflected in both places
        assert module.state["updated_by"] == "module"
        assert root_analysis.state[module.name]["updated_by"] == "module" 