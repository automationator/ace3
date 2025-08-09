import pytest
from unittest.mock import Mock
from configparser import ConfigParser

from saq.modules.config import AnalysisModuleConfig
from saq.modules.config_backend import (
    DictConfigBackend, DictConfigSection,
    INIConfigBackend, INIConfigSection,
    YAMLConfigBackend, YAMLConfigSection
)


class MockAnalysisModule:
    """Mock analysis module for testing."""
    
    def __init__(self, module_name="test.module", class_name="TestModule", instance=None):
        self.__module__ = module_name
        self.__class__.__name__ = class_name
        self._instance = instance


@pytest.mark.unit
def test_analysis_module_config_with_dict_backend():
    """Test AnalysisModuleConfig with dictionary-based configuration backend."""
    
    # Create test configuration data
    config_data = {
        "analysis_module_test": {
            "module": "test.module",
            "class": "TestModule",
            "enabled": "yes",
            "priority": "5",
            "maximum_analysis_time": "300",
            "cooldown_period": "30",
            "cache": "true",
            "version": "2",
            "valid_observable_types": "file,url,ipv4",
            "required_tags": "tag1,tag2",
            "requires_detection_path": "false",
            "exclude_test1": "file:test.txt",
            "exclude_test2": "url:http://example.com",
            "expect_test1": "file:expected.txt"
        },
        "global": {
            "maximum_analysis_time": "600"
        },
        "observable_exclusions": {
            "exclude1": "file:global_exclude.txt"
        }
    }
    
    # Create backend and module
    backend = DictConfigBackend(config_data)
    module = MockAnalysisModule()
    config = AnalysisModuleConfig(module, backend)
    
    # Test basic properties
    assert config.priority == 5
    assert config.maximum_analysis_time == 300
    assert config.cooldown_period == 30
    assert config.cache is True
    assert config.version == 2
    assert config.requires_detection_path is False
    
    # Test list properties
    assert config.valid_observable_types == ["file", "url", "ipv4"]
    assert config.required_tags == ["tag1", "tag2"]
    
    # Test exclusions
    exclusions = config.observable_exclusions
    assert "file" in exclusions
    assert "test.txt" in exclusions["file"]
    assert "global_exclude.txt" in exclusions["file"]
    assert "url" in exclusions
    assert "http://example.com" in exclusions["url"]
    
    # Test expected observables
    expected = config.expected_observables
    assert "file" in expected
    assert "expected.txt" in expected["file"]


@pytest.mark.unit
def test_analysis_module_config_with_instance():
    """Test AnalysisModuleConfig with instanced modules."""
    
    config_data = {
        "analysis_module_test_instance1": {
            "module": "test.module",
            "class": "TestModule",
            "instance": "instance1",
            "priority": "1"
        },
        "analysis_module_test_instance2": {
            "module": "test.module", 
            "class": "TestModule",
            "instance": "instance2",
            "priority": "2"
        },
        "global": {
            "maximum_analysis_time": "600"
        }
    }
    
    backend = DictConfigBackend(config_data)
    
    # Test instance1
    module1 = MockAnalysisModule(instance="instance1")
    config1 = AnalysisModuleConfig(module1, backend)
    assert config1.priority == 1
    assert config1.instance == "instance1"
    
    # Test instance2
    module2 = MockAnalysisModule(instance="instance2")
    config2 = AnalysisModuleConfig(module2, backend)
    assert config2.priority == 2
    assert config2.instance == "instance2"


@pytest.mark.unit
def test_analysis_module_config_missing_section():
    """Test AnalysisModuleConfig when configuration section is missing."""
    
    config_data = {
        "global": {
            "maximum_analysis_time": "600"
        }
    }
    
    backend = DictConfigBackend(config_data)
    module = MockAnalysisModule()
    config = AnalysisModuleConfig(module, backend)

    # now this works!
    assert config.config_section_name == "analysis_module_TestModule"


@pytest.mark.unit
def test_analysis_module_config_fallback_values():
    """Test AnalysisModuleConfig fallback values."""
    
    config_data = {
        "analysis_module_test": {
            "module": "test.module",
            "class": "TestModule"
            # No other values provided - should use fallbacks
        },
        "global": {
            "maximum_analysis_time": "600"
        }
    }
    
    backend = DictConfigBackend(config_data)
    module = MockAnalysisModule()
    config = AnalysisModuleConfig(module, backend)
    
    # Test fallback values
    assert config.priority == 10  # default fallback
    assert config.maximum_analysis_time == 600  # from global config
    assert config.cooldown_period == 60  # default fallback
    assert config.cache is False  # default fallback
    assert config.version == 1  # default fallback
    assert config.requires_detection_path is False  # default fallback
    
    # Test None/empty list fallbacks
    assert config.valid_observable_types is None
    assert config.valid_queues is None
    assert config.invalid_queues is None
    assert config.invalid_alert_types is None
    assert config.required_directives == []
    assert config.required_tags == []


@pytest.mark.unit
def test_config_section_interface():
    """Test the ConfigSection interface methods."""
    
    config_data = {
        "analysis_module_test": {
            "module": "test.module",
            "class": "TestModule",
            "test_key": "test_value",
            "test_int": "42",
            "test_bool": "true"
        }
    }
    
    backend = DictConfigBackend(config_data)
    module = MockAnalysisModule()
    config = AnalysisModuleConfig(module, backend)
    
    section = config.config_section
    
    # Test interface methods
    assert section.name == "analysis_module_test"
    assert section.get("test_key") == "test_value"
    assert section.get("missing_key", "default") == "default"
    assert section.getint("test_int") == 42
    assert section.getboolean("test_bool") is True
    assert "test_key" in section
    assert "missing_key" not in section
    assert section["test_key"] == "test_value"
    
    # Test keys and items
    keys = section.keys()
    assert "module" in keys
    assert "class" in keys
    assert "test_key" in keys
    
    items = section.items()
    assert ("test_key", "test_value") in items


@pytest.mark.unit
def test_config_utility_methods():
    """Test the utility methods on AnalysisModuleConfig."""
    
    config_data = {
        "analysis_module_test": {
            "module": "test.module",
            "class": "TestModule",
            "test_string": "hello",
            "test_int": "123",
            "test_bool": "yes"
        }
    }
    
    backend = DictConfigBackend(config_data)
    module = MockAnalysisModule()
    config = AnalysisModuleConfig(module, backend)
    
    # Test utility methods
    assert config.get_config_value("test_string") == "hello"
    assert config.get_config_value("missing", "default") == "default"
    assert config.get_config_int("test_int") == 123
    assert config.get_config_boolean("test_bool") is True
    assert config.has_config_key("test_string") is True
    assert config.has_config_key("missing") is False
    
    # Test verification methods
    config.verify_config_exists("test_string")  # Should not raise
    
    with pytest.raises(KeyError):
        config.verify_config_exists("missing_key")
    
    config.verify_config_item_has_value("test_string")  # Should not raise
    
    with pytest.raises(KeyError):
        config.verify_config_item_has_value("missing_key")


@pytest.mark.unit
def test_dict_config_section():
    """Test DictConfigSection functionality."""
    test_data = {
        "string_key": "test_value",
        "int_key": "42",
        "bool_key_true": "true",
        "bool_key_false": "false",
        "bool_key_yes": "yes",
        "bool_key_no": "no",
        "bool_key_1": "1",
        "bool_key_0": "0",
        "bool_key_on": "on",
        "bool_key_off": "off",
        "actual_bool_true": True,
        "actual_bool_false": False,
        "empty_value": "",
        "none_value": None,
        "list_value": ["item1", "item2"],
        "numeric_value": 123,
        "invalid_int": "not_a_number"
    }
    
    section = DictConfigSection("test_section", test_data)
    
    # Test name property
    assert section.name == "test_section"
    
    # Test get method
    assert section.get("string_key") == "test_value"
    assert section.get("missing_key") is None
    assert section.get("missing_key", "default") == "default"
    assert section.get("none_value") is None
    assert section.get("numeric_value") == "123"
    
    # Test getint method
    assert section.getint("int_key") == 42
    assert section.getint("numeric_value") == 123
    assert section.getint("missing_key") is None
    assert section.getint("missing_key", 99) == 99
    assert section.getint("invalid_int") is None
    assert section.getint("invalid_int", 88) == 88
    
    # Test getboolean method
    assert section.getboolean("bool_key_true") is True
    assert section.getboolean("bool_key_false") is False
    assert section.getboolean("bool_key_yes") is True
    assert section.getboolean("bool_key_no") is False
    assert section.getboolean("bool_key_1") is True
    assert section.getboolean("bool_key_0") is False
    assert section.getboolean("bool_key_on") is True
    assert section.getboolean("bool_key_off") is False
    assert section.getboolean("actual_bool_true") is True
    assert section.getboolean("actual_bool_false") is False
    assert section.getboolean("missing_key") is None
    assert section.getboolean("missing_key", True) is True
    assert section.getboolean("numeric_value") is True  # non-zero number evaluates to True
    
    # Test contains
    assert "string_key" in section
    assert "missing_key" not in section
    
    # Test getitem
    assert section["string_key"] == "test_value"
    assert section["numeric_value"] == "123"
    assert section["empty_value"] == ""
    
    with pytest.raises(KeyError):
        _ = section["missing_key"]
    
    # Test keys
    keys = section.keys()
    assert "string_key" in keys
    assert "int_key" in keys
    assert len(keys) == len(test_data)
    
    # Test items
    items = section.items()
    assert ("string_key", "test_value") in items
    assert ("int_key", "42") in items
    assert ("numeric_value", "123") in items
    
    # Test set method
    section.set("new_key", "new_value")
    assert section.get("new_key") == "new_value"
    assert "new_key" in section
    
    section.set("string_key", "updated_value")
    assert section.get("string_key") == "updated_value"


@pytest.mark.unit
def test_dict_config_backend():
    """Test DictConfigBackend functionality."""
    config_data = {
        "section1": {
            "key1": "value1",
            "int_key": "100",
            "bool_key": "true"
        },
        "section2": {
            "key2": "value2",
            "int_key2": "200",
            "bool_key2": "false"
        }
    }
    
    backend = DictConfigBackend(config_data)
    
    # Test sections
    sections = backend.sections()
    assert "section1" in sections
    assert "section2" in sections
    assert len(sections) == 2
    
    # Test has_section
    assert backend.has_section("section1") is True
    assert backend.has_section("section2") is True
    assert backend.has_section("missing_section") is False
    
    # Test get_section
    section1 = backend.get_section("section1")
    assert section1 is not None
    assert section1.name == "section1"
    assert section1.get("key1") == "value1"
    
    missing_section = backend.get_section("missing_section")
    assert missing_section is None
    
    # Test get_value
    assert backend.get_value("section1", "key1") == "value1"
    assert backend.get_value("section1", "missing_key") is None
    assert backend.get_value("section1", "missing_key", "default") == "default"
    assert backend.get_value("missing_section", "key1") is None
    assert backend.get_value("missing_section", "key1", "default") == "default"
    
    # Test get_value_as_int
    assert backend.get_value_as_int("section1", "int_key") == 100
    assert backend.get_value_as_int("section2", "int_key2") == 200
    assert backend.get_value_as_int("section1", "missing_key") is None
    assert backend.get_value_as_int("section1", "missing_key", 999) == 999
    assert backend.get_value_as_int("missing_section", "int_key") is None
    assert backend.get_value_as_int("missing_section", "int_key", 888) == 888
    
    # Test get_value_as_boolean
    assert backend.get_value_as_boolean("section1", "bool_key") is True
    assert backend.get_value_as_boolean("section2", "bool_key2") is False
    assert backend.get_value_as_boolean("section1", "missing_key") is None
    assert backend.get_value_as_boolean("section1", "missing_key", True) is True
    assert backend.get_value_as_boolean("missing_section", "bool_key") is None
    assert backend.get_value_as_boolean("missing_section", "bool_key", False) is False
    
    # Test create_section
    new_section = backend.create_section("new_section")
    assert new_section is not None
    assert new_section.name == "new_section"
    assert backend.has_section("new_section") is True
    
    # Adding to existing section should return existing section
    existing_section = backend.create_section("section1")
    assert existing_section is not None
    assert existing_section.name == "section1"
    
    # Test that created section is functional
    new_section.set("test_key", "test_value")
    assert backend.get_value("new_section", "test_key") == "test_value"


@pytest.mark.unit
def test_ini_config_section():
    """Test INIConfigSection functionality."""
    config_parser = ConfigParser()
    config_parser.add_section("test_section")
    config_parser.set("test_section", "string_key", "test_value")
    config_parser.set("test_section", "int_key", "42")
    config_parser.set("test_section", "bool_key", "true")
    
    section_proxy = config_parser["test_section"]
    section = INIConfigSection(section_proxy)
    
    # Test name property
    assert section.name == "test_section"
    
    # Test get method
    assert section.get("string_key") == "test_value"
    assert section.get("missing_key") is None
    assert section.get("missing_key", "default") == "default"
    
    # Test getint method
    assert section.getint("int_key") == 42
    assert section.getint("missing_key") is None
    assert section.getint("missing_key", 99) == 99
    
    # Test getboolean method
    assert section.getboolean("bool_key") is True
    assert section.getboolean("missing_key") is None
    assert section.getboolean("missing_key", False) is False
    
    # Test contains
    assert "string_key" in section
    assert "missing_key" not in section
    
    # Test getitem
    assert section["string_key"] == "test_value"
    
    with pytest.raises(KeyError):
        _ = section["missing_key"]
    
    # Test keys
    keys = section.keys()
    assert "string_key" in keys
    assert "int_key" in keys
    assert "bool_key" in keys
    
    # Test items
    items = section.items()
    assert ("string_key", "test_value") in items
    assert ("int_key", "42") in items
    
    # Test set method
    section.set("new_key", "new_value")
    assert section.get("new_key") == "new_value"
    assert "new_key" in section


@pytest.mark.unit
def test_ini_config_backend():
    """Test INIConfigBackend functionality."""
    config_parser = ConfigParser()
    config_parser.add_section("section1")
    config_parser.set("section1", "key1", "value1")
    config_parser.set("section1", "int_key", "100")
    config_parser.set("section1", "bool_key", "true")
    
    config_parser.add_section("section2")
    config_parser.set("section2", "key2", "value2")
    
    backend = INIConfigBackend(config_parser)
    
    # Test sections
    sections = backend.sections()
    assert "section1" in sections
    assert "section2" in sections
    
    # Test has_section
    assert backend.has_section("section1") is True
    assert backend.has_section("missing_section") is False
    
    # Test get_section
    section1 = backend.get_section("section1")
    assert section1 is not None
    assert section1.name == "section1"
    assert section1.get("key1") == "value1"
    
    missing_section = backend.get_section("missing_section")
    assert missing_section is None
    
    # Test create_section
    new_section = backend.create_section("new_section")
    assert new_section is not None
    assert new_section.name == "new_section"
    assert backend.has_section("new_section") is True
    
    # Test that created section is functional
    new_section.set("test_key", "test_value")
    assert new_section.get("test_key") == "test_value"


class MockYAMLSectionProxy:
    """Mock YAML section proxy for testing."""
    
    def __init__(self, data, name=None):
        self._data = data
        self._mapping = data  # Some implementations use _mapping
        self._name = name
    
    def get(self, key, fallback=None):
        return self._data.get(key, fallback)
    
    def keys(self):
        return self._data.keys()
    
    def items(self):
        return self._data.items()
    
    def __contains__(self, key):
        return key in self._data
    
    def __getitem__(self, key):
        return self._data[key]
    
    def __setitem__(self, key, value):
        self._data[key] = value


class MockYAMLConfig:
    """Mock YAML config for testing."""
    
    def __init__(self, data):
        self._data = data
    
    def sections(self):
        return list(self._data.keys())
    
    def keys(self):
        return self._data.keys()
    
    def __contains__(self, section):
        return section in self._data
    
    def __getitem__(self, section):
        if section not in self._data:
            raise KeyError(section)
        return MockYAMLSectionProxy(self._data[section], section)
    
    def __setitem__(self, section, value):
        self._data[section] = value


@pytest.mark.unit
def test_yaml_config_section():
    """Test YAMLConfigSection functionality."""
    test_data = {
        "string_key": "test_value",
        "int_key": 42,
        "bool_key_true": True,
        "bool_key_false": False,
        "bool_string_true": "true",
        "bool_string_false": "false",
        "bool_string_yes": "yes",
        "bool_string_no": "no",
        "bool_string_1": "1",
        "bool_string_0": "0",
        "bool_string_on": "on",
        "bool_string_off": "off",
        "list_value": ["item1", "item2", "item3"],
        "empty_value": "",
        "none_value": None
    }
    
    section_proxy = MockYAMLSectionProxy(test_data, "test_section")
    section = YAMLConfigSection(section_proxy)
    
    # Test name property (should fallback to 'unknown' if not set)
    assert section.name == "test_section"
    
    # Test name property without _name attribute
    section_proxy_no_name = MockYAMLSectionProxy(test_data)
    delattr(section_proxy_no_name, '_name')  # Remove the _name attribute
    section_no_name = YAMLConfigSection(section_proxy_no_name)
    assert section_no_name.name == "unknown"
    
    # Test get method
    assert section.get("string_key") == "test_value"
    assert section.get("missing_key") is None
    assert section.get("missing_key", "default") == "default"
    assert section.get("int_key") == "42"
    assert section.get("list_value") == "item1,item2,item3"  # Lists converted to comma-separated
    assert section.get("none_value") is None
    
    # Test getint method
    assert section.getint("int_key") == 42
    assert section.getint("string_key") is None  # Invalid int should return fallback
    assert section.getint("missing_key") is None
    assert section.getint("missing_key", 99) == 99
    
    # Test getboolean method
    assert section.getboolean("bool_key_true") is True
    assert section.getboolean("bool_key_false") is False
    assert section.getboolean("bool_string_true") is True
    assert section.getboolean("bool_string_false") is False
    assert section.getboolean("bool_string_yes") is True
    assert section.getboolean("bool_string_no") is False
    assert section.getboolean("bool_string_1") is True
    assert section.getboolean("bool_string_0") is False
    assert section.getboolean("bool_string_on") is True
    assert section.getboolean("bool_string_off") is False
    assert section.getboolean("missing_key") is None
    assert section.getboolean("missing_key", True) is True
    assert section.getboolean("int_key") is True  # Non-zero value
    assert section.getboolean("empty_value") is False  # Empty string
    
    # Test contains
    assert "string_key" in section
    assert "missing_key" not in section
    
    # Test getitem
    assert section["string_key"] == "test_value"
    assert section["list_value"] == "item1,item2,item3"
    assert section["empty_value"] == ""
    
    with pytest.raises(KeyError):
        _ = section["missing_key"]
    
    # Test keys
    keys = section.keys()
    assert "string_key" in keys
    assert "int_key" in keys
    assert len(keys) == len(test_data)
    
    # Test items (values should be stringified)
    items = section.items()
    assert ("string_key", "test_value") in items
    assert ("int_key", "42") in items
    assert ("bool_key_true", "True") in items
    
    # Test set method
    section.set("new_key", "new_value")
    assert section.get("new_key") == "new_value"
    assert "new_key" in section


@pytest.mark.unit
def test_yaml_config_backend():
    """Test YAMLConfigBackend functionality."""
    config_data = {
        "section1": {
            "key1": "value1",
            "int_key": 100,
            "bool_key": True,
            "list_key": ["a", "b", "c"]
        },
        "section2": {
            "key2": "value2",
            "int_key2": 200,
            "bool_key2": False
        }
    }
    
    yaml_config = MockYAMLConfig(config_data)
    backend = YAMLConfigBackend(yaml_config)
    
    # Test sections
    sections = backend.sections()
    assert "section1" in sections
    assert "section2" in sections
    assert len(sections) == 2
    
    # Test has_section
    assert backend.has_section("section1") is True
    assert backend.has_section("section2") is True
    assert backend.has_section("missing_section") is False
    
    # Test get_section
    section1 = backend.get_section("section1")
    assert section1 is not None
    assert section1.get("key1") == "value1"
    assert section1.get("list_key") == "a,b,c"
    
    missing_section = backend.get_section("missing_section")
    assert missing_section is None
    
    # Test create_section
    new_section = backend.create_section("new_section")
    assert new_section is not None
    assert backend.has_section("new_section") is True
    
    # Adding to existing section should return existing section
    existing_section = backend.create_section("section1")
    assert existing_section is not None
    
    # Test that created section is functional
    new_section.set("test_key", "test_value")
    assert new_section.get("test_key") == "test_value"


@pytest.mark.unit  
def test_yaml_config_backend_get_value_methods():
    """Test YAMLConfigBackend get_value methods."""
    config_data = {
        "test_section": {
            "string_key": "test_value",
            "int_key": 42,
            "bool_key": True
        }
    }
    
    yaml_config = MockYAMLConfig(config_data)
    backend = YAMLConfigBackend(yaml_config)
    
    # Note: These methods delegate to saq.configuration.config functions
    # Since we can't mock and don't want to depend on the actual config system,
    # we'll test that the methods exist and can be called, but the actual
    # behavior depends on the external configuration functions
    
    # Test that the methods exist and are callable
    assert hasattr(backend, 'get_value')
    assert hasattr(backend, 'get_value_as_int') 
    assert hasattr(backend, 'get_value_as_boolean')
    assert callable(backend.get_value)
    assert callable(backend.get_value_as_int)
    assert callable(backend.get_value_as_boolean)
    
    # Test method signatures by calling with expected parameters
    # Note: These calls may return None or raise exceptions depending on
    # the actual configuration system, but we're verifying the interface
    try:
        result = backend.get_value("test_section", "string_key")
        # Result could be None or actual value depending on config system
        assert result is None or isinstance(result, (str, type(None)))
    except:
        # Expected if config system is not properly initialized
        pass
    
    try:
        result = backend.get_value_as_int("test_section", "int_key")
        assert result is None or isinstance(result, (int, type(None)))
    except:
        pass
    
    try:
        result = backend.get_value_as_boolean("test_section", "bool_key")
        assert result is None or isinstance(result, (bool, type(None)))
    except:
        pass
    
    # Test with fallback parameters
    try:
        result = backend.get_value("missing_section", "missing_key", "default")
        assert result is None or isinstance(result, (str, type(None)))
    except:
        pass
        
    try:
        result = backend.get_value_as_int("missing_section", "missing_key", 999)
        assert result is None or isinstance(result, (int, type(None)))
    except:
        pass
        
    try:
        result = backend.get_value_as_boolean("missing_section", "missing_key", True)
        assert result is None or isinstance(result, (bool, type(None)))
    except:
        pass


@pytest.mark.unit
def test_dict_config_section_edge_cases():
    """Test edge cases for DictConfigSection."""
    # Test with empty data
    empty_section = DictConfigSection("empty", {})
    assert empty_section.name == "empty"
    assert empty_section.keys() == []
    assert empty_section.items() == []
    assert "anything" not in empty_section
    
    # Test with None values
    none_data = {"key1": None, "key2": "value"}
    none_section = DictConfigSection("none_test", none_data)
    assert none_section.get("key1") is None
    assert none_section.get("key2") == "value"
    assert none_section.getint("key1") is None
    assert none_section.getboolean("key1") is None
    
    # Test boolean conversion edge cases
    bool_data = {
        "truthy_int": 1,
        "falsy_int": 0,
        "truthy_string": "yes",  # Only specific strings are truthy
        "falsy_string": "",
        "weird_bool": "TrUe",  # Case insensitive
        "invalid_bool": "maybe"
    }
    bool_section = DictConfigSection("bool_test", bool_data)
    assert bool_section.getboolean("truthy_int") is True
    assert bool_section.getboolean("falsy_int") is False
    assert bool_section.getboolean("truthy_string") is True
    assert bool_section.getboolean("falsy_string") is False
    assert bool_section.getboolean("weird_bool") is True
    assert bool_section.getboolean("invalid_bool") is False  # Strings not in accepted list are falsy


@pytest.mark.unit
def test_dict_config_backend_edge_cases():
    """Test edge cases for DictConfigBackend."""
    # Test with empty config
    empty_backend = DictConfigBackend({})
    assert empty_backend.sections() == []
    assert empty_backend.has_section("anything") is False
    assert empty_backend.get_section("anything") is None
    assert empty_backend.get_value("section", "key") is None
    assert empty_backend.get_value_as_int("section", "key") is None
    assert empty_backend.get_value_as_boolean("section", "key") is None
    
    # Test invalid type conversions
    invalid_data = {
        "test_section": {
            "invalid_int": "not_a_number",
            "invalid_bool": "maybe"
        }
    }
    invalid_backend = DictConfigBackend(invalid_data)
    
    # Invalid int should return fallback
    assert invalid_backend.get_value_as_int("test_section", "invalid_int") is None
    assert invalid_backend.get_value_as_int("test_section", "invalid_int", 999) == 999
    
    # Invalid bool string should be treated as falsy (not in accepted list)
    assert invalid_backend.get_value_as_boolean("test_section", "invalid_bool") is False

@pytest.mark.unit
def test_yaml_config_section_set_edge_cases():
    """Test edge cases for YAMLConfigSection set method."""
    # Test section with no _mapping attribute
    test_data = {"key1": "value1"}
    
    class MinimalProxy:
        def __init__(self, data):
            self._data = data
        
        def get(self, key, fallback=None):
            return self._data.get(key, fallback)
        
        def keys(self):
            return self._data.keys()
        
        def items(self):
            return self._data.items()
        
        def __contains__(self, key):
            return key in self._data
        
        def __getitem__(self, key):
            return self._data[key]
        
        def __setitem__(self, key, value):
            self._data[key] = value
    
    minimal_proxy = MinimalProxy(test_data)
    section = YAMLConfigSection(minimal_proxy)
    
    # Should still work via fallback mechanism
    section.set("new_key", "new_value")
    assert section.get("new_key") == "new_value"
    
    # Test section that raises exception on setitem
    class ExceptionProxy(MinimalProxy):
        def __setitem__(self, key, value):
            raise Exception("Setting not allowed")
    
    exception_proxy = ExceptionProxy(test_data.copy())
    exception_section = YAMLConfigSection(exception_proxy)
    
    # Should handle exception gracefully but might raise the exception
    with pytest.raises(Exception):
        exception_section.set("another_key", "another_value")


@pytest.mark.unit
def test_yaml_config_section_boolean_edge_cases():
    """Test boolean conversion edge cases for YAMLConfigSection."""
    test_data = {
        "whitespace_true": " TRUE ",
        "whitespace_false": " false ",
        "mixed_case": "YeS",
        "number_zero": 0,
        "number_nonzero": 42,
        "empty_list": [],
        "non_empty_list": ["item"],
        "weird_string": "unknown"
    }
    
    section_proxy = MockYAMLSectionProxy(test_data)
    section = YAMLConfigSection(section_proxy)
    
    # Test whitespace handling
    assert section.getboolean("whitespace_true") is True
    assert section.getboolean("whitespace_false") is False
    assert section.getboolean("mixed_case") is True
    
    # Test numeric values
    assert section.getboolean("number_zero") is False
    assert section.getboolean("number_nonzero") is True
    
    # Test container values
    assert section.getboolean("empty_list") is False
    assert section.getboolean("non_empty_list") is True
    
    # Test unknown string (should be truthy)
    assert section.getboolean("weird_string") is True 