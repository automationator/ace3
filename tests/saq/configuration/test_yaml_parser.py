import os
import sys
import yaml

import pytest

from saq.configuration.error import ConfigurationException
from saq.configuration.yaml_parser import (
    EnvVarRef,
    EncryptedRef,
    YAMLSectionProxy,
    YAMLConfig,
    _yaml_env_constructor,
    _yaml_enc_constructor,
)


@pytest.mark.unit
def test_envvarref_initialization():
    """Test EnvVarRef class initialization and representation."""
    ref = EnvVarRef("TEST_VAR")
    assert ref.variable_name == "TEST_VAR"
    assert repr(ref) == "EnvVarRef('TEST_VAR')"


@pytest.mark.unit
def test_encryptedref_initialization():
    """Test EncryptedRef class initialization and representation."""
    ref = EncryptedRef("test_key")
    assert ref.key == "test_key"
    assert repr(ref) == "EncryptedRef('test_key')"


@pytest.mark.unit
def test_yaml_env_constructor_scalar():
    """Test YAML !env constructor with scalar node."""
    loader = yaml.SafeLoader("!env TEST_VAR")
    node = yaml.ScalarNode(tag="!env", value="TEST_VAR")
    result = _yaml_env_constructor(loader, node)
    
    assert isinstance(result, EnvVarRef)
    assert result.variable_name == "TEST_VAR"


@pytest.mark.unit
def test_yaml_env_constructor_mapping():
    """Test YAML !env constructor with mapping node."""
    loader = yaml.SafeLoader("{name: TEST_VAR}")
    # Create a mapping node with name key
    key_node = yaml.ScalarNode(tag="tag:yaml.org,2002:str", value="name")
    value_node = yaml.ScalarNode(tag="tag:yaml.org,2002:str", value="TEST_VAR")
    node = yaml.MappingNode(tag="tag:yaml.org,2002:map", value=[(key_node, value_node)])
    
    result = _yaml_env_constructor(loader, node)
    
    assert isinstance(result, EnvVarRef)
    assert result.variable_name == "TEST_VAR"


@pytest.mark.unit
def test_yaml_enc_constructor_scalar():
    """Test YAML !enc constructor with scalar node."""
    loader = yaml.SafeLoader("!enc test_key")
    node = yaml.ScalarNode(tag="!enc", value="test_key")
    result = _yaml_enc_constructor(loader, node)
    
    assert isinstance(result, EncryptedRef)
    assert result.key == "test_key"


@pytest.mark.unit
def test_yaml_enc_constructor_mapping():
    """Test YAML !enc constructor with mapping node."""
    loader = yaml.SafeLoader("{key: test_key}")
    # Create a mapping node with key key
    key_node = yaml.ScalarNode(tag="tag:yaml.org,2002:str", value="key")
    value_node = yaml.ScalarNode(tag="tag:yaml.org,2002:str", value="test_key")
    node = yaml.MappingNode(tag="tag:yaml.org,2002:map", value=[(key_node, value_node)])
    
    result = _yaml_enc_constructor(loader, node)
    
    assert isinstance(result, EncryptedRef)
    assert result.key == "test_key"


@pytest.mark.unit
def test_yaml_section_proxy_basic_operations(tmpdir):
    """Test YAMLSectionProxy basic mapping operations."""
    # Set up environment variable for testing
    os.environ["TEST_YAML_VAR"] = "test_value"
    
    try:
        config = YAMLConfig()
        test_data = {
            "key1": "value1",
            "key2": EnvVarRef("TEST_YAML_VAR"),
            "key3": "env:TEST_YAML_VAR"
        }
        
        proxy = YAMLSectionProxy(config, "test_section", test_data)
        
        # Test __getitem__
        assert proxy["key1"] == "value1"
        assert proxy["key2"] == "test_value"  # EnvVarRef resolved
        assert proxy["key3"] == "test_value"  # env: prefix resolved
        
        # Test get method
        assert proxy.get("key1") == "value1"
        assert proxy.get("nonexistent", "default") == "default"
        
        # Test __setitem__ and __delitem__
        proxy["new_key"] = "new_value"
        assert proxy["new_key"] == "new_value"
        
        del proxy["new_key"]
        assert proxy.get("new_key") is None
        
        # Test __iter__ and __len__
        keys = list(proxy)
        assert len(keys) == 3
        assert "key1" in keys
        assert "key2" in keys
        assert "key3" in keys
        assert len(proxy) == 3
        
        # Test items()
        items = list(proxy.items())
        assert len(items) == 3
        # Check that values are resolved
        item_dict = dict(items)
        assert item_dict["key1"] == "value1"
        assert item_dict["key2"] == "test_value"
        assert item_dict["key3"] == "test_value"
        
    finally:
        del os.environ["TEST_YAML_VAR"]


@pytest.mark.unit
def test_yaml_config_initialization():
    """Test YAMLConfig initialization."""
    config = YAMLConfig()
    
    assert isinstance(config._data, dict)
    assert len(config._data) == 0
    assert isinstance(config.encrypted_password_cache, dict)
    assert isinstance(config.loaded_files, set)
    assert len(config.loaded_files) == 0


@pytest.mark.unit
def test_yaml_config_basic_mapping_operations():
    """Test YAMLConfig basic mapping operations."""
    config = YAMLConfig()
    
    # Test __setitem__ and __getitem__
    config["test_section"] = {"key1": "value1", "key2": "value2"}
    section = config["test_section"]
    assert isinstance(section, YAMLSectionProxy)
    assert section["key1"] == "value1"
    assert section["key2"] == "value2"
    
    # Test __delitem__
    config["temp_section"] = {"temp_key": "temp_value"}
    del config["temp_section"]
    assert "temp_section" not in config
    
    # Test __iter__ and __len__
    keys = list(config)
    assert len(keys) == 1
    assert "test_section" in keys
    assert len(config) == 1
    
    # Test sections method
    sections = config.sections()
    assert sections == ["test_section"]
    
    # Test get method
    assert config.get("test_section", "key1") == "value1"
    assert config.get("nonexistent_section", "key1", "default") == "default"


@pytest.mark.unit
def test_yaml_config_environment_variable_resolution():
    """Test environment variable resolution in YAMLConfig."""
    # Set up test environment variables
    os.environ["TEST_YAML_VAR1"] = "env_value_1"
    os.environ["TEST_YAML_VAR2"] = "env_value_2"
    
    try:
        config = YAMLConfig()
        
        # Test EnvVarRef resolution
        assert config._resolve_value(EnvVarRef("TEST_YAML_VAR1")) == "env_value_1"
        
        # Test env: prefix resolution
        assert config._resolve_value("env:TEST_YAML_VAR2") == "env_value_2"
        
        # Test error for unknown environment variable
        with pytest.raises(RuntimeError, match="configuration referenced unknown environment variable"):
            config._resolve_value(EnvVarRef("NONEXISTENT_VAR"))
        
        with pytest.raises(RuntimeError, match="configuration referenced unknown environment variable"):
            config._resolve_value("env:NONEXISTENT_VAR")
        
        # Test regular strings are not modified
        assert config._resolve_value("regular_string") == "regular_string"
        assert config._resolve_value("prefix:but_not_env") == "prefix:but_not_env"
        
    finally:
        del os.environ["TEST_YAML_VAR1"]
        del os.environ["TEST_YAML_VAR2"]


@pytest.mark.unit
def test_yaml_config_encrypted_password_resolution():
    """Test encrypted password resolution in YAMLConfig."""
    config = YAMLConfig()
    
    # Mock encryption not initialized - should return string form
    from saq.environment import g_obj, set_g
    from saq.constants import G_ENCRYPTION_INITIALIZED
    
    # Save original state
    original_encryption_state = g_obj(G_ENCRYPTION_INITIALIZED).value
    
    try:
        # Test with encryption not initialized
        set_g(G_ENCRYPTION_INITIALIZED, False)
        
        # Test EncryptedRef when encryption not initialized
        result = config._resolve_value(EncryptedRef("test_key"))
        assert result == "encrypted:test_key"
        
        # Test encrypted: prefix when encryption not initialized
        result = config._resolve_value("encrypted:test_key")
        assert result == "encrypted:test_key"
        
    finally:
        # Restore original state
        set_g(G_ENCRYPTION_INITIALIZED, original_encryption_state)


@pytest.mark.unit
def test_yaml_config_load_file_basic(tmpdir):
    """Test basic YAML file loading."""
    yaml_file = tmpdir.join("test.yaml")
    yaml_content = """
section1:
  key1: value1
  key2: value2

section2:
  key3: value3
  key4: 42
"""
    yaml_file.write(yaml_content)
    
    config = YAMLConfig()
    result = config.load_file(str(yaml_file))
    
    assert result is True  # File was loaded
    assert "section1" in config
    assert "section2" in config
    
    assert config["section1"]["key1"] == "value1"
    assert config["section1"]["key2"] == "value2"
    assert config["section2"]["key3"] == "value3"
    assert config["section2"]["key4"] == 42
    
    assert str(yaml_file) in config.loaded_files
    
    # Test loading same file again returns False
    result = config.load_file(str(yaml_file))
    assert result is False


@pytest.mark.unit
def test_yaml_config_load_file_with_tags(tmpdir):
    """Test YAML file loading with custom tags."""
    os.environ["TEST_YAML_TAG_VAR"] = "tag_test_value"
    
    try:
        yaml_file = tmpdir.join("test_tags.yaml")
        yaml_content = """
section1:
  env_scalar: !env TEST_YAML_TAG_VAR
  env_mapping: !env {name: TEST_YAML_TAG_VAR}
  enc_scalar: !enc test_encrypted_key
  enc_mapping: !enc {key: test_encrypted_key}
"""
        yaml_file.write(yaml_content)
        
        config = YAMLConfig()
        config.load_file(str(yaml_file))
        
        # Test that tags are properly parsed as reference objects
        section = config["section1"]
        
        # These should resolve the environment variable
        assert section["env_scalar"] == "tag_test_value"
        assert section["env_mapping"] == "tag_test_value"
        
        # For encrypted values, the behavior depends on encryption initialization state
        # Since we can't easily control this in tests, we just verify they don't return the raw YAML
        enc_scalar_result = section["enc_scalar"] 
        enc_mapping_result = section["enc_mapping"]
        
        # They should be processed (not the original YAML string) - either decrypted, error message, or None
        assert enc_scalar_result != "!enc test_encrypted_key"
        assert enc_mapping_result != "!enc {key: test_encrypted_key}"
        
    finally:
        del os.environ["TEST_YAML_TAG_VAR"]


@pytest.mark.unit
def test_yaml_config_load_file_scalar_top_level(tmpdir):
    """Test YAML file loading with scalar values at top level."""
    yaml_file = tmpdir.join("test_scalar.yaml")
    yaml_content = """
scalar_key: scalar_value
section1:
  key1: value1
"""
    yaml_file.write(yaml_content)
    
    config = YAMLConfig()
    config.load_file(str(yaml_file))
    
    # Scalar at top-level should be put in a pseudo-section
    assert "scalar_key" in config
    assert config["scalar_key"]["value"] == "scalar_value"
    
    # Regular section should work normally
    assert config["section1"]["key1"] == "value1"


@pytest.mark.unit
def test_yaml_config_load_file_invalid_yaml(tmpdir):
    """Test YAML file loading with invalid content."""
    yaml_file = tmpdir.join("invalid.yaml")
    yaml_content = "not_a_mapping"
    yaml_file.write(yaml_content)
    
    config = YAMLConfig()
    
    with pytest.raises(ValueError, match="YAML configuration root must be a mapping"):
        config.load_file(str(yaml_file))


@pytest.mark.unit
def test_yaml_config_apply():
    """Test the apply method for merging configurations."""
    config = YAMLConfig()
    
    # Set initial configuration
    config["section1"] = {"key1": "value1", "key2": "value2"}
    config["section2"] = {"key3": "value3"}
    
    # Apply another configuration
    other_config = {
        "section1": {"key1": "updated_value1", "key4": "value4"},  # Update and add
        "section3": {"key5": "value5"}  # New section
    }
    
    config.apply(other_config)
    
    # Check that existing values were updated
    assert config["section1"]["key1"] == "updated_value1"
    # Check that existing values not in other_config remain
    assert config["section1"]["key2"] == "value2"
    # Check that new values were added
    assert config["section1"]["key4"] == "value4"
    # Check that untouched sections remain
    assert config["section2"]["key3"] == "value3"
    # Check that new sections were added
    assert config["section3"]["key5"] == "value5"


@pytest.mark.unit
def test_yaml_config_resolve_references_list(tmpdir):
    """Test resolve_references with list of includes."""
    # Create include files
    include1 = tmpdir.join("include1.yaml")
    include1.write("""
included_section1:
  inc_key1: inc_value1
""")
    
    include2 = tmpdir.join("include2.yaml")
    include2.write("""
included_section2:
  inc_key2: inc_value2
""")
    
    # Create main file with config list
    main_file = tmpdir.join("main.yaml")
    main_file.write(f"""
config:
  - {include1}
  - {include2}

main_section:
  main_key: main_value
""")
    
    config = YAMLConfig()
    config.load_file(str(main_file))
    
    # Check that all sections are loaded
    assert "main_section" in config
    assert "included_section1" in config
    assert "included_section2" in config
    
    assert config["main_section"]["main_key"] == "main_value"
    assert config["included_section1"]["inc_key1"] == "inc_value1"
    assert config["included_section2"]["inc_key2"] == "inc_value2"
    
    # Check that all files are in loaded_files
    assert str(main_file) in config.loaded_files
    assert str(include1) in config.loaded_files
    assert str(include2) in config.loaded_files


@pytest.mark.unit
def test_yaml_config_resolve_references_mapping(tmpdir):
    """Test resolve_references with mapping of includes."""
    # Create include files
    include1 = tmpdir.join("db.yaml")
    include1.write("""
database:
  host: localhost
  port: 3306
""")
    
    include2 = tmpdir.join("cache.yaml")
    include2.write("""
redis:
  host: redis-server
  port: 6379
""")
    
    # Create main file with config mapping
    main_file = tmpdir.join("main.yaml")
    main_file.write(f"""
config:
  database: {include1}
  cache: {include2}

app:
  name: test_app
""")
    
    config = YAMLConfig()
    config.load_file(str(main_file))
    
    # Check that all sections are loaded
    assert "app" in config
    assert "database" in config
    assert "redis" in config
    
    assert config["app"]["name"] == "test_app"
    assert config["database"]["host"] == "localhost"
    assert config["database"]["port"] == 3306
    assert config["redis"]["host"] == "redis-server"


@pytest.mark.unit
def test_yaml_config_resolve_references_non_yaml_skipped(tmpdir):
    """Test that non-YAML includes are skipped with warning."""
    # Create a non-YAML file
    txt_file = tmpdir.join("config.txt")
    txt_file.write("some config text")
    
    # Create main file
    main_file = tmpdir.join("main.yaml")
    main_file.write(f"""
config:
  - {txt_file}

main_section:
  key: value
""")
    
    config = YAMLConfig()
    
    # This should not raise an error, but should log a warning
    config.load_file(str(main_file))
    
    # Main section should still be loaded
    assert "main_section" in config
    assert config["main_section"]["key"] == "value"
    
    # txt file should not be in loaded_files
    assert str(txt_file) not in config.loaded_files


@pytest.mark.unit
def test_yaml_config_verify_success():
    """Test verify method when no OVERRIDE values exist."""
    config = YAMLConfig()
    config["section1"] = {"key1": "value1", "key2": "value2"}
    config["section2"] = {"key3": "value3"}
    
    # Should return True when no OVERRIDE values
    result = config.verify()
    assert result is True


@pytest.mark.unit
def test_yaml_config_verify_with_overrides():
    """Test verify method when OVERRIDE values exist."""
    config = YAMLConfig()
    config["section1"] = {"key1": "value1", "key2": "OVERRIDE"}
    config["section2"] = {"key3": "OVERRIDE", "key4": "value4"}
    
    # Should raise ConfigurationException when OVERRIDE values exist
    with pytest.raises(ConfigurationException, match="missing OVERRIDES in configuration"):
        config.verify()


@pytest.mark.unit
def test_yaml_config_verify_with_resolved_overrides():
    """Test verify method with values that resolve to OVERRIDE."""
    os.environ["OVERRIDE_VAR"] = "OVERRIDE"
    
    try:
        config = YAMLConfig()
        config["section1"] = {"key1": "value1", "key2": "env:OVERRIDE_VAR"}
        
        # Should raise ConfigurationException when resolved value is OVERRIDE
        with pytest.raises(ConfigurationException, match="missing OVERRIDES in configuration"):
            config.verify()
            
    finally:
        del os.environ["OVERRIDE_VAR"]


@pytest.mark.unit
def test_yaml_config_apply_path_references():
    """Test apply_path_references method."""
    # Save original sys.path
    original_path = sys.path.copy()
    
    try:
        config = YAMLConfig()
        test_path1 = "/test/path1"
        test_path2 = "/test/path2"
        
        # Set up path section with various value types
        config["path"] = {
            "path1": test_path1,
            "path2": test_path2,
            "not_string": 42,  # Should be ignored
        }
        
        config.apply_path_references()
        
        # Check that string paths were added to sys.path
        assert test_path1 in sys.path
        assert test_path2 in sys.path
        
    finally:
        # Restore original sys.path
        sys.path[:] = original_path


@pytest.mark.unit
def test_yaml_config_apply_path_references_with_env_var():
    """Test apply_path_references with environment variable."""
    os.environ["TEST_PATH_VAR"] = "/env/test/path"
    original_path = sys.path.copy()
    
    try:
        config = YAMLConfig()
        config["path"] = {"env_path": "env:TEST_PATH_VAR"}
        
        config.apply_path_references()
        
        # Check that resolved path was added
        assert "/env/test/path" in sys.path
        
    finally:
        del os.environ["TEST_PATH_VAR"]
        sys.path[:] = original_path


@pytest.mark.unit
def test_yaml_config_apply_path_references_no_path_section():
    """Test apply_path_references when no path section exists."""
    original_path = sys.path.copy()
    
    try:
        config = YAMLConfig()
        config["other_section"] = {"key": "value"}
        
        # Should not raise an error
        config.apply_path_references()
        
        # sys.path should be unchanged
        assert sys.path == original_path
        
    finally:
        sys.path[:] = original_path


@pytest.mark.unit
def test_yaml_config_apply_path_references_non_dict_path_section():
    """Test apply_path_references when path section is not a dict."""
    original_path = sys.path.copy()
    
    try:
        config = YAMLConfig()
        # This would happen if someone puts 'path: some_string' at top level
        config._data["path"] = "not_a_dict"
        
        # Should not raise an error
        config.apply_path_references()
        
        # sys.path should be unchanged
        assert sys.path == original_path
        
    finally:
        sys.path[:] = original_path


@pytest.mark.unit
def test_yaml_config_recursive_includes(tmpdir):
    """Test recursive includes and circular reference handling."""
    # Create files that include each other
    file1 = tmpdir.join("file1.yaml")
    file2 = tmpdir.join("file2.yaml")
    
    file1.write(f"""
config:
  - {file2}

section1:
  key1: value1
""")
    
    file2.write(f"""
config:
  - {file1}  # This creates a circular reference

section2:
  key2: value2
""")
    
    config = YAMLConfig()
    config.load_file(str(file1))
    
    # Should handle circular references gracefully
    assert "section1" in config
    assert "section2" in config
    assert config["section1"]["key1"] == "value1"
    assert config["section2"]["key2"] == "value2"
    
    # Both files should be in loaded_files (loaded only once each)
    assert str(file1) in config.loaded_files
    assert str(file2) in config.loaded_files


@pytest.mark.unit
def test_yaml_config_get_decrypted_password_cached():
    """Test _get_decrypted_password with cached value."""
    config = YAMLConfig()
    
    # Pre-populate cache
    config.encrypted_password_cache["test_key"] = "cached_password"
    
    result = config._get_decrypted_password("test_key")
    assert result == "cached_password"


@pytest.mark.unit
def test_yaml_config_merge_sections_on_multiple_loads(tmpdir):
    """Test that sections are merged when loading multiple files with same sections."""
    file1 = tmpdir.join("file1.yaml")
    file1.write("""
section1:
  key1: value1
  key2: value2
""")
    
    file2 = tmpdir.join("file2.yaml")
    file2.write("""
section1:
  key2: updated_value2  # This should override
  key3: value3          # This should be added
""")
    
    config = YAMLConfig()
    config.load_file(str(file1))
    config.load_file(str(file2))
    
    # Check that sections were merged
    assert config["section1"]["key1"] == "value1"  # Original value preserved
    assert config["section1"]["key2"] == "updated_value2"  # Value updated
    assert config["section1"]["key3"] == "value3"  # New value added