import sys
from typing import Any, Optional

from saq.configuration.loader import load_configuration
from saq.configuration.schema import ACEConfig

# global configuration singleton (YAML-backed)
CONFIG = None

CONFIG_V2: Optional[ACEConfig] = None

def config_section_exists(section_name: str) -> bool:
    """Returns True if the given configuration section exists."""
    return section_name in get_config()

def get_config():
    """Returns the global configuration object (YAMLConfig)."""
    return CONFIG

def get_config_value(section: str, name: str, default: Optional[Any] = None) -> Optional[Any]:
    """Returns the configuration value for the given section and name as the type it is stored as.
    If the section or name does not exist, the default value is returned."""
    cfg = get_config()
    if section not in cfg:
        return default

    section_proxy = cfg[section]
    value = section_proxy.get(name, default)
    if value is None:
        return default

    return value

def get_config_value_as_str(section: str, name: str, default: Optional[Any] = None) -> Optional[str]:
    """Returns the configuration value for the given section and name as a string.
    If the section or name does not exist, the default value is returned."""
    cfg = get_config()
    if section not in cfg:
        return default

    value = cfg[section].get(name, default)
    if value is None:
        return default

    return value if isinstance(value, str) else str(value)

def get_config_value_as_int(section: str, name: str, default: Optional[Any] = None) -> Optional[int]:
    """Returns the configuration value for the given section and name as an integer.
    If the section or name does not exist, the default value is returned."""
    cfg = get_config()
    if section not in cfg:
        return default

    section_proxy = cfg[section]
    if hasattr(section_proxy, 'getint'):
        try:
            return section_proxy.getint(name, default)  # type: ignore[attr-defined]
        except Exception:
            return default

    value = section_proxy.get(name, None) if hasattr(section_proxy, 'get') else None
    if value is None:
        return default
    if isinstance(value, int):
        return value

    try:
        return int(str(value).strip())
    except Exception:
        return default

def get_config_value_as_boolean(section: str, name: str, default: Optional[Any] = None) -> Optional[bool]:
    """Returns the configuration value for the given section and name as a boolean.
    If the section or name does not exist, the default value is returned."""
    cfg = get_config()
    if section not in cfg:
        return default

    section_proxy = cfg[section]
    if hasattr(section_proxy, 'getboolean'):
        try:
            return section_proxy.getboolean(name, default)  # type: ignore[attr-defined]
        except Exception:
            return default

    value = section_proxy.get(name, None) if hasattr(section_proxy, 'get') else None
    if value is None:
        return default

    if isinstance(value, bool):
        return value

    s = str(value).strip().lower()
    if s in {"1", "true", "yes", "on"}:
        return True

    if s in {"0", "false", "no", "off"}:
        return False

    return default

def get_config_value_as_list(section: str, name: str, default: Optional[list[str]] = None, sep: Optional[str] = ",", include_empty: Optional[bool] = True) -> Optional[list[str]]:
    """Returns the configuration value for the given section and name as a list of strings separated by sep.
    If the section or name does not exist, the default value is returned.
    The optional include_empty parameter controls whether empty strings are included in the result."""

    cfg = get_config()
    if section not in cfg:
        return default

    section_proxy = cfg[section]
    value = section_proxy.get(name, None) if hasattr(section_proxy, 'get') else None
    if value is None:
        return default

    if isinstance(value, list):
        result = [str(v).strip() for v in value]
        return result if include_empty else [v for v in result if v]

    s = str(value)
    parts = [_.strip() for _ in s.split(sep)] if sep is not None else [s]
    return parts if include_empty else [p for p in parts if p]

def set_config(config):
    global CONFIG
    CONFIG = config

def initialize_configuration(config_paths: Optional[list[str]]=None):
    global CONFIG
    global CONFIG_V2

    # load configuration files
    if config_paths is None:
        config_paths = []
    
    try:
        CONFIG = load_configuration(config_paths=config_paths)
        CONFIG_V2 = ACEConfig.model_validate(CONFIG._data)
    except Exception as e:
        sys.stderr.write(f"ERROR: unable to load configuration: {e}")
        raise

def get_config_v2() -> ACEConfig:
    """Returns the global configuration object (ACEConfig)."""
    if CONFIG_V2 is None:
        raise RuntimeError("Configuration not loaded")

    return CONFIG_V2