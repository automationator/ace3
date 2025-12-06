import sys
from typing import TYPE_CHECKING, Any, Optional

from saq.configuration.loader import load_configuration
from saq.configuration.schema import ACEConfig
from saq.constants import DB_ACE, SERVICE_ENGINE

if TYPE_CHECKING:
    from saq.engine.core import EngineServiceConfig
    from saq.modules.config import AnalysisModuleConfig
    from saq.configuration.schema import ServiceConfig, SplunkConfig, ProxyConfig, DatabaseConfig

# parsed and validated configuration
CONFIG: Optional[ACEConfig] = None

def get_config() -> ACEConfig:
    """Returns the global configuration object (YAMLConfig)."""
    return CONFIG

def get_database_config(name: str=DB_ACE) -> "DatabaseConfig":
    return get_config().get_database_config(name)

def get_engine_config() -> "EngineServiceConfig":
    return get_config().get_service_config(SERVICE_ENGINE)

def get_analysis_module_config(name: str) -> "AnalysisModuleConfig":
    return get_config().get_analysis_module_config(name)

def get_service_config(name: str) -> "ServiceConfig":
    return get_config().get_service_config(name)

def get_splunk_config(name: Optional[str] = None) -> "SplunkConfig":
    return get_config().get_splunk_config(name)

def get_proxy_config(name: Optional[str] = None) -> "ProxyConfig":
    return get_config().get_proxy_config(name)

def set_config(config):
    global CONFIG
    CONFIG = config

def resolve_configuration(existing_config: ACEConfig):
    global CONFIG
    existing_config.resolve_all_values()
    CONFIG = ACEConfig.model_validate(existing_config.raw._data)
    CONFIG.raw = existing_config.raw

def initialize_configuration(config_paths: Optional[list[str]]=None):
    global CONFIG

    # load configuration files
    if config_paths is None:
        config_paths = []
    
    try:
        raw_config = load_configuration(config_paths=config_paths)
        CONFIG = ACEConfig.model_validate(raw_config._data)
        CONFIG.raw = raw_config
    except Exception as e:
        sys.stderr.write(f"ERROR: unable to load configuration: {e}")
        raise
