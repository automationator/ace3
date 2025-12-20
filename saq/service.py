import importlib
import logging
import threading
from typing import Protocol, Type


from saq.configuration.config import get_config, get_service_config
from saq.configuration.schema import ServiceConfig

class ACEServiceInterface(Protocol):
    def start(self):
        ...

    def wait_for_start(self, timeout: float = 5) -> bool:
        ...

    def start_single_threaded(self):
        ...

    def stop(self):
        ...

    def wait(self):
        ...

    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        ...

class DisabledService(ACEServiceInterface):
    """This is a placeholder service that is used to indicate that a service is disabled by configuration.
    It is used to prevent the service from being started if it is disabled by configuration."""

    def __init__(self):
        self.shutdown_event = threading.Event()

    def start(self):
        pass

    def wait_for_start(self, timeout: float = 5) -> bool:
        return True

    def start_single_threaded(self):
        pass

    def stop(self):
        self.shutdown_event.set()

    def wait(self):
        while not self.shutdown_event.is_set():
            self.shutdown_event.wait()

    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return ServiceConfig

def _get_service_section_name(service_name: str) -> str:
    return f"service_{service_name}"

def service_valid_for_instance(name: str) -> bool:
    """Returns True if the service (specified by name) is valud for the current instance type.
    NOTE if the service does not have any instance types configured, then it is valid for all instance types."""

    instance_type = get_config().global_settings.instance_type

    valid_service_instance_types = get_config().get_service_config(name).instance_types
    if not valid_service_instance_types:
        return True

    return "ANY" in valid_service_instance_types or instance_type in valid_service_instance_types

def service_enabled(name: str) -> bool:
    """Returns True if the service (specified by name) is enabled, False otherwise."""
    return get_service_config(name).enabled
        
def load_service(_module: str, _class: str) -> ACEServiceInterface:
    module = importlib.import_module(_module)
    class_definition = getattr(module, _class)
    return class_definition()

def load_service_by_name(name: str) -> ACEServiceInterface:
    if not service_valid_for_instance(name):
        logging.info(f"service {name} is not valid for the current instance type")
        return DisabledService()

    if not service_enabled(name):
        logging.info(f"service {name} is disabled by configuration")
        return DisabledService()

    service_config = get_service_config(name)
    return load_service(service_config.python_module, service_config.python_class)
