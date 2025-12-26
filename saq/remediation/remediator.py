from abc import ABC, abstractmethod
import importlib
from typing import Optional

from saq.configuration.schema import RemediatorConfig
from saq.remediation.types import RemediationAction, RemediationWorkItem, RemediatorResult


class Remediator(ABC):
    def __init__(self, config: RemediatorConfig):
        self.config = config

    @property
    def observable_type(self) -> str:
        return self.config.observable_type

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def display_name(self) -> str:
        return self.config.display_name

    @property
    def description(self) -> str:
        return self.config.description

    def remediate(self, target: RemediationWorkItem) -> RemediatorResult:
        if target.action == RemediationAction.REMOVE:
            return self.remove(target)
        elif target.action == RemediationAction.RESTORE:
            return self.restore(target)
        else:
            raise ValueError(f"invalid action: {target.action}")

    @abstractmethod
    def remove(self, target: RemediationWorkItem) -> RemediatorResult:
        pass

    @abstractmethod
    def restore(self, target: RemediationWorkItem) -> RemediatorResult:
        pass

def load_remediator_from_config(config: RemediatorConfig) -> Remediator:
    """Returns a Remediator instance as defined by a RemediatorConfig."""
    module = importlib.import_module(config.python_module)
    class_definition = getattr(module, config.python_class)
    return class_definition(config)

def get_remediator_by_name(name: str) -> Remediator:
    from saq.configuration import get_config
    for remediator_config in get_config().remediators:
        if remediator_config.name == name:
            return load_remediator_from_config(remediator_config)

    raise ValueError(f"remediator {name} not found")
