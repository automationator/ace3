import asyncio
import signal
from typing import Type

from pydantic import Field
from saq.configuration.config import get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import SERVICE_CRON
from saq.service import ACEServiceInterface

from yacron.cron import Cron

class ACECronConfig(ServiceConfig):
    cron_config_path: str = Field(..., description="the path to the cron configuration file")


class ACECronService(ACEServiceInterface):
    def start(self):
        cron = Cron(get_service_config(SERVICE_CRON).cron_config_path)
        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGINT, cron.signal_shutdown)
        loop.add_signal_handler(signal.SIGTERM, cron.signal_shutdown)
        try:
            loop.run_until_complete(cron.run())
        finally:
            loop.remove_signal_handler(signal.SIGINT)
            loop.remove_signal_handler(signal.SIGTERM)

    def wait_for_start(self, timeout: float = 5) -> bool:
        return True

    def start_single_threaded(self):
        return self.start()

    def stop(self):
        pass

    def wait(self):
        pass

    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return ACECronConfig