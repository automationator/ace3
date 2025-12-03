import asyncio
import signal
from saq.configuration.config import get_config_value_as_str
from saq.constants import CONFIG_SERVICE_CRON, CONFIG_SERVICE_CRON_CONFIG
from saq.service import ACEServiceInterface

from yacron.cron import Cron


class ACECronService(ACEServiceInterface):
    def start(self):
        cron = Cron(get_config_value_as_str(CONFIG_SERVICE_CRON, CONFIG_SERVICE_CRON_CONFIG))
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
