# vim: sw=4:ts=4:et
#
# ACE service wrapper for YaraScannerServer
#

import os
import os.path
from typing import Type

from pydantic import Field
from yara_scanner import YaraScannerServer

import logging

from saq.configuration import get_config
from saq.configuration.config import get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import CONFIG_YARA_SCANNER, SERVICE_YARA_SCANNER
from saq.environment import get_base_dir, get_data_dir
from saq.service import ACEServiceInterface
from saq.util import abs_path, create_directory

KNOWN_ERRORS = ['no scanners available', 'unable to process client request: [Errno 32] Broken pipe']

class YaraScannerServiceConfig(ServiceConfig):
    socket_dir: str = Field(..., description="relative directory where the unix sockets for the yara scanner server are located (relative to DATA_DIR)")
    signature_dir: str = Field(..., description="global configuration of yara rules (relative to SAQ_HOME or absolute path)")
    update_frequency: int = Field(..., description="how often to check the yara rules for changes (in seconds)")
    backlog: int = Field(..., description="parameter to the socket.listen() function (how many connections to backlog)")
    blacklist_path: str = Field(..., description="the blacklist contains a list of rule names (one per line) to exclude from the results")
    scan_failure_dir: str = Field(..., description="a directory that contains all the files that fail to scan (relative to DATA_DIR)")
    default_timeout: int = Field(..., description="how long (in seconds) a single scan is allowed to take")

class YSSService(ACEServiceInterface):

    def __init__(self):
        self.service_config = get_config().get_service_config(SERVICE_YARA_SCANNER)
        if not os.path.isdir(self.socket_dir):
            create_directory(self.socket_dir)

        self.yss_server = YaraScannerServer(
            base_dir=get_base_dir(),
            signature_dir=self.signature_dir,
            socket_dir=self.socket_dir,
            update_frequency=get_service_config(SERVICE_YARA_SCANNER).update_frequency,
            backlog=get_service_config(SERVICE_YARA_SCANNER).backlog,
            default_timeout=get_service_config(SERVICE_YARA_SCANNER).default_timeout,
        )

    def start(self):
        self.yss_server.start()
    
    def wait_for_start(self, timeout: float = 5) -> bool:
        return True
    
    def start_single_threaded(self):
        self.yss_server = YaraScannerServer(
            base_dir=get_base_dir(),
            signature_dir=self.signature_dir,
            socket_dir=self.socket_dir,
            update_frequency=self.service_config.getint('update_frequency'),
            backlog=self.service_config.getint('backlog'),
            default_timeout=self.service_config.getint('default_timeout', fallback=5),
        )

        try:
            self.yss_server.start()
            self.yss_server.wait()
        except Exception as e:
            if str(e) not in KNOWN_ERRORS:
                raise

            logging.warning(e)
    
    def stop(self):
        self.yss_server.stop()
    
    def wait(self):
        self.yss_server.wait()

    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return YaraScannerServiceConfig

    @property
    def socket_dir(self):
        return os.path.join(get_data_dir(), get_service_config(SERVICE_YARA_SCANNER).socket_dir)

    @property
    def signature_dir(self):
        return abs_path(get_service_config(SERVICE_YARA_SCANNER).signature_dir)