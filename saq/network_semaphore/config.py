from pydantic import Field
from saq.configuration.schema import ServiceConfig

class NetworkSemaphoreConfig(ServiceConfig):
    bind_address: str = Field(..., description="the address to bind the network semaphore server to")
    bind_port: int = Field(..., description="the port to bind the network semaphore server to")
    remote_address: str = Field(..., description="the address of the network semaphore server to the clients that want to use them")
    remote_port: int = Field(..., description="the port of the network semaphore server to the clients that want to use them")
    allowed_ipv4: list[str] = Field(..., description="the comma separated list of source IP addresses that are allowed to connect")
    stats_dir: str = Field(..., description="the directory that contains metrics and current status of semaphores")
    semaphore_capacity_limits: dict[str, int] = Field(..., description="the SEMAPHORE CAPACITY LIMITS")