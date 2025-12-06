# vim: sw=4:ts=4:et
#
# ACE proxy settings

from typing import Optional
import urllib
from saq.configuration.config import get_config, get_proxy_config

def proxies(proxy_name: Optional[str] = None) -> dict[str, str]:
    """Returns the current proxy settings pulled from the configuration.
       Parameters:
       key - a key to select a proxy other than the default globally configured one
       Returns a dict in the following format. ::

    {
        'http': 'url',
        'https': 'url'
    }
"""
    result = {}
    if proxy_name is None:
        proxy_name = get_config().global_settings.default_proxy

    if proxy_name is None:
        return result

    config = get_proxy_config(proxy_name)

    if config is not None:
        for proxy_key in [ 'http', 'https' ]:
            if config.host and config.port and config.transport:
                if config.user and config.password:
                    result[proxy_key] = '{}://{}:{}@{}:{}'.format(
                        config.transport, 
                        urllib.parse.quote_plus(config.user), 
                        urllib.parse.quote_plus(config.password), 
                        config.host, 
                        config.port)
                else:
                    result[proxy_key] = '{}://{}:{}'.format(config.transport, 
                                                            config.host, 
                                                            config.port)

    return result
