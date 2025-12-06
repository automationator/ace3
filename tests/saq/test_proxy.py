import pytest

from saq.configuration.config import get_config
from saq.configuration.schema import ProxyConfig
from saq.proxy import proxies

INVALID_KEY = "WrongKey"

@pytest.mark.unit
def test_wrong_key_raises():
    with pytest.raises(ValueError):
        proxy = proxies(INVALID_KEY)

@pytest.mark.unit
def test_proxy_config(monkeypatch):
    mock_proxy_config = ProxyConfig(name="default", transport="http", host="proxy.local", port=3128)
    get_config().clear_proxy_configs()
    get_config().add_proxy_config("default", mock_proxy_config)
    monkeypatch.setattr(get_config().global_settings, "default_proxy", "default")

    assert proxies() == {
        'http': 'http://proxy.local:3128',
        'https': 'http://proxy.local:3128',
    }

    mock_proxy_config.user = "ace"
    mock_proxy_config.password = "1234"

    assert proxies() == {
        'http': 'http://ace:1234@proxy.local:3128',
        'https': 'http://ace:1234@proxy.local:3128',
    }
