from qdrant_client import QdrantClient

from saq.configuration.config import get_config


def get_qdrant_client():
    kwargs = {
        "url": get_config().qdrant.url
    }

    if get_config().qdrant.use_ssl:
        kwargs["https"] = True
        kwargs["verify"] = get_config().qdrant.ssl_ca_path
        # Note: SSL certificate verification is handled by the underlying HTTP client
        # The ca_certs configuration is not directly supported in qdrant-client
        kwargs["api_key"] = get_config().qdrant.api_key

    return QdrantClient(**kwargs)
