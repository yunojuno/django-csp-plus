# <scheme>://<netloc>/<path>;<params>?<query>#<fragment>
from urllib.parse import urlparse, urlunparse


def strip_fragment(url: str) -> str:
    """Strip the fragment from a url."""
    scheme, netloc, path, params, query, _ = urlparse(url)
    if not scheme:
        return url
    return urlunparse((scheme, netloc, path, params, query, ""))


def strip_query(url: str) -> str:
    """Strip the query, fragment from a url."""
    return url.split("?")[0] if url else url


def strip_path(url: str) -> str:
    """Strip the path, query, fragment from a url."""
    scheme, netloc, _, _, _, _ = urlparse(url)
    if not scheme:
        return url
    # scheme only - must end in ":", which urlunparse will munge
    if scheme and not netloc:
        return url
    return urlunparse((scheme, netloc, "", "", "", ""))
