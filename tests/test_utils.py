import pytest

from csp.utils import strip_path


@pytest.mark.parametrize(
    "input,output",
    [
        # no scheme - so return as-is
        ("example.com", "example.com"),
        ("*.example.com", "*.example.com"),
        ("example.com/api/", "example.com/api/"),
        # scheme and netloc - strip path
        (
            "https://*.example.com:12/path/to/file.js",
            "https://*.example.com:12",
        ),
        ("http://example.com/file.js", "http://example.com"),
        (
            "https://example.com/file.js/file2.js",
            "https://example.com",
        ),
        # scheme only - do not convert to "scheme://"
        ("https:", "https:"),
        ("data:", "data:"),
        ("wss:", "wss:"),
        ("blob:", "blob:"),
    ],
)
def test_strip_path(input: str, output: str) -> None:
    assert strip_path(input) == output
