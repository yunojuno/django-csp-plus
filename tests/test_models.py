import pytest
from pydantic import ValidationError

from csp.models import CspRule, ReportData


@pytest.mark.parametrize(
    "input,output",
    [
        ("", ""),
        # add single quotes
        ("nonce", "'nonce'"),
        ("none", "'none'"),
        ("report-sample", "'report-sample'"),
        ("self", "'self'"),
        ("strict-dynamic", "'strict-dynamic'"),
        ("unsafe-eval", "'unsafe-eval'"),
        ("'unsafe-eval'", "'unsafe-eval'"),
        ("unsafe-hashes", "'unsafe-hashes'"),
        ("unsafe-inline", "'unsafe-inline'"),
        ("wasm-unsafe-eval", "'wasm-unsafe-eval'"),
        # add unsafe and single quotes
        ("inline", "'unsafe-inline'"),
        # add trailing colon
        ("data", "data:"),
        ("mediastream", "mediastream:"),
        ("blob", "blob:"),
        ("filesystem", "filesystem:"),
        # source schemes
        ("https://*.example.com", "https://*.example.com"),
        ("https://*.example.com?foo=bar", "https://*.example.com"),
        ("mail.example.com:443", "mail.example.com:443"),
        ("https://store.example.com", "https://store.example.com"),
        ("ws://example.com", "ws://example.com"),
    ],
)
def test_clean_value(input, output) -> None:
    assert CspRule.clean_value(input) == output


class TestReportData:
    def test_defaults(self) -> None:
        report = ReportData(
            **{
                "blocked-uri": "https://yunojuno-prod-assets.s3.amazonaws.com/",
                "effective-directive": "img-src",
            }
        )
        assert report.blocked_uri == "https://yunojuno-prod-assets.s3.amazonaws.com/"
        assert report.effective_directive == "img-src"

    @pytest.mark.parametrize(
        "report_data",
        [
            {},
            {"blocked_uri": "/"},
            {"effective_directive": "script-src"},
        ],
    )
    def test_mandatory_fields(self, report_data: dict) -> None:
        with pytest.raises(ValidationError):
            _ = ReportData(**report_data)
