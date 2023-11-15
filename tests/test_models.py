import pytest
from pydantic import ValidationError

from csp.models import CspReportBlacklist, CspRule, ReportData


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
def test_clean_value(input: str, output: str) -> None:  # noqa: A002
    assert CspRule.clean_value(input) == output


class TestReportData:
    def test_defaults(self) -> None:
        report = ReportData(
            **{
                "blocked-uri": "https://example.com",
                "effective-directive": "img-src",
            }
        )
        assert report.blocked_uri == "https://example.com"
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

    @pytest.mark.parametrize(
        "input,output",
        [
            ("inline", "inline"),
            ("'eval'", "'eval'"),
            ("https://example.com", "https://example.com"),
            ("https://example.com/", "https://example.com/"),
            ("https://example.com/foo/", "https://example.com/foo/"),
            ("https://example.com/foo/?bar", "https://example.com/foo/"),
            ("https://example.com:80/foo/?bar", "https://example.com:80/foo/"),
        ],
    )
    def test_blocked_uri(self, input: str, output: str) -> None:  # noqa: A002
        data = ReportData(effective_directive="img-src", blocked_uri=input)
        assert data.blocked_uri == output

    def test_directive_replacement(self) -> None:
        # effective_directive is empty, so violated_directive is injected
        # in as a replacement
        data = ReportData(blocked_uri="/", violated_directive="img-src")
        assert data.effective_directive == "img-src"

    def test_directive_validation(self) -> None:
        # effective_directive is empty, so violated_directive is injected
        # in as a replacement
        with pytest.raises(ValidationError):
            _ = ReportData(blocked_uri="/")


@pytest.mark.django_db
class TestBlacklist:
    def get_blacklist_dict(self) -> dict:
        return CspReportBlacklist.objects.all().order_by("id").as_dict()

    def test_queryset_as_dict(self) -> None:
        assert self.get_blacklist_dict() == {}
        CspReportBlacklist.objects.create(directive="img-src", blocked_uri="inline")
        assert self.get_blacklist_dict() == {"img-src": ["inline"]}
        CspReportBlacklist.objects.create(
            directive="img-src", blocked_uri="http://example.com"
        )
        assert self.get_blacklist_dict() == {
            "img-src": ["inline", "http://example.com"]
        }
        CspReportBlacklist.objects.create(
            directive="font-src", blocked_uri="https://google.com"
        )
        assert self.get_blacklist_dict() == {
            "img-src": ["inline", "http://example.com"],
            "font-src": ["https://google.com"],
        }
