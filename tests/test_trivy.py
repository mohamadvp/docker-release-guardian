import pytest

from guardian.errors import ScannerError
from guardian.models import Severity
from guardian.scanners import trivy

# A trimmed example of Trivy's `--format json` output.
SAMPLE_REPORT = {
    "Results": [
        {
            "Target": "python:3.9 (debian 11)",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-0001",
                    "PkgName": "openssl",
                    "InstalledVersion": "1.1.1",
                    "FixedVersion": "1.1.2",
                    "Severity": "CRITICAL",
                    "Title": "openssl: bad things",
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-0001",
                },
                {
                    "VulnerabilityID": "CVE-2024-0002",
                    "PkgName": "zlib",
                    "InstalledVersion": "1.2",
                    "Severity": "MEDIUM",
                },
            ],
        },
        {"Target": "requirements.txt"},  # a result with no Vulnerabilities key
    ]
}


def test_parse_maps_fields_and_fixability() -> None:
    findings = trivy.parse_trivy_json(SAMPLE_REPORT)
    assert [f.id for f in findings] == ["CVE-2024-0001", "CVE-2024-0002"]
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].fixable is True
    assert findings[1].fixable is False
    assert "no fix available" in findings[1].message


def test_parse_empty_report() -> None:
    assert trivy.parse_trivy_json({}) == []
    assert trivy.parse_trivy_json({"Results": None}) == []


def test_missing_trivy_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(trivy.shutil, "which", lambda _name: None)
    with pytest.raises(ScannerError, match="not installed"):
        trivy.scan_image("python:3.12")

# TODO(you): test the subprocess handling by monkeypatching subprocess.run:
#   - non-zero exit code -> ScannerError
#   - invalid JSON on stdout -> ScannerError
#   - timeout -> ScannerError
