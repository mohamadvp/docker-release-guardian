"""Trivy adapter: run Trivy, parse its JSON, return normalized Findings."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from guardian.errors import ScannerError
from guardian.models import Finding, Severity, Source

TRIVY_TIMEOUT_SECONDS = 600


def parse_trivy_json(data: dict[str, Any]) -> list[Finding]:
    """Convert Trivy's JSON report into Findings. Pure function: easy to unit-test."""
    findings: list[Finding] = []
    for result in data.get("Results") or []:
        target = result.get("Target")
        for vuln in result.get("Vulnerabilities") or []:
            pkg = vuln.get("PkgName", "?")
            installed = vuln.get("InstalledVersion", "?")
            fixed = vuln.get("FixedVersion") or ""
            refs = [vuln["PrimaryURL"]] if vuln.get("PrimaryURL") else []
            findings.append(
                Finding(
                    id=vuln.get("VulnerabilityID", "UNKNOWN"),
                    source=Source.TRIVY,
                    severity=Severity.parse(vuln.get("Severity", "")),
                    title=vuln.get("Title") or vuln.get("VulnerabilityID", "Vulnerability"),
                    message=(
                        f"{pkg} {installed}"
                        + (f" (fixed in {fixed})" if fixed else " (no fix available)")
                    ),
                    file=target,
                    fixable=bool(fixed),
                    references=refs,
                )
            )
        for secret in result.get("Secrets") or []:
            rule_id = secret.get("RuleID", "UNKNOWN")
            findings.append(
                Finding(
                    id=rule_id,
                    source=Source.TRIVY,
                    severity=Severity.parse(secret.get("Severity", "")),
                    title=secret.get("Title") or rule_id,
                    message=secret.get("Category") or "Potential secret detected",
                    file=target,
                    line=secret.get("StartLine"),
                )
            )
    return findings


def _run_trivy(args: list[str]) -> list[Finding]:
    if shutil.which("trivy") is None:
        raise ScannerError(
            "Trivy is not installed or not on PATH. "
            "Install it from https://trivy.dev or run without --image/--scan-fs."
        )
    cmd = ["trivy", *args, "--format", "json", "--quiet"]
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv list, no shell
            cmd, capture_output=True, text=True, timeout=TRIVY_TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(f"Trivy timed out after {TRIVY_TIMEOUT_SECONDS}s") from exc
    except OSError as exc:
        raise ScannerError(f"could not run Trivy: {exc}") from exc

    # Trivy exits 0 on a successful scan even when vulnerabilities exist (we did not pass
    # --exit-code). So any non-zero exit means Trivy itself failed.
    if proc.returncode != 0:
        raise ScannerError(f"Trivy failed (exit {proc.returncode}): {proc.stderr.strip()[:500]}")
    try:
        return parse_trivy_json(json.loads(proc.stdout))
    except json.JSONDecodeError as exc:
        raise ScannerError("Trivy produced output that is not valid JSON") from exc


def scan_image(image: str) -> list[Finding]:
    """Scan a container image (local or remote) for OS and library vulnerabilities."""
    return _run_trivy(["image", "--scanners", "vuln", image])


def scan_filesystem(path: Path) -> list[Finding]:
    """Scan project dependency files and source files for vulnerabilities and secrets."""
    return _run_trivy(["fs", "--scanners", "vuln,secret", str(path)])
