"""Report renderers. Each takes the same inputs and returns a string."""

from __future__ import annotations

import json

from guardian import __version__
from guardian.models import Decision, Finding

REPORT_SCHEMA_VERSION = "1"  # bump when the JSON structure changes incompatibly


def _loc(f: Finding) -> str:
    if f.file and f.line:
        return f"{f.file}:{f.line}"
    return f.file or ""


def render_text(decision: Decision) -> str:
    out: list[str] = []

    def section(title: str, findings: list[Finding]) -> None:
        if not findings:
            return
        out.append(f"\n{title} ({len(findings)})")
        out.append("-" * (len(title) + len(str(len(findings))) + 3))
        for f in sorted(findings, key=lambda x: -int(x.severity)):
            out.append(f"  [{f.severity.name:<8}] {f.id}  {f.title}")
            if f.message:
                out.append(f"             {f.message}")
            if _loc(f):
                out.append(f"             at {_loc(f)}")

    out.append(f"Docker Release Guardian {__version__}")
    section("VIOLATIONS", decision.violations)
    section("WARNINGS", decision.warnings)
    section("WAIVED", decision.waived)
    out.append("")
    out.append(
        f"Summary: {len(decision.violations)} violation(s), {len(decision.warnings)} warning(s), "
        f"{len(decision.waived)} waived, {len(decision.ignored)} ignored"
    )
    out.append("RESULT: PASS" if decision.passed else "RESULT: FAIL")
    return "\n".join(out) + "\n"


def render_json(decision: Decision) -> str:
    payload = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "tool_version": __version__,
        "passed": decision.passed,
        "summary": {
            "violations": len(decision.violations),
            "warnings": len(decision.warnings),
            "waived": len(decision.waived),
            "ignored": len(decision.ignored),
        },
        "violations": [f.model_dump(mode="json") for f in decision.violations],
        "warnings": [f.model_dump(mode="json") for f in decision.warnings],
        "waived": [f.model_dump(mode="json") for f in decision.waived],
        "ignored": [f.model_dump(mode="json") for f in decision.ignored],
    }
    return json.dumps(payload, indent=2) + "\n"


def render_markdown(decision: Decision) -> str:
    """Suited for $GITHUB_STEP_SUMMARY, so results show on the workflow run page."""
    status = "✅ PASS" if decision.passed else "❌ FAIL"
    lines = [
        "# Docker Release Guardian",
        "",
        f"**Result:** {status}  ",
        f"**Violations:** {len(decision.violations)} · **Warnings:** {len(decision.warnings)} · "
        f"**Waived:** {len(decision.waived)} · **Ignored:** {len(decision.ignored)}",
    ]

    def table(title: str, findings: list[Finding]) -> None:
        if not findings:
            return
        lines.extend(["", f"## {title}", "", "| Severity | ID | Finding | Location |", "|---|---|---|---|"])
        for f in sorted(findings, key=lambda x: -int(x.severity)):
            detail = f"{f.title}: {f.message}" if f.message else f.title
            detail = detail.replace("|", "\\|")
            lines.append(f"| {f.severity.name} | {f.id} | {detail} | {_loc(f)} |")

    table("Violations", decision.violations)
    table("Warnings", decision.warnings)
    table("Waived", decision.waived)
    return "\n".join(lines) + "\n"

RENDERERS = {
    "text": render_text,
    "json": render_json,
    "markdown": render_markdown,
}
