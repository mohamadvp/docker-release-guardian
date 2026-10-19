from datetime import date

from guardian.engine import evaluate
from guardian.models import Finding, Severity, Source
from guardian.policy import Action, Policy, VulnerabilityPolicy, Waiver

TODAY = date(2026, 10, 17)


def vuln(id_: str = "CVE-2024-0001", severity: Severity = Severity.HIGH, fixable: bool = True) -> Finding:
    return Finding(id=id_, source=Source.TRIVY, severity=severity, title="vuln", fixable=fixable)


def df_finding(rule_name: str = "require_non_root_user") -> Finding:
    return Finding(
        id="DG-DF-001",
        source=Source.DOCKERFILE,
        severity=Severity.HIGH,
        title="root",
        rule_name=rule_name,
    )


def test_no_findings_passes() -> None:
    assert evaluate([], Policy(), TODAY).passed


def test_high_vulnerability_fails_by_default() -> None:
    decision = evaluate([vuln(severity=Severity.HIGH)], Policy(), TODAY)
    assert not decision.passed
    assert len(decision.violations) == 1


def test_low_vulnerability_only_warns() -> None:
    decision = evaluate([vuln(severity=Severity.LOW)], Policy(), TODAY)
    assert decision.passed
    assert len(decision.warnings) == 1


def test_unfixed_vulnerability_is_ignored_when_configured() -> None:
    policy = Policy(vulnerabilities=VulnerabilityPolicy(ignore_unfixed=True))
    decision = evaluate([vuln(fixable=False)], policy, TODAY)
    assert decision.passed
    assert len(decision.ignored) == 1


def test_unfixed_vulnerability_fails_when_not_ignored() -> None:
    policy = Policy(vulnerabilities=VulnerabilityPolicy(ignore_unfixed=False))
    assert not evaluate([vuln(fixable=False)], policy, TODAY).passed


def test_dockerfile_rule_fail_warn_off() -> None:
    finding = df_finding()
    assert not evaluate([finding], Policy(dockerfile={"require_non_root_user": Action.FAIL}), TODAY).passed
    warn = evaluate([finding], Policy(dockerfile={"require_non_root_user": Action.WARN}), TODAY)
    assert warn.passed and len(warn.warnings) == 1
    off = evaluate([finding], Policy(dockerfile={"require_non_root_user": Action.OFF}), TODAY)
    assert off.passed and len(off.ignored) == 1


def test_unlisted_rule_uses_default_action() -> None:
    policy = Policy(default_action=Action.FAIL)
    assert not evaluate([df_finding("some_unlisted_rule")], policy, TODAY).passed


def test_active_waiver_suppresses_violation() -> None:
    waiver = Waiver(id="CVE-2024-0001", reason="not reachable", owner="me", expires=date(2026, 12, 1))
    decision = evaluate([vuln()], Policy(waivers=[waiver]), TODAY)
    assert decision.passed
    assert len(decision.waived) == 1


def test_waiver_for_other_id_does_not_apply() -> None:
    waiver = Waiver(id="CVE-2099-9999", reason="unrelated", owner="me", expires=date(2026, 12, 1))
    assert not evaluate([vuln()], Policy(waivers=[waiver]), TODAY).passed


def test_expired_waiver_fails_even_with_no_findings() -> None:
    waiver = Waiver(id="CVE-2024-0001", reason="was fine once", owner="me", expires=date(2026, 1, 1))
    decision = evaluate([], Policy(waivers=[waiver]), TODAY)
    assert not decision.passed
    assert decision.violations[0].id == "DG-POLICY-001"


def test_waiver_expires_exactly_after_its_date() -> None:
    waiver = Waiver(id="CVE-2024-0001", reason="on the last day", owner="me", expires=TODAY)
    assert evaluate([vuln()], Policy(waivers=[waiver]), TODAY).passed  # still valid today
    assert not evaluate([vuln()], Policy(waivers=[waiver]), date(2026, 10, 18)).passed

# TODO(you): more engine tests
#   - the same finding matched by a waiver AND set to `off` (which bucket should it land in?)
#   - multiple waivers, some expired, some active
#   - decision ordering / determinism
