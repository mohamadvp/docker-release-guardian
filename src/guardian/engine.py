"""The policy engine: findings + policy + date -> Decision."""

from __future__ import annotations

from datetime import date

from guardian.models import Decision, Finding, Severity, Source
from guardian.policy import Action, Policy, Waiver


def _action_for(finding: Finding, policy: Policy) -> Action:
    """Decide what the policy says about one finding."""
    if finding.source is Source.TRIVY:
        if finding.severity in policy.vulnerabilities.fail_on:
            return Action.FAIL
        return Action.WARN

    if finding.source is Source.DOCKERFILE:
        return policy.dockerfile.get(finding.rule_name or "", policy.default_action)
    if finding.source is Source.COMPOSE:
        return policy.compose.get(finding.rule_name or "", policy.default_action)

    # Findings created by the engine itself (expired waivers) always fail.
    return Action.FAIL


def _expired_waiver_finding(waiver: Waiver) -> Finding:
    return Finding(
        id="DG-POLICY-001",
        source=Source.POLICY,
        severity=Severity.HIGH,
        title=f"Waiver for {waiver.id} has expired",
        message=(
            f"Waiver owned by '{waiver.owner}' expired on {waiver.expires}. "
            "Fix the issue or renew the waiver with a new expiry date."
        ),
    )


def evaluate(findings: list[Finding], policy: Policy, today: date) -> Decision:
    """Apply the policy to the findings and return the verdict."""
    decision = Decision(passed=True)

    active = {w.id: w for w in policy.waivers if not w.is_expired(today)}

    # Expired waivers are violations in their own right.
    for waiver in policy.waivers:
        if waiver.is_expired(today):
            decision.violations.append(_expired_waiver_finding(waiver))

    for finding in findings:
        # 1. Policy can switch a rule off entirely.
        action = _action_for(finding, policy)
        if action is Action.OFF:
            decision.ignored.append(finding)
            continue

        # 2. Unfixable vulnerabilities are ignored when the policy says so.
        if (
            finding.source is Source.TRIVY
            and policy.vulnerabilities.ignore_unfixed
            and finding.fixable is False
        ):
            decision.ignored.append(finding)
            continue

        # 3. Accepted risks (non-expired waivers).
        if finding.id in active:
            decision.waived.append(finding)
            continue

        # 4. Everything else is a violation or a warning.
        if action is Action.FAIL:
            decision.violations.append(finding)
        else:
            decision.warnings.append(finding)

    decision.passed = not decision.violations
    return decision
