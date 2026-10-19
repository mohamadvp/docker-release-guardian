# Docker Release Guardian

A policy-driven DevSecOps release gate for Docker projects. It checks a project's Dockerfile and
Docker Compose files (and optionally scans an image or dependencies with Trivy) against a YAML
policy, prints a report, and returns an exit code so CI pipelines can block a bad release.

## Install

Requires Python 3.11+. Trivy is optional (only needed for `--image` and `--scan-fs`).

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
guardian --version
```

## Usage

```bash
guardian init                                   # write a starter guardian.yaml
guardian validate-policy guardian.yaml          # check the policy (also flags unknown rule names)
guardian check .                                # Dockerfile + Compose rules only
guardian check . --image myapp:1.4.0            # also scan the image with Trivy
guardian check . --scan-fs                      # also scan dependency files with Trivy
guardian check . -f json -o report.json         # formats: text | json | markdown | (sarif: TODO)
```

Try the examples (the first must fail, the second must pass):

```bash
cd examples/vulnerable-app && guardian check . ; echo "exit: $?"
cd ../secure-app && guardian check . ; echo "exit: $?"
```

Output for the vulnerable example (shortened):

```
VIOLATIONS (5)
  [CRITICAL] DG-DC-001  Service runs in privileged mode
  [CRITICAL] DG-DC-002  Docker socket is mounted into a container
  [HIGH    ] DG-DF-001  Container runs as root
  [HIGH    ] DG-DF-003  Possible secret in ENV or ARG
  [MEDIUM  ] DG-DF-002  Base image uses ':latest' or no tag
WARNINGS (2) ...
RESULT: FAIL
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Passed: no violations |
| 1 | Policy violations found (the gate says no) |
| 2 | Usage or config error: bad policy, bad path, unknown format |
| 3 | Tool error: Trivy missing, timed out, or returned invalid output |

In a Bash script or CI step: `guardian check . --image app:ci || exit 1` works as expected.

## Policy file

```yaml
version: 1
default_action: warn          # used for rules the policy does not mention

vulnerabilities:
  fail_on: [CRITICAL, HIGH]   # other severities only warn
  ignore_unfixed: true        # ignore CVEs with no fixed version

dockerfile:
  require_non_root_user: fail # off | warn | fail
  forbid_latest_tag: fail

compose:
  forbid_privileged: fail

waivers:
  - id: CVE-2024-12345
    reason: "No upstream fix; not reachable in our configuration"
    owner: your-name
    expires: 2027-01-31
```

Unknown keys are rejected on purpose, so a typo cannot silently weaken the gate.

## Architecture

```
CLI (cli.py)
  -> load + validate policy         policy.py   (Pydantic, strict)
  -> static analysis                analyzers/  (Dockerfile parser + rules, Compose rules)
  -> optional Trivy scan            scanners/trivy.py  (subprocess -> JSON -> Findings)
  -> policy engine                  engine.py   (pure: findings + policy + date -> Decision)
  -> report                         reporters.py (text / json / markdown)
```

The key idea: **everything becomes a `Finding`** (`models.py`). The engine only sees findings, so a
new rule or a new scanner never requires changing it.

```
src/guardian/
  models.py        Finding, Decision, Severity, exit codes
  policy.py        policy schema, loader, starter policy
  engine.py        evaluate(): the verdict logic
  rules.py         tiny rule registry (decorator-based)
  analyzers/       dockerfile.py, compose.py, discovery
  scanners/        trivy.py
  reporters.py     text, json, markdown
  cli.py           Typer commands: check, init, validate-policy
tests/             pytest suite
examples/          vulnerable-app (fails), secure-app (passes)
```

## How to add a rule

Write one decorated function; the registry does the rest.

```python
@DOCKERFILE_RULES.rule(
    id="DG-DF-010",
    name="require_healthcheck",            # the key used in guardian.yaml
    severity=Severity.LOW,
    title="Image has no HEALTHCHECK",
    references=["CIS Docker Benchmark 4.6"],
)
def check_healthcheck(df: ParsedDockerfile) -> list[Hit]:
    stage = df.final_stage
    if stage and not any(i.cmd == "HEALTHCHECK" for i in stage.instructions):
        return [Hit("No HEALTHCHECK in the final stage.")]
    return []
```

Then add `require_healthcheck: warn` to `DEFAULT_POLICY_YAML` (and your `guardian.yaml`), and write
tests. `guardian validate-policy` will catch a misspelled rule name.
