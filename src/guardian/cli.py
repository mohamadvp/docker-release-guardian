"""Command line interface. This module only wires things together; no logic lives here."""

from __future__ import annotations

import sys
from datetime import date
from pathlib import Path
from typing import Annotated

import typer

from guardian import __version__
from guardian.analyzers import analyze_project
from guardian.analyzers.compose import COMPOSE_RULES
from guardian.analyzers.dockerfile_analyzer import DOCKERFILE_RULES
from guardian.engine import evaluate
from guardian.errors import PolicyError, ProjectError, ScannerError
from guardian.models import (
    EXIT_PASS,
    EXIT_POLICY_FAIL,
    EXIT_TOOL_ERROR,
    EXIT_USAGE_ERROR,
    Finding,
)
from guardian.policy import DEFAULT_POLICY_YAML, load_policy
from guardian.reporters import RENDERERS
from guardian.scanners import trivy

app = typer.Typer(
    help="A policy-driven release gate for Docker projects.",
    no_args_is_help=True,
    add_completion=False,
)


def _err(message: str) -> None:
    typer.echo(message, err=True)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version_callback, is_eager=True)
    ] = False,
) -> None:
    """Docker Release Guardian."""

@app.command()
def init(
    path: Annotated[Path, typer.Argument(help="Where to write the policy.")] = Path("guardian.yaml"),
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing file.")] = False,
) -> None:
    """Write a starter policy file."""
    if path.exists() and not force:
        _err(f"error: {path} already exists (use --force to overwrite)")
        raise typer.Exit(EXIT_USAGE_ERROR)
    path.write_text(DEFAULT_POLICY_YAML, encoding="utf-8")
    typer.echo(f"Wrote starter policy to {path}")

@app.command()
def check(
    project: Annotated[Path, typer.Argument(help="Path to the project to check.")] = Path("."),
    policy: Annotated[Path, typer.Option("--policy", "-p", help="Policy file.")] = Path(
        "guardian.yaml"
    ),
    image: Annotated[
        str | None, typer.Option("--image", help="Also scan this image with Trivy.")
    ] = None,
    scan_fs: Annotated[
        bool, typer.Option("--scan-fs", help="Also scan project dependency files with Trivy.")
    ] = False,
    fmt: Annotated[
        str, typer.Option("--format", "-f", help="text | json | markdown")
    ] = "text",
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the report to a file.")
    ] = None,
) -> None:
    """Check a Docker project against a policy. Exit: 0 pass, 1 fail, 2 usage, 3 tool error."""
    if fmt not in RENDERERS:
        _err(f"error: unknown format '{fmt}'. Choose from: {', '.join(RENDERERS)}")
        raise typer.Exit(EXIT_USAGE_ERROR)

    try:
        loaded_policy = load_policy(policy)
        findings: list[Finding] = analyze_project(project)
        if image:
            findings.extend(trivy.scan_image(image))
        if scan_fs:
            findings.extend(trivy.scan_filesystem(project))
    except (PolicyError, ProjectError) as exc:
        _err(f"error: {exc}")
        raise typer.Exit(EXIT_USAGE_ERROR) from exc
    except ScannerError as exc:
        _err(f"scanner error: {exc}")
        raise typer.Exit(EXIT_TOOL_ERROR) from exc

    decision = evaluate(findings, loaded_policy, today=date.today())

    try:
        report = RENDERERS[fmt](decision)
    except NotImplementedError as exc:
        _err(f"error: format '{fmt}' is not implemented yet ({exc})")
        raise typer.Exit(EXIT_USAGE_ERROR) from exc

    if output:
        output.write_text(report, encoding="utf-8")
        typer.echo(f"Report written to {output}", err=True)
    else:
        sys.stdout.write(report)

    raise typer.Exit(EXIT_PASS if decision.passed else EXIT_POLICY_FAIL)

@app.command("validate-policy")
def validate_policy(
    policy: Annotated[Path, typer.Argument(help="Policy file to validate.")] = Path("guardian.yaml"),
) -> None:
    """Validate a policy file and warn about unknown rule names."""
    try:
        loaded = load_policy(policy)
    except PolicyError as exc:
        _err(f"error: {exc}")
        raise typer.Exit(EXIT_USAGE_ERROR) from exc

    problems = [
        f"unknown dockerfile rule: {name}"
        for name in loaded.dockerfile
        if name not in DOCKERFILE_RULES.rules
    ] + [
        f"unknown compose rule: {name}" for name in loaded.compose if name not in COMPOSE_RULES.rules
    ]
    for problem in problems:
        _err(f"warning: {problem}")
    typer.echo(f"{policy}: valid ({len(loaded.waivers)} waiver(s))")
    # A typo'd rule name silently does nothing, so treat it as an error.
    raise typer.Exit(EXIT_USAGE_ERROR if problems else EXIT_PASS)


if __name__ == "__main__":
    app()
