"""Project discovery and the combined static analysis entry point."""

from __future__ import annotations

from pathlib import Path

from guardian.analyzers.compose import analyze_compose
from guardian.analyzers.dockerfile_analyzer import analyze_dockerfile
from guardian.errors import ProjectError
from guardian.models import Finding

COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")


def discover(project: Path) -> tuple[list[Path], list[Path]]:
    """Find Dockerfiles and Compose files in the project root.

    TODO(you): walk subdirectories (monorepos), support `--exclude`, and ignore
    `node_modules/`, `.git/`, `venv/`. Also pick up `Dockerfile.*` and `*.Dockerfile` names.
    """
    if not project.is_dir():
        raise ProjectError(f"project path is not a directory: {project}")
    dockerfiles = [project / "Dockerfile"] if (project / "Dockerfile").is_file() else []
    composes = [project / n for n in COMPOSE_NAMES if (project / n).is_file()]
    return dockerfiles, composes


def analyze_project(project: Path) -> list[Finding]:
    dockerfiles, composes = discover(project)
    if not dockerfiles and not composes:
        raise ProjectError(f"no Dockerfile or Compose file found in {project}")
    findings: list[Finding] = []
    for path in dockerfiles:
        findings.extend(analyze_dockerfile(path))
    for path in composes:
        findings.extend(analyze_compose(path))
    return findings
