"""Docker Compose analyzer: YAML parsing plus a few service-level security rules."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from guardian.errors import ProjectError
from guardian.models import Finding, Severity, Source
from guardian.rules import Hit, Registry

COMPOSE_RULES = Registry(Source.COMPOSE)

DOCKER_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock")
_DANGEROUS_CAPABILITIES = {"ALL", "SYS_ADMIN", "NET_ADMIN"}
_SECRET_NAME = re.compile(r"(password|passwd|secret|token|api[_-]?key|private[_-]?key)", re.I)
_DATABASE_IMAGE = re.compile(
    r"(?:^|/)(?:postgres(?:ql)?|mysql|mariadb|mongo(?:db)?|redis|cassandra|"
    r"elasticsearch)(?:[:@]|$)",
    re.I,
)


def _services(compose: dict[str, Any]) -> dict[str, dict[str, Any]]:
    services = compose.get("services") or {}
    return {k: v for k, v in services.items() if isinstance(v, dict)}


@COMPOSE_RULES.rule(
    id="DG-DC-001",
    name="forbid_privileged",
    severity=Severity.CRITICAL,
    title="Service runs in privileged mode",
    references=["CIS Docker Benchmark 5.4"],
)
def check_privileged(compose: dict[str, Any]) -> list[Hit]:
    return [
        Hit(f"Service '{name}' sets privileged: true (full access to host devices).")
        for name, svc in _services(compose).items()
        if svc.get("privileged") is True
    ]


@COMPOSE_RULES.rule(
    id="DG-DC-002",
    name="forbid_docker_socket_mount",
    severity=Severity.CRITICAL,
    title="Docker socket is mounted into a container",
    references=["CIS Docker Benchmark 5.31", "OWASP Docker Security Cheat Sheet: RULE #1"],
)
def check_docker_socket(compose: dict[str, Any]) -> list[Hit]:
    hits: list[Hit] = []
    for name, svc in _services(compose).items():
        for volume in svc.get("volumes") or []:
            # Short syntax: "/host:/container[:mode]"; long syntax: {type, source, target}
            if isinstance(volume, str):
                source = volume.split(":")[0]
            elif isinstance(volume, dict):
                source = str(volume.get("source", ""))
            else:
                continue
            if source in DOCKER_SOCKETS:
                hits.append(
                    Hit(
                        f"Service '{name}' mounts the Docker socket; "
                        "a compromise of the container means root on the host."
                    )
                )
    return hits


@COMPOSE_RULES.rule(
    id="DG-DC-003",
    name="forbid_host_network",
    severity=Severity.HIGH,
    title="Service uses the host network namespace",
    references=["CIS Docker Benchmark 5.9"],
)
def check_host_network(compose: dict[str, Any]) -> list[Hit]:
    return [
        Hit(f"Service '{name}' uses network_mode: host (no network isolation).")
        for name, svc in _services(compose).items()
        if svc.get("network_mode") == "host"
    ]


@COMPOSE_RULES.rule(
    id="DG-DC-004",
    name="forbid_dangerous_capabilities",
    severity=Severity.HIGH,
    title="Service adds a dangerous Linux capability",
    references=["CIS Docker Benchmark 5.3"],
)
def check_dangerous_capabilities(compose: dict[str, Any]) -> list[Hit]:
    hits: list[Hit] = []
    for name, svc in _services(compose).items():
        capabilities = svc.get("cap_add") or []
        if isinstance(capabilities, str):
            capabilities = [capabilities]
        for capability in capabilities:
            if str(capability).upper().removeprefix("CAP_") in _DANGEROUS_CAPABILITIES:
                hits.append(Hit(f"Service '{name}' adds dangerous capability {capability}."))
    return hits


@COMPOSE_RULES.rule(
    id="DG-DC-005",
    name="forbid_secrets_in_environment",
    severity=Severity.HIGH,
    title="Possible secret is set in the environment",
    references=["OWASP Docker Security Cheat Sheet: RULE #12"],
)
def check_secrets_in_environment(compose: dict[str, Any]) -> list[Hit]:
    hits: list[Hit] = []
    for name, svc in _services(compose).items():
        environment = svc.get("environment") or {}
        entries = environment.items() if isinstance(environment, dict) else (
            entry.split("=", 1) for entry in environment if isinstance(entry, str) and "=" in entry
        )
        for key, value in entries:
            # Unset values and Compose interpolation are sourced at runtime, not literals.
            if _SECRET_NAME.search(str(key)) and value is not None and "${" not in str(value):
                hits.append(Hit(f"Service '{name}' sets possible secret '{key}' as a literal environment value."))
    return hits


@COMPOSE_RULES.rule(
    id="DG-DC-006",
    name="require_healthcheck",
    severity=Severity.MEDIUM,
    title="Service has no healthcheck",
)
def check_healthcheck(compose: dict[str, Any]) -> list[Hit]:
    return [
        Hit(f"Service '{name}' has no enabled healthcheck.")
        for name, svc in _services(compose).items()
        if not isinstance(svc.get("healthcheck"), dict) or svc["healthcheck"].get("disable") is True
    ]


@COMPOSE_RULES.rule(
    id="DG-DC-007",
    name="require_resource_limits",
    severity=Severity.MEDIUM,
    title="Service has no resource limits",
)
def check_resource_limits(compose: dict[str, Any]) -> list[Hit]:
    hits: list[Hit] = []
    for name, svc in _services(compose).items():
        deploy = svc.get("deploy")
        resources = deploy.get("resources") if isinstance(deploy, dict) else None
        limits = resources.get("limits") if isinstance(resources, dict) else None
        if not limits and not svc.get("mem_limit"):
            hits.append(Hit(f"Service '{name}' has neither deploy.resources.limits nor mem_limit."))
    return hits


def _is_database_service(name: str, svc: dict[str, Any]) -> bool:
    image = svc.get("image")
    return bool(_DATABASE_IMAGE.search(str(image))) or bool(
        re.search(r"(?:db|database|postgres|mysql|mariadb|mongo|redis|cassandra)", name, re.I)
    )


def _is_wide_port_binding(port: Any) -> bool:
    if isinstance(port, dict):
        return port.get("published") is not None and port.get("host_ip", "0.0.0.0") in {"0.0.0.0", "::"}
    if not isinstance(port, str):
        return False
    parts = port.split(":")
    if len(parts) == 2:  # HOST_PORT:CONTAINER_PORT
        return True
    return len(parts) >= 3 and parts[-3] in {"0.0.0.0", "::"}


@COMPOSE_RULES.rule(
    id="DG-DC-008",
    name="forbid_wide_port_binding",
    severity=Severity.HIGH,
    title="Database is published on all network interfaces",
    references=["CIS Docker Benchmark 5.5"],
)
def check_wide_port_binding(compose: dict[str, Any]) -> list[Hit]:
    return [
        Hit(f"Database service '{name}' publishes a port on all network interfaces.")
        for name, svc in _services(compose).items()
        if _is_database_service(name, svc) and any(_is_wide_port_binding(port) for port in svc.get("ports") or [])
    ]


@COMPOSE_RULES.rule(
    id="DG-DC-009",
    name="forbid_latest_image",
    severity=Severity.MEDIUM,
    title="Service image uses ':latest' or no tag",
    references=["CIS Docker Benchmark 4.7"],
)
def check_latest_image(compose: dict[str, Any]) -> list[Hit]:
    hits: list[Hit] = []
    for name, svc in _services(compose).items():
        image = svc.get("image")
        if not isinstance(image, str) or not image or "$" in image or "@sha256:" in image:
            continue
        name_part = image.rsplit("/", 1)[-1]
        tag = name_part.split(":", 1)[1] if ":" in name_part else None
        if tag is None:
            hits.append(Hit(f"Service '{name}' image '{image}' has no tag (defaults to latest)."))
        elif tag.lower() == "latest":
            hits.append(Hit(f"Service '{name}' image '{image}' uses the ':latest' tag."))
    return hits


@COMPOSE_RULES.rule(
    id="DG-DC-010",
    name="require_read_only_rootfs",
    severity=Severity.MEDIUM,
    title="Service root filesystem is writable",
    references=["CIS Docker Benchmark 5.12"],
)
def check_read_only_rootfs(compose: dict[str, Any]) -> list[Hit]:
    return [
        Hit(f"Service '{name}' does not set read_only: true.")
        for name, svc in _services(compose).items()
        if svc.get("read_only") is not True
    ]


def analyze_compose(path: Path) -> list[Finding]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ProjectError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ProjectError(f"{path}: not a valid Compose file (top level must be a mapping)")
    return COMPOSE_RULES.run(data, file=str(path))
