from typing import Any

from guardian.analyzers.compose import COMPOSE_RULES
from guardian.models import Finding


def run(compose: dict[str, Any]) -> set[str | None]:
    findings: list[Finding] = COMPOSE_RULES.run(compose, file="docker-compose.yml")
    return {f.rule_name for f in findings}


def test_privileged_service_is_flagged() -> None:
    assert "forbid_privileged" in run({"services": {"web": {"privileged": True}}})


def test_docker_socket_short_and_long_syntax_are_flagged() -> None:
    short = {"services": {"a": {"volumes": ["/var/run/docker.sock:/var/run/docker.sock"]}}}
    long = {"services": {"a": {"volumes": [{"type": "bind", "source": "/var/run/docker.sock", "target": "/s"}]}}}
    assert "forbid_docker_socket_mount" in run(short)
    assert "forbid_docker_socket_mount" in run(long)


def test_host_network_is_flagged() -> None:
    assert "forbid_host_network" in run({"services": {"web": {"network_mode": "host"}}})


def test_clean_service_has_no_findings() -> None:
    assert run({"services": {"web": {"image": "nginx:1.27", "volumes": ["./data:/data"]}}}) == set()


def test_empty_or_service_less_compose_does_not_crash() -> None:
    assert run({}) == set()
    assert run({"services": None}) == set()

# TODO(you): tests for each new Compose rule you add.
