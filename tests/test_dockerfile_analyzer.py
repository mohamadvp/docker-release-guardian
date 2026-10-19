from guardian.analyzers.dockerfile_analyzer import DOCKERFILE_RULES, parse_dockerfile
from guardian.models import Finding


def run(text: str) -> list[Finding]:
    return DOCKERFILE_RULES.run(parse_dockerfile(text), file="Dockerfile")


def names(findings: list[Finding]) -> set[str | None]:
    return {f.rule_name for f in findings}


def test_parser_joins_continuation_lines_and_tracks_line_numbers() -> None:
    parsed = parse_dockerfile("FROM python:3.12\n# comment\nRUN apt-get update && \\\n    apt-get install -y curl\n")
    run_ins = [i for i in parsed.instructions if i.cmd == "RUN"][0]
    assert run_ins.line == 3
    assert "apt-get install -y curl" in run_ins.args


def test_no_user_instruction_is_flagged() -> None:
    assert "require_non_root_user" in names(run("FROM python:3.12\nCMD ['x']\n"))


def test_explicit_root_user_is_flagged() -> None:
    assert "require_non_root_user" in names(run("FROM python:3.12\nUSER root\n"))


def test_non_root_user_is_fine() -> None:
    assert "require_non_root_user" not in names(run("FROM python:3.12\nUSER app\n"))


def test_only_final_stage_user_matters() -> None:
    text = "FROM golang:1.22 AS build\nRUN go build\n\nFROM gcr.io/distroless/static:nonroot\nUSER 65532\n"
    assert "require_non_root_user" not in names(run(text))


def test_latest_and_untagged_base_images_are_flagged() -> None:
    assert "forbid_latest_tag" in names(run("FROM python:latest\nUSER app\n"))
    assert "forbid_latest_tag" in names(run("FROM python\nUSER app\n"))


def test_pinned_tag_digest_scratch_and_stage_refs_are_fine() -> None:
    text = (
        "FROM python:3.12-slim AS base\n"
        "FROM base AS final\n"
        "FROM scratch\n"
        "FROM python@sha256:" + "a" * 64 + "\n"
        "FROM registry.example.com:5000/team/app:1.2\n"
        "USER app\n"
    )
    assert "forbid_latest_tag" not in names(run(text))


def test_secret_in_env_is_flagged() -> None:
    assert "forbid_secrets_in_env" in names(run("FROM python:3.12\nENV DB_PASSWORD=hunter2\nUSER app\n"))


def test_env_without_secret_name_is_fine() -> None:
    assert "forbid_secrets_in_env" not in names(run("FROM python:3.12\nENV APP_ENV=production\nUSER app\n"))

# TODO(you): tests for forbid_add_remote_url, and for every rule you add
# (one "flagged" test and one "fine" test per rule is a good minimum).
