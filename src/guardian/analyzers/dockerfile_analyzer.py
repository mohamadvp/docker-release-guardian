"""Dockerfile analyzer: a small parser plus a handful of security rules."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from guardian.models import Finding, Severity, Source
from guardian.rules import Hit, Registry

DOCKERFILE_RULES = Registry(Source.DOCKERFILE)


@dataclass
class Instruction:
    line: int  # 1-based line where the instruction starts
    cmd: str  # upper-cased, e.g. "FROM"
    args: str  # the rest of the (joined) line


@dataclass
class Stage:
    from_line: int
    image: str
    name: str | None
    instructions: list[Instruction] = field(default_factory=list)


@dataclass
class ParsedDockerfile:
    instructions: list[Instruction]
    stages: list[Stage]

    @property
    def final_stage(self) -> Stage | None:
        return self.stages[-1] if self.stages else None


def parse_dockerfile(text: str) -> ParsedDockerfile:
    instructions: list[Instruction] = []
    buffer = ""
    start_line = 0

    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if not buffer:
            start_line = lineno
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        buffer += stripped
        cmd, _, args = buffer.partition(" ")
        instructions.append(Instruction(start_line, cmd.upper(), args.strip()))
        buffer = ""

    if buffer:  # file ended in the middle of a continuation
        cmd, _, args = buffer.partition(" ")
        instructions.append(Instruction(start_line, cmd.upper(), args.strip()))

    stages: list[Stage] = []
    for ins in instructions:
        if ins.cmd == "FROM":
            parts = [p for p in ins.args.split() if not p.startswith("--")]  # skip --platform=
            image = parts[0] if parts else ""
            name = parts[2] if len(parts) >= 3 and parts[1].upper() == "AS" else None
            stages.append(Stage(ins.line, image, name))
        elif stages:
            stages[-1].instructions.append(ins)

    return ParsedDockerfile(instructions, stages)


# rules


@DOCKERFILE_RULES.rule(
    id="DG-DF-001",
    name="require_non_root_user",
    severity=Severity.HIGH,
    title="Container runs as root",
    references=["CIS Docker Benchmark 4.1"],
)
def check_non_root_user(df: ParsedDockerfile) -> list[Hit]:
    stage = df.final_stage
    if stage is None:
        return []
    # Only the FINAL stage matters: earlier build stages never run in production.
    users = [i for i in stage.instructions if i.cmd == "USER"]
    if not users:
        return [Hit("No USER instruction in the final stage; the container runs as root.")]
    last = users[-1]
    user = last.args.split(":")[0].strip().lower()
    if user in {"root", "0"}:
        return [Hit("The final USER is root.", line=last.line)]
    return []


@DOCKERFILE_RULES.rule(
    id="DG-DF-002",
    name="forbid_latest_tag",
    severity=Severity.MEDIUM,
    title="Base image uses ':latest' or no tag",
    references=["CIS Docker Benchmark 4.7"],
)
def check_latest_tag(df: ParsedDockerfile) -> list[Hit]:
    hits: list[Hit] = []
    stage_names = {s.name.lower() for s in df.stages if s.name}
    for stage in df.stages:
        image = stage.image
        if not image or image.lower() == "scratch" or image.lower() in stage_names:
            continue
        if "$" in image:  # tag comes from an ARG; cannot be judged statically
            continue
        if "@sha256:" in image:  # pinned by digest is fine
            continue
        # The tag is whatever follows the last ':' that is after the last '/'.
        name_part = image.rsplit("/", 1)[-1]
        tag = name_part.split(":", 1)[1] if ":" in name_part else None
        if tag is None:
            hits.append(Hit(f"Base image '{image}' has no tag (defaults to latest).", stage.from_line))
        elif tag.lower() == "latest":
            hits.append(Hit(f"Base image '{image}' uses the ':latest' tag.", stage.from_line))
    return hits


_SECRET_NAME = re.compile(r"(password|passwd|secret|token|api[_-]?key|private[_-]?key)", re.I)


@DOCKERFILE_RULES.rule(
    id="DG-DF-003",
    name="forbid_secrets_in_env",
    severity=Severity.HIGH,
    title="Possible secret in ENV or ARG",
    references=["OWASP Docker Security Cheat Sheet: RULE #12"],
)
def check_secrets_in_env(df: ParsedDockerfile) -> list[Hit]:
    hits: list[Hit] = []
    for ins in df.instructions:
        if ins.cmd not in {"ENV", "ARG"}:
            continue
        # Handles both `ENV KEY=value other=value` and legacy `ENV KEY value`.
        first = ins.args.split()[0] if ins.args.split() else ""
        names = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=", ins.args) or [first.split("=")[0]]
        for name in names:
            has_value = "=" in ins.args or len(ins.args.split()) > 1
            if _SECRET_NAME.search(name) and has_value:
                hits.append(
                    Hit(
                        f"{ins.cmd} {name} looks like a secret baked into the image. "
                        "Use build secrets or runtime secrets instead.",
                        ins.line,
                    )
                )
    return hits


@DOCKERFILE_RULES.rule(
    id="DG-DF-004",
    name="forbid_add_remote_url",
    severity=Severity.MEDIUM,
    title="ADD fetches a remote URL",
    references=["CIS Docker Benchmark 4.9"],
)
def check_add_remote_url(df: ParsedDockerfile) -> list[Hit]:
    return [
        Hit("ADD with a URL is unverified; use curl/wget with a checksum check.", ins.line)
        for ins in df.instructions
        if ins.cmd == "ADD" and re.search(r"\bhttps?://", ins.args)
    ]


@DOCKERFILE_RULES.rule(
    id="DG-DF-005",
    name="require_pinned_base_image",
    severity=Severity.HIGH,
    title="Base image is not pinned by digest",
    references=["CIS Docker Benchmark 4.7"],
)
def check_pinned_base_image(df: ParsedDockerfile) -> list[Hit]:
    stage_names = {stage.name.lower() for stage in df.stages if stage.name}
    return [
        Hit(f"Base image '{stage.image}' is not pinned by digest.", stage.from_line)
        for stage in df.stages
        if stage.image
        and stage.image.lower() != "scratch"
        and stage.image.lower() not in stage_names
        and "$" not in stage.image
        and "@sha256:" not in stage.image
    ]


@DOCKERFILE_RULES.rule(
    id="DG-DF-006",
    name="require_healthcheck",
    severity=Severity.LOW,
    title="Image has no healthcheck",
    references=["CIS Docker Benchmark 4.6"],
)
def check_healthcheck(df: ParsedDockerfile) -> list[Hit]:
    stage = df.final_stage
    if stage and not any(ins.cmd == "HEALTHCHECK" for ins in stage.instructions):
        return [Hit("No HEALTHCHECK instruction in the final stage.", stage.from_line)]
    return []


@DOCKERFILE_RULES.rule(
    id="DG-DF-007",
    name="forbid_curl_pipe_sh",
    severity=Severity.HIGH,
    title="Downloaded script is piped to a shell",
    references=["OWASP Docker Security Cheat Sheet: RULE #9"],
)
def check_curl_pipe_sh(df: ParsedDockerfile) -> list[Hit]:
    pattern = re.compile(r"\b(?:curl|wget)\b[^|]*\|\s*(?:\S+\s+)*(?:sh|bash)\b", re.I)
    return [
        Hit("Do not pipe curl or wget output directly to a shell; verify the download first.", ins.line)
        for ins in df.instructions
        if ins.cmd == "RUN" and pattern.search(ins.args)
    ]


@DOCKERFILE_RULES.rule(
    id="DG-DF-008",
    name="require_apt_cleanup",
    severity=Severity.MEDIUM,
    title="apt package cache is not cleaned up",
    references=["Dockerfile best practices"],
)
def check_apt_cleanup(df: ParsedDockerfile) -> list[Hit]:
    return [
        Hit("apt-get install should remove /var/lib/apt/lists/* in the same RUN instruction.", ins.line)
        for ins in df.instructions
        if ins.cmd == "RUN"
        and re.search(r"\bapt-get\s+install\b", ins.args)
        and not re.search(r"\brm\s+-[^\n]*\brf\b\s+/var/lib/apt/lists/\*", ins.args)
    ]


_PACKAGE_INSTALL = re.compile(r"\b(?:apt(?:-get)?\s+install|apk\s+add|yum\s+install|dnf\s+install)\b", re.I)


@DOCKERFILE_RULES.rule(
    id="DG-DF-009",
    name="forbid_sudo",
    severity=Severity.MEDIUM,
    title="sudo is installed in the image",
    references=["CIS Docker Benchmark 4.1"],
)
def check_sudo(df: ParsedDockerfile) -> list[Hit]:
    return [
        Hit("Do not install sudo in a container image.", ins.line)
        for ins in df.instructions
        if ins.cmd == "RUN" and _PACKAGE_INSTALL.search(ins.args) and re.search(r"\bsudo\b", ins.args)
    ]


@DOCKERFILE_RULES.rule(
    id="DG-DF-010",
    name="forbid_ssh",
    severity=Severity.MEDIUM,
    title="SSH server is installed in the image",
    references=["CIS Docker Benchmark 4.1"],
)
def check_ssh(df: ParsedDockerfile) -> list[Hit]:
    return [
        Hit("Do not install an SSH server in a container image.", ins.line)
        for ins in df.instructions
        if ins.cmd == "RUN"
        and _PACKAGE_INSTALL.search(ins.args)
        and re.search(r"\b(?:openssh-server|sshd)\b", ins.args, re.I)
    ]


def analyze_dockerfile(path: Path) -> list[Finding]:
    parsed = parse_dockerfile(path.read_text(encoding="utf-8", errors="replace"))
    return DOCKERFILE_RULES.run(parsed, file=str(path))
