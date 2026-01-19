#!/usr/bin/env python3
"""Environment-aware preflight for ScanSage MCP gates."""

from __future__ import annotations

import argparse
import dataclasses
import importlib.util
import os
import shutil
import subprocess
import sys
from typing import Tuple


@dataclasses.dataclass(frozen=True)
class Capabilities:
    ensurepip: bool
    pip: bool
    setuptools: bool
    wheelhouse: bool
    docker_cli: bool
    docker_daemon: bool
    docker_message: str


@dataclasses.dataclass(frozen=True)
class PreflightContext:
    context: str
    in_venv: bool
    venv_exists: bool


@dataclasses.dataclass(frozen=True)
class Recommendation:
    path: str | None
    next_step: str | None
    notes: tuple[str, ...]


def module_available(name: str) -> bool:
    """Return True if the named module is importable."""

    return importlib.util.find_spec(name) is not None


def check_docker() -> Tuple[bool, bool, str]:
    """Check whether the Docker CLI exists and whether the daemon is reachable."""

    docker_cmd = shutil.which("docker")
    if docker_cmd is None:
        return False, False, "docker CLI missing"

    try:
        result = subprocess.run(
            [docker_cmd, "info"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return True, False, str(exc)

    if result.returncode == 0:
        return True, True, ""

    message = (result.stderr or result.stdout or "").strip()
    if not message:
        message = f"exit code {result.returncode}"
    return True, False, message


def detect_context(venv_path: str = ".venv") -> PreflightContext:
    """Detect whether the current interpreter is inside the project venv."""

    in_venv = (
        getattr(sys, "base_prefix", sys.prefix) != sys.prefix
        or os.environ.get("VIRTUAL_ENV") is not None
    )
    venv_exists = os.path.isdir(venv_path)
    context = "venv" if in_venv else "system"
    return PreflightContext(context=context, in_venv=in_venv, venv_exists=venv_exists)


def detect_capabilities() -> Capabilities:
    """Gather the boolean capabilities that influence each gate path."""

    docker_cli, docker_daemon, docker_message = check_docker()
    return Capabilities(
        ensurepip=module_available("ensurepip"),
        pip=module_available("pip"),
        setuptools=module_available("setuptools"),
        wheelhouse=os.path.isdir(".wheels"),
        docker_cli=docker_cli,
        docker_daemon=docker_daemon,
        docker_message=docker_message,
    )


def evaluate_paths(
    context: PreflightContext, capabilities: Capabilities
) -> Tuple[bool, bool, bool]:
    """Return readiness for host, offline, and docker gate paths."""

    host_ready = context.in_venv and capabilities.pip and capabilities.setuptools
    offline_ready = context.in_venv and capabilities.pip and capabilities.wheelhouse
    docker_ready = capabilities.docker_cli and capabilities.docker_daemon
    return host_ready, offline_ready, docker_ready


def _venv_creation_command(mode: str) -> str:
    return f"python -m venv .venv && .venv/bin/python preflight.py --mode {mode}"


def _venv_rerun_command(mode: str) -> str:
    return f".venv/bin/python preflight.py --mode {mode}"


def _ensurepip_command(mode: str) -> str:
    return (
        ".venv/bin/python -m ensurepip --upgrade && "
        f".venv/bin/python preflight.py --mode {mode}"
    )


def _offline_wheelhouse_command() -> str:
    return (
        "make wheelhouse (online machine), copy .wheels/ into this repo, "
        "then make offline-dev && make gate"
    )


def _setuptools_missing_command() -> str:
    return (
        "install your OS python-setuptools (and pip if needed) "
        "or build a wheelhouse (make wheelhouse, copy .wheels/, then make offline-dev"
        " && make gate)"
    )


def _docker_troubleshooting_message() -> str:
    return (
        "Docker troubleshooting: ensure the daemon is running and you can access "
        "/var/run/docker.sock (group membership/rootless) then rerun make gate-docker."
    )


def plan_recommendation(
    mode: str, context: PreflightContext, capabilities: Capabilities
) -> Recommendation:
    """Create the recommended path or next step for the requested mode."""

    host_ready, offline_ready, docker_ready = evaluate_paths(context, capabilities)

    if mode == "host":
        if host_ready:
            return Recommendation(
                path="Host dev: make dev && make gate",
                next_step=None,
                notes=(),
            )
        return Recommendation(
            path=None,
            next_step=_host_mode_next_step(context, capabilities, "host"),
            notes=_docker_notes(capabilities),
        )

    if mode == "offline":
        if offline_ready:
            return Recommendation(
                path="Offline dev: make offline-dev && make gate",
                next_step=None,
                notes=(),
            )
        return Recommendation(
            path=None,
            next_step=_offline_mode_next_step(context, capabilities),
            notes=_docker_notes(capabilities),
        )

    if mode == "docker":
        if docker_ready:
            return Recommendation(
                path="Docker gates: make gate-docker",
                next_step=None,
                notes=(),
            )
        return Recommendation(
            path=None,
            next_step=_docker_mode_next_step(capabilities),
            notes=_docker_notes(capabilities),
        )

    # mode == "any"
    if host_ready:
        return Recommendation(
            path="Host dev: make dev && make gate",
            next_step=None,
            notes=(),
        )
    if offline_ready:
        return Recommendation(
            path="Offline dev: make offline-dev && make gate",
            next_step=None,
            notes=(),
        )
    if docker_ready:
        return Recommendation(
            path="Docker gates: make gate-docker",
            next_step=None,
            notes=(),
        )
    return Recommendation(
        path=None,
        next_step=_any_mode_next_step(context, capabilities),
        notes=_docker_notes(capabilities),
    )


def _host_mode_next_step(
    context: PreflightContext, capabilities: Capabilities, mode: str
) -> str:
    if not context.in_venv:
        if context.venv_exists:
            return _venv_rerun_command(mode)
        return _venv_creation_command(mode)
    if not capabilities.pip:
        return _ensurepip_command(mode)
    if not capabilities.setuptools:
        return _setuptools_missing_command()
    return _venv_rerun_command(mode)


def _offline_mode_next_step(
    context: PreflightContext, capabilities: Capabilities
) -> str:
    if not context.in_venv:
        if context.venv_exists:
            return _venv_rerun_command("offline")
        return _venv_creation_command("offline")
    if not capabilities.pip:
        return _ensurepip_command("offline")
    if not capabilities.setuptools:
        return _setuptools_missing_command()
    if not capabilities.wheelhouse:
        return _offline_wheelhouse_command()
    return _offline_wheelhouse_command()


def _docker_mode_next_step(capabilities: Capabilities) -> str:
    if not capabilities.docker_cli:
        return (
            "install the Docker CLI and ensure it is on your PATH, "
            "then rerun make gate-docker"
        )
    if not capabilities.docker_daemon:
        return _docker_troubleshooting_message()
    return "make gate-docker"


def _any_mode_next_step(context: PreflightContext, capabilities: Capabilities) -> str:
    if not context.in_venv:
        if context.venv_exists:
            return _venv_rerun_command("any")
        return _venv_creation_command("any")
    if not capabilities.pip:
        return _ensurepip_command("any")
    if not capabilities.setuptools:
        return _setuptools_missing_command()
    if not capabilities.wheelhouse:
        return _offline_wheelhouse_command()
    return _offline_wheelhouse_command()


def _docker_notes(capabilities: Capabilities) -> tuple[str, ...]:
    if capabilities.docker_cli and not capabilities.docker_daemon:
        return (_docker_troubleshooting_message(),)
    return ()


def emit(line: str) -> None:
    """Emit a single line to stdout without using `print`."""

    sys.stdout.write(f"{line}\n")


def print_status(name: str, value: str | bool) -> None:
    """Print a stable PREFLIGHT line for automation."""

    emit(f"PREFLIGHT {name}={value}")


def main() -> None:
    """Entry point for the preflight CLI."""

    parser = argparse.ArgumentParser(description="Preflight for ScanSage MCP gates.")
    parser.add_argument(
        "--mode",
        choices=["any", "host", "offline", "docker"],
        default="any",
        help="Check that the requested path is ready.",
    )
    args = parser.parse_args()

    context = detect_context()
    capabilities = detect_capabilities()
    host_ready, offline_ready, docker_ready = evaluate_paths(context, capabilities)

    print_status("context", context.context)
    print_status("venv_path", ".venv")
    print_status("venv_exists", context.venv_exists)

    print_status("ensurepip", capabilities.ensurepip)
    print_status("pip", capabilities.pip)
    print_status("setuptools", capabilities.setuptools)
    print_status("wheelhouse", capabilities.wheelhouse)
    print_status("docker-cli", capabilities.docker_cli)
    print_status("docker-daemon", capabilities.docker_daemon)
    if capabilities.docker_message:
        emit(f"PREFLIGHT docker-message={capabilities.docker_message}")

    recommendation = plan_recommendation(args.mode, context, capabilities)

    if recommendation.path:
        emit(f"Recommended path: {recommendation.path}")
    else:
        assert recommendation.next_step is not None
        emit(f"Recommended next step: {recommendation.next_step}")
        for note in recommendation.notes:
            emit(note)

    valid_path = host_ready or offline_ready or docker_ready
    if args.mode == "any":
        exit_code = 0 if valid_path else 1
    elif args.mode == "host":
        exit_code = 0 if host_ready else 1
    elif args.mode == "offline":
        exit_code = 0 if offline_ready else 1
    else:
        exit_code = 0 if docker_ready else 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
