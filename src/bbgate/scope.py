"""Scope resolution: the one place in the gate allowed to run a subprocess.

Two modes. `none` answers ok for everything and says so in the reason, which
keeps the tool usable for someone who has no scope engine of their own. `command`
shells out to whatever the project configured and reads a verdict off stdout.
"""
from __future__ import annotations

import json
import shlex
import subprocess
from typing import Callable

from .config import Config

TIMEOUT_SECONDS = 60

Resolver = Callable[[str, str], dict]


def permissive(host: str, program: str = "") -> dict:
    """Answer ok for every host, recording that no engine was consulted.

    The reason string is surfaced by the CLI, so a project running without a
    scope engine can see that check_7 is not actually checking anything.
    """
    return {
        "host": host,
        "verdict": "ok",
        "reasons": ["no scope engine configured"],
    }


def _unknown(host: str) -> dict:
    return {
        "host": host,
        "verdict": "unknown",
        "reasons": ["scope engine did not return a usable verdict"],
    }


def command_resolver(command: str) -> Resolver:
    """Build a resolver that runs `command` and parses its stdout as JSON.

    The template is split into argv first and the placeholders are filled in per
    argument afterwards, so a hostname containing spaces or quotes lands in one
    argv slot instead of becoming extra arguments. There is no shell in the path
    and never should be.

    Any failure at all (timeout, non-zero exit that printed nothing parseable,
    JSON without a verdict, a command that is not there) answers unknown, which
    routes to HOLD. A scope engine that broke must not be able to produce a pass.
    """
    try:
        template = shlex.split(command)
    except ValueError:
        # Unbalanced quotes in the configured command. Empty argv means every
        # call answers unknown rather than the tool dying at import time.
        template = []

    def resolve(host: str, program: str = "") -> dict:
        if not template:
            return _unknown(host)
        argv = [part.replace("{host}", host).replace("{program}", program)
                for part in template]
        try:
            # check=False: a non-zero exit is not an error here. The verdict
            # is read off stdout, and anything unreadable answers unknown below.
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=TIMEOUT_SECONDS,
                check=False,
            )
            data = json.loads(proc.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError, ValueError):
            return _unknown(host)
        if not isinstance(data, dict) or not str(data.get("verdict") or "").strip():
            return _unknown(host)
        return data

    return resolve


def resolver(cfg: Config) -> Resolver:
    """Pick the resolver a config asks for, falling back to permissive."""
    if cfg.scope_mode == "command" and cfg.scope_command:
        return command_resolver(cfg.scope_command)
    return permissive
