#!/usr/bin/env python3
"""swarm-auth run — generic process-local credential presentation primitive.

ADR-026 Rule 8 (One Credential Access Plane). This command resolves LOGICAL
credential names through `swarm_auth`, presents them to a single child process
only (as environment variables and/or on stdin), runs the command, and exits.

It knows NOTHING about any platform (Cloudflare, Stripe, GitHub, ...). Platform
deployment workflows live in their own repos and call THIS primitive; they never
resolve secrets themselves. Adding a platform never touches this file.

Usage:
    python -m swarm_auth.cli.run \\
        --env CLOUDFLARE_API_TOKEN=CLOUDFLARE_DEPLOY_TOKEN \\
        --stdin COMMERCE_INTERNAL_KEY_NEXT \\
        -- wrangler secret put CERT_SERVICE_KEY

Guarantees:
  - credential VALUES never appear in argv, logs, errors, or this process's env;
  - the child receives injected vars only in its own environment copy;
  - the parent environment is unchanged after the run;
  - fail-closed: if any logical name does not resolve, the command does not run.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

# Minimal non-secret environment a typical CLI/runtime (node, wrangler, python)
# needs to start. Deliberately excludes anything credential-shaped: the parent
# operator shell's other secrets are NOT forwarded unless explicitly requested.
BASE_ENV_ALLOWLIST = frozenset({
    "PATH", "PATHEXT", "HOME", "HOMEDRIVE", "HOMEPATH", "USERPROFILE",
    "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
    "TEMP", "TMP", "TMPDIR", "SystemRoot", "SystemDrive", "windir", "ComSpec",
    "LANG", "LC_ALL", "LC_CTYPE", "TERM", "SHELL", "TZ",
    "NUMBER_OF_PROCESSORS", "OS", "PROCESSOR_ARCHITECTURE",
    "NODE_PATH", "NVM_DIR",
})


def _resolve(logical_name: str) -> Optional[str]:
    """Resolve a logical credential name through the plane (value never logged)."""
    from swarm_auth import get_credential

    return get_credential(logical_name, None)


def _parse_env_specs(specs: List[str]) -> List[Tuple[str, str]]:
    """Parse ``TOOL_VAR=LOGICAL_NAME`` specs into (tool_var, logical_name) pairs."""
    out: List[Tuple[str, str]] = []
    for spec in specs:
        if "=" not in spec:
            raise ValueError(f"--env expects TOOL_VAR=LOGICAL_NAME, got: {spec!r}")
        tool_var, logical = spec.split("=", 1)
        if not tool_var or not logical:
            raise ValueError(f"--env expects TOOL_VAR=LOGICAL_NAME, got: {spec!r}")
        out.append((tool_var, logical))
    return out


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="swarm-auth run",
        description="Resolve credentials via swarm_auth and present them to one child process.",
    )
    parser.add_argument(
        "--env", action="append", default=[], metavar="TOOL_VAR=LOGICAL_NAME",
        help="Inject the resolved LOGICAL_NAME into the child env as TOOL_VAR (repeatable).",
    )
    parser.add_argument(
        "--stdin", metavar="LOGICAL_NAME", default=None,
        help="Resolve LOGICAL_NAME and write its value to the child's stdin.",
    )
    parser.add_argument(
        "--inherit", action="append", default=[], metavar="VAR",
        help="Also pass through this specific parent env var (repeatable). "
             "By default only a minimal non-secret allowlist is inherited.",
    )
    parser.add_argument(
        "--inherit-all", action="store_true",
        help="Inherit the FULL parent environment (explicit opt-in; may forward "
             "unrelated operator-shell credentials — use only when required).",
    )
    parser.add_argument(
        "command", nargs=argparse.REMAINDER,
        help="The command to run, after `--`.",
    )
    args = parser.parse_args(argv)

    # Strip a leading `--` separator from the command remainder.
    cmd = args.command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("swarm-auth run: no command given (expected `-- <cmd> ...`)", file=sys.stderr)
        return 2

    try:
        env_specs = _parse_env_specs(args.env)
    except ValueError as e:
        print(f"swarm-auth run: {e}", file=sys.stderr)
        return 2

    # --- Build the child environment: minimal non-secret allowlist by default,
    # so unrelated operator-shell credentials are NOT forwarded. --inherit adds
    # named vars; --inherit-all opts into the full parent env explicitly. ---
    if args.inherit_all:
        child_env: Dict[str, str] = dict(os.environ)
    else:
        # Case-insensitive allowlist: Windows stores vars as `Path`, `Temp`, etc.
        allow_upper = {a.upper() for a in BASE_ENV_ALLOWLIST}
        child_env = {k: v for k, v in os.environ.items() if k.upper() in allow_upper}
        for var in args.inherit:
            if var in os.environ:  # os.environ lookup is case-insensitive on Windows
                child_env[var] = os.environ[var]

    # --- Resolve everything up front; fail closed before running anything. ---
    resolved_names: List[str] = []

    for tool_var, logical in env_specs:
        value = _resolve(logical)
        if value is None:
            print(f"swarm-auth run: credential '{logical}' did not resolve on the plane "
                  f"(fail-closed; command not run)", file=sys.stderr)
            return 3
        child_env[tool_var] = value
        resolved_names.append(f"{logical}->${tool_var}")
        del value

    stdin_value: Optional[str] = None
    if args.stdin is not None:
        stdin_value = _resolve(args.stdin)
        if stdin_value is None:
            print(f"swarm-auth run: credential '{args.stdin}' did not resolve on the plane "
                  f"(fail-closed; command not run)", file=sys.stderr)
            return 3
        resolved_names.append(f"{args.stdin}->stdin")

    # Audit metadata: names + destinations only. NEVER values.
    print(f"swarm-auth run: presenting [{', '.join(resolved_names) or 'none'}] "
          f"to `{cmd[0]}` (values redacted)", file=sys.stderr)

    try:
        proc = subprocess.run(
            cmd,
            env=child_env,
            input=stdin_value if stdin_value is not None else None,
            text=True,
        )
        return proc.returncode
    except FileNotFoundError:
        print(f"swarm-auth run: command not found: {cmd[0]!r}", file=sys.stderr)
        return 127
    finally:
        # Best-effort scrub of local references; parent os.environ was never modified.
        child_env.clear()
        stdin_value = None


if __name__ == "__main__":
    raise SystemExit(main())
