"""Sync local keyfile credentials to AWS Secrets Manager.

Local dev uses ``KeyfileAdapter`` (per-file ``keys/*.txt``). Production
Lambda/ECS workloads can't read from a developer laptop, so the same
values must live under AWS Secrets Manager. This module bridges the two.

Secret naming convention::

    swarmit/keyfile/<NORMALIZED_KEY>

Normalization matches :func:`KeyfileAdapter._normalize` — uppercase,
``-`` → ``_`` — so a file called ``swarmit-rapidapi-staging.txt`` lands
at the secret ID ``swarmit/keyfile/SWARMIT_RAPIDAPI_STAGING``.

Usage::

    # Dry-run first, see what would change.
    python -m swarm_auth.sync_secrets --dry-run

    # Actually push.
    python -m swarm_auth.sync_secrets

The sync:

- Creates secrets that don't exist (``CreateSecret``).
- Updates the value of secrets whose local file differs (``PutSecretValue``).
- Leaves alone any secret whose stored value already matches the file.
- **Never deletes secrets.** Stale secrets are tracked but require manual
  deletion to avoid accidentally dropping a key still used by a running
  workload.

This module is opt-in: nothing imports it implicitly. Running the
module-level CLI is always an explicit operator action.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable, List, Optional

from swarm_auth.adapters.keyfile_credential import KeyfileAdapter, _normalize

if TYPE_CHECKING:  # pragma: no cover - typing only
    import botocore  # noqa: F401


DEFAULT_SECRET_PREFIX = "swarmit/keyfile"


@dataclass
class SyncAction:
    """One planned or executed change."""

    key: str
    secret_id: str
    action: str  # "create" | "update" | "unchanged" | "error"
    detail: Optional[str] = None


def _secret_id(key: str, prefix: str = DEFAULT_SECRET_PREFIX) -> str:
    return f"{prefix}/{_normalize(key)}"


def _current_secret_value(client, secret_id: str) -> Optional[str]:
    """Return the current ``SecretString`` for ``secret_id``, or ``None`` if
    the secret doesn't exist."""
    try:
        resp = client.get_secret_value(SecretId=secret_id)
    except client.exceptions.ResourceNotFoundException:
        return None
    # ``SecretString`` is absent when the value is binary; we only manage
    # text credentials here.
    return resp.get("SecretString")


def plan_sync(
    keys_dir: Optional[str] = None,
    *,
    prefix: str = DEFAULT_SECRET_PREFIX,
    keys: Optional[Iterable[str]] = None,
    client=None,
) -> List[SyncAction]:
    """Compute what a sync would do, without making any changes.

    Args:
        keys_dir: Override the keyfile directory. ``None`` = adapter default.
        prefix: Secret-name prefix. Default: ``swarmit/keyfile``.
        keys: Restrict to a subset of normalized key names. ``None`` = all
            keys the adapter can see.
        client: Optional pre-built Secrets Manager boto3 client (test hook).

    Returns:
        One :class:`SyncAction` per key inspected.
    """
    adapter = KeyfileAdapter(keys_dir=keys_dir)
    all_keys = adapter.list_keys()
    if keys is not None:
        wanted = {_normalize(k) for k in keys}
        all_keys = [k for k in all_keys if k in wanted]

    if client is None:
        from swarm_auth.adapters.aws_credential import AWSSecretsAdapter
        client = AWSSecretsAdapter()._client

    actions: List[SyncAction] = []
    for key in sorted(all_keys):
        value = adapter.retrieve(key)
        if value is None:
            actions.append(
                SyncAction(key=key, secret_id=_secret_id(key, prefix),
                           action="error", detail="could not parse file")
            )
            continue

        sid = _secret_id(key, prefix)
        current = _current_secret_value(client, sid)
        if current is None:
            actions.append(SyncAction(key=key, secret_id=sid, action="create"))
        elif current == value:
            actions.append(SyncAction(key=key, secret_id=sid, action="unchanged"))
        else:
            actions.append(SyncAction(key=key, secret_id=sid, action="update"))

    return actions


def apply_sync(
    actions: Iterable[SyncAction],
    *,
    keys_dir: Optional[str] = None,
    client=None,
) -> List[SyncAction]:
    """Execute the planned actions. Returns actions with updated ``detail``."""
    adapter = KeyfileAdapter(keys_dir=keys_dir)

    if client is None:
        from swarm_auth.adapters.aws_credential import AWSSecretsAdapter
        client = AWSSecretsAdapter()._client

    executed: List[SyncAction] = []
    for act in actions:
        if act.action in ("unchanged", "error"):
            executed.append(act)
            continue

        value = adapter.retrieve(act.key)
        if value is None:
            executed.append(SyncAction(
                key=act.key, secret_id=act.secret_id, action="error",
                detail="could not parse file at apply time",
            ))
            continue

        try:
            if act.action == "create":
                client.create_secret(
                    Name=act.secret_id,
                    SecretString=value,
                    Description=f"swarm-auth keyfile: {act.key}",
                )
            elif act.action == "update":
                client.put_secret_value(
                    SecretId=act.secret_id,
                    SecretString=value,
                )
            executed.append(SyncAction(
                key=act.key, secret_id=act.secret_id, action=act.action,
                detail="ok",
            ))
        except Exception as exc:  # pragma: no cover - surfaces to operator
            executed.append(SyncAction(
                key=act.key, secret_id=act.secret_id, action="error",
                detail=f"{type(exc).__name__}: {exc}",
            ))
    return executed


def _format_actions(actions: Iterable[SyncAction]) -> str:
    """Human-readable summary; never includes credential values."""
    buckets: dict[str, List[SyncAction]] = {}
    for act in actions:
        buckets.setdefault(act.action, []).append(act)

    lines = []
    for action in ("create", "update", "unchanged", "error"):
        items = buckets.get(action, [])
        lines.append(f"{action}: {len(items)}")
        for it in items:
            suffix = f" — {it.detail}" if it.detail else ""
            lines.append(f"  {it.key}  →  {it.secret_id}{suffix}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sync local keyfile credentials to AWS Secrets Manager.",
    )
    parser.add_argument("--keys-dir", help="Override the keyfile directory.")
    parser.add_argument(
        "--prefix", default=DEFAULT_SECRET_PREFIX,
        help="Secret-name prefix (default: swarmit/keyfile).",
    )
    parser.add_argument(
        "--only", nargs="+", metavar="KEY",
        help="Restrict to specific keys (e.g. SWARMIT_RAPIDAPI_STAGING).",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Plan only; do not create or update any secrets.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit the action list as JSON (for scripting).",
    )
    args = parser.parse_args(argv)

    planned = plan_sync(
        keys_dir=args.keys_dir, prefix=args.prefix, keys=args.only,
    )

    if args.dry_run:
        result = planned
    else:
        result = apply_sync(planned, keys_dir=args.keys_dir)

    if args.json:
        print(json.dumps([a.__dict__ for a in result], indent=2))
    else:
        print(_format_actions(result))

    # Exit non-zero if any action errored.
    return 1 if any(a.action == "error" for a in result) else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
