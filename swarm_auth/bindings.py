"""Explicit credential-plane bindings (ADR-026 Rule 8 — One Credential Access Plane).

A binding maps a *logical* credential name to the *exact* approved backing secret.
This is the authorized way to teach the plane a secret whose backing name does not
follow the default ``swarm-it/<KEY>`` convention, or whose body is a raw string
rather than the adapter's ``{"value": ...}`` JSON envelope.

Adding a platform/secret to the plane = adding a binding HERE, never consumer-side
access code. The registry carries names and purpose only — never values.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class SecretBinding:
    """A logical credential name bound to an exact backing secret reference."""

    logical_name: str
    backing: str            # exact Secrets Manager secret name or full ARN
    source: str = "aws_secrets"
    plaintext: bool = True   # True: secret body is the raw value (not {"value": ...} JSON)
    purpose: str = ""


# Registry. Explicit, auditable, expiring only by removal. Values NEVER appear here.
BINDINGS: Dict[str, SecretBinding] = {
    "CLOUDFLARE_DEPLOY_TOKEN": SecretBinding(
        logical_name="CLOUDFLARE_DEPLOY_TOKEN",
        backing="cloudflare/api-token",
        plaintext=True,
        purpose="Wrangler deploy / secret-put for the floodcaster-api Worker",
    ),
    "COMMERCE_INTERNAL_KEY_NEXT": SecretBinding(
        logical_name="COMMERCE_INTERNAL_KEY_NEXT",
        backing=(
            "arn:aws:secretsmanager:us-east-1:865679935554:secret:"
            "swarmit/internal-service-key-next-7hZbMN"
        ),
        plaintext=True,
        purpose="Rotation NEXT internal-service-key for the CERT_SERVICE_KEY migration",
    ),
    "COMMERCE_INTERNAL_KEY_CURRENT": SecretBinding(
        logical_name="COMMERCE_INTERNAL_KEY_CURRENT",
        backing="swarmit/internal-service-key",
        plaintext=True,
        purpose=(
            "Rotation ROLLBACK binding: CURRENT internal-service-key so the Commerce "
            "CERT_SERVICE_KEY cutover can be reverted through the plane (never via "
            "direct Secrets Manager access in the Commerce workflow)"
        ),
    ),
}


def get_binding(logical_name: str) -> Optional[SecretBinding]:
    """Return the binding for a logical name, or None if unbound (fail-closed upstream)."""
    return BINDINGS.get(logical_name)
