#!/usr/bin/env python3
"""
env_to_secrets.py — Migrate environment variables to AWS Secrets Manager.

Usage:
    # From env var name:
    python -m swarm_auth.cli.env_to_secrets JINA_API_KEY --secret-name jina-api-key

    # From direct value:
    python -m swarm_auth.cli.env_to_secrets --value "jina_xxx" --secret-name jina-api-key

    # With custom region:
    python -m swarm_auth.cli.env_to_secrets JINA_API_KEY --secret-name jina-api-key --region us-west-2
"""

import argparse
import os
import sys


def migrate_to_secrets(
    value: str,
    secret_name: str,
    region: str = "us-east-1",
    prefix: str = "",
) -> bool:
    """
    Store a value in AWS Secrets Manager.

    Args:
        value: The secret value to store
        secret_name: Name for the secret in Secrets Manager
        region: AWS region
        prefix: Optional prefix for secret name

    Returns:
        True if successful
    """
    from swarm_auth.adapters.aws_credential import AWSSecretsAdapter

    adapter = AWSSecretsAdapter(region_name=region, prefix=prefix)

    try:
        cred = adapter.store(
            key=secret_name,
            value=value,
            metadata={"description": f"Migrated from env var"},
        )
        print(f"[OK] Secret '{prefix}{secret_name}' created/updated in {region}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to create secret: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Migrate environment variable to AWS Secrets Manager"
    )
    parser.add_argument(
        "env_var",
        nargs="?",
        help="Environment variable name to read from",
    )
    parser.add_argument(
        "--value",
        help="Direct value (instead of reading from env var)",
    )
    parser.add_argument(
        "--secret-name",
        required=True,
        help="Secret name in AWS Secrets Manager",
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region (default: us-east-1)",
    )
    parser.add_argument(
        "--prefix",
        default="",
        help="Prefix for secret name (default: none)",
    )

    args = parser.parse_args()

    # Get value from env var or direct input
    if args.value:
        value = args.value
    elif args.env_var:
        value = os.environ.get(args.env_var)
        if not value:
            print(f"[ERROR] Environment variable '{args.env_var}' not set", file=sys.stderr)
            sys.exit(1)
    else:
        print("[ERROR] Either env_var or --value is required", file=sys.stderr)
        sys.exit(1)

    # Migrate to Secrets Manager
    success = migrate_to_secrets(
        value=value,
        secret_name=args.secret_name,
        region=args.region,
        prefix=args.prefix,
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
