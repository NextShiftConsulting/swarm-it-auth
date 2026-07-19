"""
P18 v3.0 - Unified Credential Access Gateway (DEPRECATED).

.. deprecated:: 0.2.0
    This module is deprecated. Use AccessScript from swarm_auth.access_script instead.
    Only get_aws_credentials() remains exported for boto3 convenience.
    Will be removed in v0.3.0.

Migration:
    # Old (deprecated)
    from swarm_auth.credentials import get_credential, has_credential

    # New (P18 v4.0)
    from swarm_auth import get_credential, has_credential  # Now from access_script

Legacy usage (still works but deprecated):
    from swarm_auth import get_aws_credentials
    aws = get_aws_credentials()
    client = boto3.client('s3', **aws)
"""
import os
import warnings
from typing import Optional

warnings.warn(
    "swarm_auth.credentials is deprecated. Use swarm_auth.access_script instead. "
    "Only get_aws_credentials() is still exported from the main package.",
    DeprecationWarning,
    stacklevel=2,
)


def get_credential(key: str, default: Optional[str] = None) -> Optional[str]:
    """
    Get any credential by key.

    Simple os.environ wrapper. Use standard variable names:
    - OPENAI_API_KEY
    - ANTHROPIC_API_KEY
    - MIMO_API_KEY
    - AWS_ACCESS_KEY_ID
    - AWS_SECRET_ACCESS_KEY
    - AWS_REGION

    Args:
        key: Environment variable name (e.g., 'OPENAI_API_KEY')
        default: Default value if not found

    Returns:
        Credential value or default
    """
    return os.environ.get(key, default)


def get_aws_credentials() -> dict:
    """
    Get AWS credentials dict for boto3.

    Returns dict suitable for boto3 client kwargs:
        client = boto3.client('s3', region_name='us-east-1', **get_aws_credentials())

    Returns:
        Dict with explicit keys if found, otherwise empty dict.
    """
    access_key = get_credential('AWS_ACCESS_KEY_ID')
    secret_key = get_credential('AWS_SECRET_ACCESS_KEY')
    if access_key and secret_key:
        creds = {
            'aws_access_key_id': access_key,
            'aws_secret_access_key': secret_key,
        }
        # Temporary credentials (Lambda/STS/assumed role) also require the session
        # token; omitting it produces INCOMPLETE creds -> auth failure. Permanent
        # IAM-user keys have none, so include only when present.
        session_token = get_credential('AWS_SESSION_TOKEN')
        if session_token:
            creds['aws_session_token'] = session_token
        return creds
    return {}


def has_credential(key: str) -> bool:
    """
    Check if credential exists (is set and non-empty).

    Args:
        key: Environment variable name

    Returns:
        True if credential exists and is non-empty
    """
    value = get_credential(key)
    return value is not None and value != ''
