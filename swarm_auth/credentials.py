"""
P18 v3.0 - Unified Credential Access Gateway.

Single source of truth for all credential access across swarm-it repos.
Simple os.environ wrapper - no prefix required, standard variable names.

Usage:
    from swarm_auth import get_credential, get_aws_credentials, has_credential

    # Get any credential
    api_key = get_credential('OPENAI_API_KEY')

    # Get AWS credentials dict (boto3-compatible)
    aws = get_aws_credentials()
    client = boto3.client('s3', **aws)

    # Check existence
    if has_credential('ANTHROPIC_API_KEY'):
        ...
"""
import os
from typing import Optional


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

    Returns dict suitable for boto3 client initialization:
        client = boto3.client('s3', **get_aws_credentials())

    Returns:
        Dict with aws_access_key_id, aws_secret_access_key, region_name
    """
    return {
        'aws_access_key_id': get_credential('AWS_ACCESS_KEY_ID'),
        'aws_secret_access_key': get_credential('AWS_SECRET_ACCESS_KEY'),
        'region_name': get_credential('AWS_REGION', 'us-east-1'),
    }


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
