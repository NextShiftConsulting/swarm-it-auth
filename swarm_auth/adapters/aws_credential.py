"""
AWS Secrets Manager Credential Adapter - AWS-native secret storage.
"""

from typing import Optional, Dict, Any
import json
from swarm_auth.ports.credential_port import CredentialPort
from swarm_auth.domain.credential import Credential


class AWSSecretsAdapter(CredentialPort):
    """
    AWS Secrets Manager credential storage adapter.

    Uses AWS Secrets Manager for secure credential storage.
    Requires: pip install boto3
    """

    def __init__(
        self,
        region_name: str = "us-east-1",
        prefix: str = "swarm-it/",
    ):
        """
        Initialize AWS Secrets Manager adapter.

        Args:
            region_name: AWS region
            prefix: Secret name prefix (default: swarm-it/)
        """
        try:
            import boto3
        except ImportError:
            raise ImportError("boto3 package required: pip install boto3")

        self._prefix = prefix
        self._client = boto3.client("secretsmanager", region_name=region_name)

    def _get_secret_id(self, key: str) -> str:
        """Get full secret ID for a key."""
        return f"{self._prefix}{key}"

    def store(
        self,
        key: str,
        value: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Credential:
        """
        Store a credential in AWS Secrets Manager.

        Args:
            key: Credential key
            value: Credential value
            metadata: Optional metadata (stored as tags)

        Returns:
            Created credential
        """
        secret_id = self._get_secret_id(key)

        # Prepare secret structure
        secret_data = {
            "value": value,
            "metadata": metadata or {},
        }

        # Convert metadata to tags
        tags = []
        if metadata:
            if "tags" in metadata:
                for tag_key, tag_value in metadata["tags"].items():
                    tags.append({"Key": tag_key, "Value": str(tag_value)})
            if "description" in metadata:
                tags.append({"Key": "Description", "Value": metadata["description"]})

        try:
            # Try to create new secret
            self._client.create_secret(
                Name=secret_id,
                SecretString=json.dumps(secret_data),
                Tags=tags,
            )
        except self._client.exceptions.ResourceExistsException:
            # Secret exists, update it
            self._client.update_secret(
                SecretId=secret_id,
                SecretString=json.dumps(secret_data),
            )

        cred = Credential.create(
            key=key,
            description=metadata.get("description") if metadata else None,
            tags=metadata.get("tags", {}) if metadata else {},
        )

        return cred

    def retrieve(self, key: str) -> Optional[str]:
        """
        Retrieve a credential from AWS Secrets Manager.

        Args:
            key: Credential key

        Returns:
            Credential value or None
        """
        secret_id = self._get_secret_id(key)

        try:
            response = self._client.get_secret_value(SecretId=secret_id)
            secret_data = json.loads(response["SecretString"])
            return secret_data.get("value")
        except self._client.exceptions.ResourceNotFoundException:
            return None
        except Exception:
            return None

    def delete(self, key: str) -> bool:
        """
        Delete a credential from AWS Secrets Manager.

        Args:
            key: Credential key

        Returns:
            True if deleted, False if not found
        """
        secret_id = self._get_secret_id(key)

        try:
            self._client.delete_secret(
                SecretId=secret_id,
                ForceDeleteWithoutRecovery=True,
            )
            return True
        except self._client.exceptions.ResourceNotFoundException:
            return False
        except Exception:
            return False

    def list_keys(self, prefix: Optional[str] = None) -> list[str]:
        """
        List credential keys.

        Args:
            prefix: Optional prefix filter

        Returns:
            List of credential keys
        """
        search_prefix = self._prefix
        if prefix:
            search_prefix = f"{self._prefix}{prefix}"

        try:
            paginator = self._client.get_paginator("list_secrets")
            keys = []

            for page in paginator.paginate():
                for secret in page["SecretList"]:
                    name = secret["Name"]
                    if name.startswith(search_prefix):
                        # Strip prefix to get original key
                        key = name[len(self._prefix):]
                        keys.append(key)

            return keys
        except Exception:
            return []

    def rotate(self, key: str, new_value: str) -> Credential:
        """
        Rotate a credential.

        AWS Secrets Manager supports rotation policies.

        Args:
            key: Credential key
            new_value: New credential value

        Returns:
            Updated credential
        """
        secret_id = self._get_secret_id(key)

        try:
            # Update secret value
            self._client.update_secret(
                SecretId=secret_id,
                SecretString=json.dumps({"value": new_value}),
            )

            # Mark as rotated
            cred = Credential.create(key=key)
            cred.rotate()
            return cred
        except Exception as e:
            raise ValueError(f"Failed to rotate credential: {e}")

    def get_metadata(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get credential metadata from AWS Secrets Manager.

        Args:
            key: Credential key

        Returns:
            Metadata dict or None
        """
        secret_id = self._get_secret_id(key)

        try:
            response = self._client.describe_secret(SecretId=secret_id)

            # Extract tags
            tags = {}
            for tag in response.get("Tags", []):
                tags[tag["Key"]] = tag["Value"]

            return {
                "key": key,
                "arn": response.get("ARN"),
                "created_date": response.get("CreatedDate").isoformat() if response.get("CreatedDate") else None,
                "last_accessed_date": response.get("LastAccessedDate").isoformat() if response.get("LastAccessedDate") else None,
                "last_changed_date": response.get("LastChangedDate").isoformat() if response.get("LastChangedDate") else None,
                "rotation_enabled": response.get("RotationEnabled", False),
                "tags": tags,
            }
        except self._client.exceptions.ResourceNotFoundException:
            return None
        except Exception:
            return None
