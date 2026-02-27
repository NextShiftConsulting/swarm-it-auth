"""
Environment Variable Credential Adapter - Simple env-based credential storage.

WARNING: For development only. Credentials are not encrypted.
Use Vault or AWS Secrets Manager in production.
"""

import os
from typing import Optional, Dict, Any
from swarm_auth.ports.credential_port import CredentialPort
from swarm_auth.domain.credential import Credential


class EnvCredentialAdapter(CredentialPort):
    """
    Environment variable-based credential storage.

    Reads from environment variables. Useful for local development.
    NOT SECURE for production use.
    """

    def __init__(self, prefix: str = "SWARM_"):
        """
        Initialize env credential adapter.

        Args:
            prefix: Prefix for environment variables (default SWARM_)
        """
        self._prefix = prefix
        self._metadata: Dict[str, Credential] = {}

    def _env_key(self, key: str) -> str:
        """Convert credential key to env var name."""
        return f"{self._prefix}{key.upper()}"

    def store(
        self,
        key: str,
        value: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Credential:
        """
        Store a credential in environment.

        Args:
            key: Credential key
            value: Credential value
            metadata: Optional metadata

        Returns:
            Created credential
        """
        env_key = self._env_key(key)
        os.environ[env_key] = value

        cred = Credential.create(key=key)
        if metadata:
            cred.tags = metadata.get("tags", {})
            cred.description = metadata.get("description")
            cred.rotation_policy = metadata.get("rotation_policy")

        self._metadata[key] = cred
        return cred

    def retrieve(self, key: str) -> Optional[str]:
        """
        Retrieve a credential from environment.

        Args:
            key: Credential key

        Returns:
            Credential value or None
        """
        env_key = self._env_key(key)
        value = os.environ.get(env_key)

        if value and key in self._metadata:
            self._metadata[key].record_access()

        return value

    def delete(self, key: str) -> bool:
        """
        Delete a credential from environment.

        Args:
            key: Credential key

        Returns:
            True if deleted, False if not found
        """
        env_key = self._env_key(key)

        if env_key not in os.environ:
            return False

        del os.environ[env_key]
        if key in self._metadata:
            del self._metadata[key]

        return True

    def list_keys(self, prefix: Optional[str] = None) -> list[str]:
        """
        List credential keys.

        Args:
            prefix: Optional prefix filter

        Returns:
            List of credential keys
        """
        keys = []
        search_prefix = self._env_key(prefix) if prefix else self._prefix

        for env_key in os.environ:
            if env_key.startswith(search_prefix):
                # Strip prefix to get original key
                key = env_key[len(self._prefix):].lower()
                keys.append(key)

        return keys

    def rotate(self, key: str, new_value: str) -> Credential:
        """
        Rotate a credential.

        Args:
            key: Credential key
            new_value: New credential value

        Returns:
            Updated credential
        """
        env_key = self._env_key(key)
        os.environ[env_key] = new_value

        if key in self._metadata:
            cred = self._metadata[key]
            cred.rotate()
        else:
            cred = Credential.create(key=key)
            self._metadata[key] = cred

        return cred

    def get_metadata(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get credential metadata.

        Args:
            key: Credential key

        Returns:
            Metadata dict or None
        """
        cred = self._metadata.get(key)
        if not cred:
            # Check if credential exists in env
            if self._env_key(key) not in os.environ:
                return None
            # Create minimal metadata
            return {"key": key, "exists": True}

        return cred.to_dict()
