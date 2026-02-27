"""
Credential Port - Interface for secure credential storage.

Implementations:
- VaultCredentialAdapter: HashiCorp Vault
- AWSSecretsAdapter: AWS Secrets Manager
- EnvCredentialAdapter: Environment variables (dev only)
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from swarm_auth.domain.credential import Credential


class CredentialPort(ABC):
    """Port: Secure credential storage and retrieval."""

    @abstractmethod
    def store(self, key: str, value: str, metadata: Optional[Dict[str, Any]] = None) -> Credential:
        """
        Store a credential securely.

        Args:
            key: Credential identifier (e.g., "openai_api_key")
            value: Credential value (encrypted at rest)
            metadata: Optional metadata (tags, rotation policy, etc.)

        Returns:
            Created credential
        """
        pass

    @abstractmethod
    def retrieve(self, key: str) -> Optional[str]:
        """
        Retrieve a credential value.

        Args:
            key: Credential identifier

        Returns:
            Decrypted credential value, or None if not found
        """
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        """
        Delete a credential.

        Args:
            key: Credential identifier

        Returns:
            True if deleted, False if not found
        """
        pass

    @abstractmethod
    def list_keys(self, prefix: Optional[str] = None) -> list[str]:
        """
        List credential keys (not values).

        Args:
            prefix: Optional prefix filter (e.g., "openai_")

        Returns:
            List of credential keys
        """
        pass

    @abstractmethod
    def rotate(self, key: str, new_value: str) -> Credential:
        """
        Rotate a credential (store new value, keep version history).

        Args:
            key: Credential identifier
            new_value: New credential value

        Returns:
            Updated credential
        """
        pass

    @abstractmethod
    def get_metadata(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get credential metadata without retrieving the value.

        Args:
            key: Credential identifier

        Returns:
            Metadata dict, or None if not found
        """
        pass
