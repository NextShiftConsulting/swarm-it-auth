"""
HashiCorp Vault Credential Adapter - Production-grade secret storage.
"""

from typing import Optional, Dict, Any
from swarm_auth.ports.credential_port import CredentialPort
from swarm_auth.domain.credential import Credential


class VaultCredentialAdapter(CredentialPort):
    """
    HashiCorp Vault credential storage adapter.

    Uses KV Secrets Engine v2 for versioned secrets.
    Requires: pip install hvac
    """

    def __init__(
        self,
        url: str = "http://localhost:8200",
        token: Optional[str] = None,
        mount_point: str = "secret",
        path_prefix: str = "swarm-it",
    ):
        """
        Initialize Vault adapter.

        Args:
            url: Vault server URL
            token: Vault token (or use VAULT_TOKEN env var)
            mount_point: KV mount point (default: secret)
            path_prefix: Path prefix for secrets (default: swarm-it)
        """
        try:
            import hvac
        except ImportError:
            raise ImportError("hvac package required: pip install hvac")

        self._mount_point = mount_point
        self._path_prefix = path_prefix

        # Initialize Vault client
        self._client = hvac.Client(url=url, token=token)

        if not self._client.is_authenticated():
            raise ValueError("Vault authentication failed")

    def _get_path(self, key: str) -> str:
        """Get full Vault path for a key."""
        return f"{self._path_prefix}/{key}"

    def store(
        self,
        key: str,
        value: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Credential:
        """
        Store a credential in Vault.

        Args:
            key: Credential key
            value: Credential value
            metadata: Optional metadata

        Returns:
            Created credential
        """
        path = self._get_path(key)

        # Store secret with metadata
        secret_data = {"value": value}
        if metadata:
            secret_data["metadata"] = metadata

        self._client.secrets.kv.v2.create_or_update_secret(
            path=path,
            secret=secret_data,
            mount_point=self._mount_point,
        )

        # Create credential metadata
        cred = Credential.create(
            key=key,
            description=metadata.get("description") if metadata else None,
            tags=metadata.get("tags", {}) if metadata else {},
        )

        return cred

    def retrieve(self, key: str) -> Optional[str]:
        """
        Retrieve a credential from Vault.

        Args:
            key: Credential key

        Returns:
            Credential value or None
        """
        path = self._get_path(key)

        try:
            response = self._client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=self._mount_point,
            )
            return response["data"]["data"].get("value")
        except Exception:
            return None

    def delete(self, key: str) -> bool:
        """
        Delete a credential from Vault.

        Args:
            key: Credential key

        Returns:
            True if deleted, False if not found
        """
        path = self._get_path(key)

        try:
            self._client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=path,
                mount_point=self._mount_point,
            )
            return True
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
        list_path = self._path_prefix if not prefix else f"{self._path_prefix}/{prefix}"

        try:
            response = self._client.secrets.kv.v2.list_secrets(
                path=list_path,
                mount_point=self._mount_point,
            )
            keys = response["data"]["keys"]
            return [k.rstrip("/") for k in keys]
        except Exception:
            return []

    def rotate(self, key: str, new_value: str) -> Credential:
        """
        Rotate a credential (creates new version).

        Args:
            key: Credential key
            new_value: New credential value

        Returns:
            Updated credential
        """
        # Vault KV v2 automatically versions secrets
        return self.store(key, new_value)

    def get_metadata(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get credential metadata from Vault.

        Args:
            key: Credential key

        Returns:
            Metadata dict or None
        """
        path = self._get_path(key)

        try:
            response = self._client.secrets.kv.v2.read_secret_metadata(
                path=path,
                mount_point=self._mount_point,
            )

            metadata = response["data"]
            return {
                "key": key,
                "versions": metadata.get("versions", {}),
                "created_time": metadata.get("created_time"),
                "updated_time": metadata.get("updated_time"),
                "current_version": metadata.get("current_version"),
            }
        except Exception:
            return None
