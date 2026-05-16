"""
AWS KMS Credential Adapter - Envelope encryption for credentials.

Uses AWS KMS to decrypt credentials stored as encrypted blobs.
Common in locked-down corporate environments.
"""

import os
import base64
import json
from typing import Optional, Dict, Any
from swarm_auth.ports.credential_port import CredentialPort
from swarm_auth.domain.credential import Credential


class KMSAdapter(CredentialPort):
    """
    AWS KMS credential adapter.

    Decrypts credentials that are stored as KMS-encrypted blobs.
    Supports both direct encryption and envelope encryption patterns.

    Environment variables:
    - KMS_KEY_ID or KMS_KEY_ALIAS: KMS key to use
    - KMS_ENCRYPTED_CREDENTIALS: JSON blob of encrypted credentials
    """

    def __init__(
        self,
        key_id: Optional[str] = None,
        region_name: str = "us-east-1",
        encrypted_credentials_env: str = "KMS_ENCRYPTED_CREDENTIALS",
    ):
        """
        Initialize KMS adapter.

        Args:
            key_id: KMS key ID or alias (default: from KMS_KEY_ID env)
            region_name: AWS region
            encrypted_credentials_env: Env var containing encrypted creds
        """
        try:
            import boto3  # noqa: F401
        except ImportError:
            raise ImportError("boto3 package required: pip install boto3")

        self._key_id = key_id or os.environ.get("KMS_KEY_ID") or os.environ.get("KMS_KEY_ALIAS")
        self._region = region_name
        self._encrypted_env = encrypted_credentials_env
        self._client = None
        self._cache: Dict[str, str] = {}
        self._loaded = False

    def _get_client(self):
        """Lazy-load KMS client."""
        if self._client is None:
            import boto3
            self._client = boto3.client("kms", region_name=self._region)
        return self._client

    def _decrypt_blob(self, encrypted_blob: bytes) -> str:
        """Decrypt a KMS-encrypted blob."""
        client = self._get_client()

        response = client.decrypt(
            CiphertextBlob=encrypted_blob,
            KeyId=self._key_id,
        )

        return response["Plaintext"].decode("utf-8")

    def _encrypt_blob(self, plaintext: str) -> bytes:
        """Encrypt plaintext using KMS."""
        client = self._get_client()

        response = client.encrypt(
            KeyId=self._key_id,
            Plaintext=plaintext.encode("utf-8"),
        )

        return response["CiphertextBlob"]

    def _load_encrypted_credentials(self):
        """Load and decrypt credentials from environment."""
        if self._loaded:
            return

        encrypted_json = os.environ.get(self._encrypted_env)
        if not encrypted_json:
            self._loaded = True
            return

        try:
            # Parse the encrypted blob (base64 encoded)
            encrypted_data = json.loads(encrypted_json)

            for key, encrypted_value in encrypted_data.items():
                try:
                    # Decode base64 and decrypt
                    blob = base64.b64decode(encrypted_value)
                    decrypted = self._decrypt_blob(blob)
                    self._cache[key] = decrypted
                except Exception:
                    # Skip credentials we can't decrypt
                    pass

        except json.JSONDecodeError:
            # Single encrypted blob containing all credentials
            try:
                blob = base64.b64decode(encrypted_json)
                decrypted = self._decrypt_blob(blob)
                # Assume decrypted is JSON
                self._cache = json.loads(decrypted)
            except Exception:
                pass

        self._loaded = True

    def store(
        self,
        key: str,
        value: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Credential:
        """
        Store credential (encrypts with KMS).

        Note: This encrypts and returns the blob. Caller must persist it.

        Args:
            key: Credential key
            value: Credential value
            metadata: Optional metadata

        Returns:
            Created credential with encrypted blob in metadata
        """
        encrypted = self._encrypt_blob(value)
        encoded = base64.b64encode(encrypted).decode("utf-8")

        self._cache[key] = value

        cred = Credential.create(key=key)
        # Store encrypted blob in tags for retrieval
        cred.tags["encrypted_blob"] = encoded
        return cred

    def retrieve(self, key: str) -> Optional[str]:
        """
        Retrieve decrypted credential.

        Args:
            key: Credential key

        Returns:
            Decrypted credential value or None
        """
        self._load_encrypted_credentials()
        return self._cache.get(key)

    def delete(self, key: str) -> bool:
        """
        Delete credential from cache.

        Args:
            key: Credential key

        Returns:
            True if deleted, False if not found
        """
        self._load_encrypted_credentials()

        if key in self._cache:
            del self._cache[key]
            return True
        return False

    def list_keys(self, prefix: Optional[str] = None) -> list[str]:
        """
        List credential keys.

        Args:
            prefix: Optional prefix filter

        Returns:
            List of credential keys
        """
        self._load_encrypted_credentials()

        if prefix:
            return [k for k in self._cache.keys() if k.startswith(prefix)]
        return list(self._cache.keys())

    def rotate(self, key: str, new_value: str) -> Credential:
        """
        Rotate credential.

        Args:
            key: Credential key
            new_value: New credential value

        Returns:
            Updated credential with new encrypted blob
        """
        return self.store(key, new_value)

    def get_metadata(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get credential metadata.

        Args:
            key: Credential key

        Returns:
            Metadata dict or None
        """
        self._load_encrypted_credentials()

        if key not in self._cache:
            return None

        return {
            "key": key,
            "source": "kms",
            "key_id": self._key_id,
            "region": self._region,
        }

    @classmethod
    def is_available(cls) -> bool:
        """Check if KMS is available and configured."""
        # Check for KMS key configuration
        if not (os.environ.get("KMS_KEY_ID") or os.environ.get("KMS_KEY_ALIAS")):
            return False

        # Check for AWS credentials
        try:
            import boto3
            sts = boto3.client("sts")
            sts.get_caller_identity()
            return True
        except Exception:
            return False
