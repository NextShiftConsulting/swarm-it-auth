"""
Kubernetes Secrets Credential Adapter - Read from mounted secrets.

In Kubernetes, secrets are mounted as files in /var/run/secrets or
custom paths. This adapter reads credentials from those mounts.
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any, List
from swarm_auth.ports.credential_port import CredentialPort
from swarm_auth.domain.credential import Credential


class K8sSecretsAdapter(CredentialPort):
    """
    Kubernetes mounted secrets adapter.

    Reads credentials from Kubernetes secret volume mounts.
    Secrets are mounted as files where filename = key, content = value.

    Default search paths:
    - /var/run/secrets/swarm-it/
    - /etc/secrets/
    - /secrets/
    """

    def __init__(
        self,
        secret_paths: Optional[List[str]] = None,
        namespace: Optional[str] = None,
    ):
        """
        Initialize K8s secrets adapter.

        Args:
            secret_paths: List of paths to search for mounted secrets
            namespace: Kubernetes namespace (for path construction)
        """
        self._namespace = namespace or os.environ.get("K8S_NAMESPACE", "default")
        self._secret_paths = secret_paths or self._default_paths()
        self._cache: Dict[str, str] = {}
        self._loaded = False

    def _default_paths(self) -> List[Path]:
        """Default Kubernetes secret mount paths."""
        return [
            Path("/var/run/secrets/swarm-it"),
            Path("/var/run/secrets/kubernetes.io/serviceaccount"),
            Path(f"/var/run/secrets/{self._namespace}"),
            Path("/etc/secrets"),
            Path("/secrets"),
            # Also check for projected volumes
            Path("/var/run/secrets/tokens"),
        ]

    def _find_secret_paths(self) -> List[Path]:
        """Find all existing secret mount paths."""
        existing = []
        for path in self._secret_paths:
            if isinstance(path, str):
                path = Path(path)
            if path.exists() and path.is_dir():
                existing.append(path)
        return existing

    def _load_secrets(self):
        """Load all secrets from mounted paths."""
        if self._loaded:
            return

        for secret_dir in self._find_secret_paths():
            try:
                for secret_file in secret_dir.iterdir():
                    if secret_file.is_file():
                        key = secret_file.name
                        try:
                            value = secret_file.read_text().strip()
                            # Don't override if already loaded from higher priority path
                            if key not in self._cache:
                                self._cache[key] = value
                        except Exception:
                            pass
            except PermissionError:
                pass

        self._loaded = True

    def store(
        self,
        key: str,
        value: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Credential:
        """
        Store credential (writes to first writable secret path).

        Note: In most K8s setups, secret mounts are read-only.

        Args:
            key: Credential key
            value: Credential value
            metadata: Optional metadata

        Returns:
            Created credential
        """
        # Find first writable path
        for secret_dir in self._find_secret_paths():
            secret_file = secret_dir / key
            try:
                secret_file.write_text(value)
                self._cache[key] = value
                return Credential.create(key=key)
            except (PermissionError, OSError):
                continue

        raise PermissionError("No writable secret path found")

    def retrieve(self, key: str) -> Optional[str]:
        """
        Retrieve credential from mounted secrets.

        Args:
            key: Credential key (filename)

        Returns:
            Credential value or None
        """
        self._load_secrets()
        return self._cache.get(key)

    def delete(self, key: str) -> bool:
        """
        Delete credential (removes from cache, file deletion usually not allowed).

        Args:
            key: Credential key

        Returns:
            True if deleted from cache, False if not found
        """
        self._load_secrets()

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
        self._load_secrets()

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
            Updated credential
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
        self._load_secrets()

        if key not in self._cache:
            return None

        # Find which path the secret came from
        source_path = None
        for secret_dir in self._find_secret_paths():
            if (secret_dir / key).exists():
                source_path = str(secret_dir / key)
                break

        return {
            "key": key,
            "source": "k8s_secrets",
            "path": source_path,
            "namespace": self._namespace,
        }

    @classmethod
    def is_available(cls) -> bool:
        """Check if running in Kubernetes with mounted secrets."""
        # Check for K8s service account token (standard mount)
        if Path("/var/run/secrets/kubernetes.io/serviceaccount/token").exists():
            return True

        # Check for any of our default paths
        adapter = cls()
        return len(adapter._find_secret_paths()) > 0

    @classmethod
    def is_in_kubernetes(cls) -> bool:
        """Check if running inside a Kubernetes pod."""
        return (
            os.environ.get("KUBERNETES_SERVICE_HOST") is not None
            or Path("/var/run/secrets/kubernetes.io").exists()
        )
