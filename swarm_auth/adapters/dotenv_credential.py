"""
DotEnv Credential Adapter - Load credentials from .env files.

Auto-discovers and loads .env files without manual sourcing.
"""

from pathlib import Path
from typing import Optional, Dict, Any
from swarm_auth.ports.credential_port import CredentialPort
from swarm_auth.domain.credential import Credential


class DotEnvAdapter(CredentialPort):
    """
    .env file credential adapter.

    Loads credentials from .env files. Searches in priority order:
    1. Explicit path provided
    2. keys/.env (swarm-it-auth convention)
    3. .env in current directory
    4. .env in home directory
    """

    def __init__(
        self,
        env_file: Optional[str] = None,
        search_paths: Optional[list] = None,
    ):
        """
        Initialize dotenv adapter.

        Args:
            env_file: Explicit path to .env file
            search_paths: List of paths to search for .env files
        """
        self._env_file = env_file
        self._search_paths = search_paths or self._default_search_paths()
        self._cache: Dict[str, str] = {}
        self._loaded = False

    def _default_search_paths(self) -> list:
        """Default .env search paths in priority order."""
        home = Path.home()
        return [
            Path(__file__).parent.parent.parent / "keys" / ".env",  # swarm-it-auth/keys/.env
            Path.cwd() / ".env",
            Path.cwd() / "keys" / ".env",
            home / ".env",
            home / "github" / "swarm-it-auth" / "keys" / ".env",
        ]

    def _find_env_file(self) -> Optional[Path]:
        """Find first existing .env file."""
        if self._env_file:
            path = Path(self._env_file)
            return path if path.exists() else None

        for path in self._search_paths:
            if isinstance(path, str):
                path = Path(path)
            if path.exists():
                return path

        return None

    def _load_env_file(self, path: Path) -> Dict[str, str]:
        """Parse .env file into dict."""
        result = {}

        with open(path, 'r') as f:
            for line in f:
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue

                # Parse KEY=value
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()

                    # Remove quotes
                    if (value.startswith('"') and value.endswith('"')) or \
                       (value.startswith("'") and value.endswith("'")):
                        value = value[1:-1]

                    result[key] = value

        return result

    def _ensure_loaded(self):
        """Lazy-load .env file on first access."""
        if self._loaded:
            return

        env_file = self._find_env_file()
        if env_file:
            self._cache = self._load_env_file(env_file)

        self._loaded = True

    def store(
        self,
        key: str,
        value: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Credential:
        """
        Store credential (appends to .env file).

        Args:
            key: Credential key
            value: Credential value
            metadata: Optional metadata (ignored for .env)

        Returns:
            Created credential
        """
        self._ensure_loaded()

        env_file = self._find_env_file()
        if not env_file:
            # Create default location
            env_file = Path(__file__).parent.parent.parent / "keys" / ".env"
            env_file.parent.mkdir(parents=True, exist_ok=True)

        # Append to file
        with open(env_file, 'a') as f:
            f.write(f'\n{key}="{value}"\n')

        self._cache[key] = value

        return Credential.create(key=key)

    def retrieve(self, key: str) -> Optional[str]:
        """
        Retrieve credential from .env file.

        Args:
            key: Credential key

        Returns:
            Credential value or None
        """
        self._ensure_loaded()
        return self._cache.get(key)

    def delete(self, key: str) -> bool:
        """
        Delete credential (removes from cache, not file).

        Args:
            key: Credential key

        Returns:
            True if deleted, False if not found
        """
        self._ensure_loaded()

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
        self._ensure_loaded()

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
        self._ensure_loaded()

        if key not in self._cache:
            return None

        return {
            "key": key,
            "source": "dotenv",
            "exists": True,
        }

    @classmethod
    def is_available(cls) -> bool:
        """Check if any .env file is available."""
        adapter = cls()
        return adapter._find_env_file() is not None
