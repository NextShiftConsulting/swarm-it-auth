"""
Keyfile Credential Adapter - Load credentials from per-service text files.

Convention: each credential lives in its own text file under a ``keys/``
directory. The filename (minus extension) becomes the normalized credential
key; the file content is the credential value.

Why a separate adapter (not just ``.env``)?
- Keeps high-sensitivity values out of a single dotfile that might get
  accidentally committed or sourced too broadly.
- Lets rotation / audit happen per credential (ls, stat, mtime).
- Maps cleanly onto AWS Secrets Manager where each file →  one secret.

Filename → key normalization:
    ``swarmit-rapidapi-staging.txt`` → ``SWARMIT_RAPIDAPI_STAGING``
    ``Gemini_API_Key.txt``           → ``GEMINI_API_KEY``
    ``KAGGLE_API_TOKEN.txt``         → ``KAGGLE_API_TOKEN``

Lookup is case-insensitive and dash-insensitive: callers can pass either
``"SWARMIT_RAPIDAPI_STAGING"`` or ``"swarmit-rapidapi-staging"``.

File format:
- Lines starting with ``#`` are comments and ignored.
- Blank lines are ignored.
- Exactly one remaining line = the credential value (surrounding single
  or double quotes are stripped).
- Files with multiple non-comment non-blank lines are considered
  ambiguous and return ``None``.

Only ``.txt`` files are scanned. ``.md`` / ``.json`` / ``.pem`` are ignored
so README / IAM policy / SSH key files don't surface as credentials.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from swarm_auth.domain.credential import Credential
from swarm_auth.ports.credential_port import CredentialPort


# Only these extensions are treated as credential files.
KEYFILE_EXTENSIONS: tuple[str, ...] = (".txt",)


def _normalize(name: str) -> str:
    """Canonicalize a credential key name.

    Uppercase, strip whitespace, convert ``-`` to ``_``. Makes lookup
    insensitive to the filename casing convention the caller picked.
    """
    return name.strip().upper().replace("-", "_")


class KeyfileAdapter(CredentialPort):
    """Credential adapter for per-file text credentials.

    Args:
        keys_dir: Directory holding ``*.txt`` credential files. If ``None``,
            the adapter searches (in order) the same canonical locations as
            ``DotEnvAdapter`` — relative to the installed ``swarm_auth``
            package, the current working directory, then
            ``~/github/swarm-it-auth/keys``.
        extensions: File extensions to treat as credentials. Default:
            ``(".txt",)``.
    """

    def __init__(
        self,
        keys_dir: Optional[str | os.PathLike[str]] = None,
        extensions: Iterable[str] = KEYFILE_EXTENSIONS,
    ) -> None:
        self._explicit_dir = Path(keys_dir) if keys_dir else None
        self._extensions = tuple(ext.lower() for ext in extensions)
        self._cache: Dict[str, str] = {}
        self._loaded = False

    # ------------------------------------------------------------------ helpers

    @classmethod
    def _default_search_paths(cls) -> List[Path]:
        """Directories to search for a ``keys/`` folder."""
        here = Path(__file__).resolve()
        home = Path.home()
        return [
            # swarm-it-auth/keys (installed layout)
            here.parent.parent.parent / "keys",
            # caller-local keys/
            Path.cwd() / "keys",
            # conventional checkout
            home / "github" / "swarm-it-auth" / "keys",
        ]

    def _find_keys_dir(self) -> Optional[Path]:
        """Resolve the keys directory, or ``None`` if none exist."""
        if self._explicit_dir is not None:
            return self._explicit_dir if self._explicit_dir.is_dir() else None
        for p in self._default_search_paths():
            if p.is_dir():
                return p
        return None

    @staticmethod
    def _parse_file(path: Path) -> Optional[str]:
        """Return the credential value contained in ``path``.

        - Strip each line of leading/trailing whitespace.
        - Ignore blank lines and lines starting with ``#``.
        - If exactly one non-empty non-comment line remains, return it
          (with any surrounding single/double quotes stripped).
        - Otherwise return ``None`` (empty or ambiguous file).
        """
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None

        content_lines: List[str] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            content_lines.append(line)

        if len(content_lines) != 1:
            return None

        v = content_lines[0]
        if (v.startswith('"') and v.endswith('"')) or (
            v.startswith("'") and v.endswith("'")
        ):
            v = v[1:-1]
        return v

    def _scan_dir(self, keys_dir: Path) -> Dict[str, Path]:
        """Return a mapping of normalized key → file path for the dir."""
        mapping: Dict[str, Path] = {}
        for entry in keys_dir.iterdir():
            if not entry.is_file():
                continue
            if entry.suffix.lower() not in self._extensions:
                continue
            mapping[_normalize(entry.stem)] = entry
        return mapping

    def _ensure_loaded(self) -> None:
        """Populate the cache of file *locations* (values loaded on demand)."""
        if self._loaded:
            return
        self._loaded = True

        keys_dir = self._find_keys_dir()
        if keys_dir is None:
            self._file_map: Dict[str, Path] = {}
            return
        self._file_map = self._scan_dir(keys_dir)

    # ------------------------------------------------------------ CredentialPort

    def retrieve(self, key: str) -> Optional[str]:
        """Return the credential value for ``key`` or ``None``."""
        self._ensure_loaded()
        norm = _normalize(key)

        # In-memory cache (short-circuits file read if already resolved).
        cached = self._cache.get(norm)
        if cached is not None:
            return cached

        path = self._file_map.get(norm)
        if path is None:
            return None

        value = self._parse_file(path)
        if value is not None:
            self._cache[norm] = value
        return value

    def store(
        self,
        key: str,
        value: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Credential:
        """Write a new credential file (``<keys_dir>/<key>.txt``).

        The file contains just the value (no KEY=VALUE prefix) so it can be
        safely committed nowhere and rotated by overwriting. Creates the
        keys directory if it doesn't already exist.
        """
        keys_dir = self._find_keys_dir()
        if keys_dir is None:
            # Default to the swarm-it-auth layout.
            keys_dir = self._default_search_paths()[0]
            keys_dir.mkdir(parents=True, exist_ok=True)

        # File lives under the canonical lowercased filename; lookup
        # normalizes both sides so casing is irrelevant for callers.
        filename = _normalize(key).lower().replace("_", "-") + ".txt"
        path = keys_dir / filename
        path.write_text(value + "\n", encoding="utf-8")

        # Invalidate caches so the new file is visible.
        self._loaded = False
        self._cache.pop(_normalize(key), None)

        return Credential.create(key=_normalize(key))

    def delete(self, key: str) -> bool:
        """Delete the credential file for ``key``. Returns ``True`` on success."""
        self._ensure_loaded()
        norm = _normalize(key)
        path = self._file_map.get(norm)
        if path is None:
            return False
        try:
            path.unlink()
        except OSError:
            return False
        self._cache.pop(norm, None)
        self._file_map.pop(norm, None)
        return True

    def list_keys(self, prefix: Optional[str] = None) -> List[str]:
        """List normalized credential keys present on disk."""
        self._ensure_loaded()
        keys = list(self._file_map.keys())
        if prefix:
            norm_prefix = _normalize(prefix)
            keys = [k for k in keys if k.startswith(norm_prefix)]
        return sorted(keys)

    def rotate(self, key: str, new_value: str) -> Credential:
        """Overwrite the file with a new value."""
        return self.store(key, new_value)

    def get_metadata(self, key: str) -> Optional[Dict[str, Any]]:
        """Return file-level metadata (path, mtime, size) — never the value."""
        self._ensure_loaded()
        norm = _normalize(key)
        path = self._file_map.get(norm)
        if path is None:
            return None
        stat = path.stat()
        return {
            "key": norm,
            "source": "keyfile",
            "path": str(path),
            "size_bytes": stat.st_size,
            "modified_unix": int(stat.st_mtime),
        }

    @classmethod
    def is_available(cls) -> bool:
        """True if any candidate keys directory exists and contains files."""
        inst = cls()
        keys_dir = inst._find_keys_dir()
        if keys_dir is None:
            return False
        for entry in keys_dir.iterdir():
            if entry.is_file() and entry.suffix.lower() in KEYFILE_EXTENSIONS:
                return True
        return False
