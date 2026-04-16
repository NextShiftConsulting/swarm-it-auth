"""
AccessScript - Credential Triage Orchestration.

Implements SOTA agent auth patterns:
- Priority-ordered credential sources
- Forbidden source enforcement (avoid security violations)
- JIT provisioning
- Environment-specific configuration
- Full audit trail

Usage:
    from swarm_auth import AccessScript

    # Auto-discovers available sources
    access = AccessScript()
    api_key = access.get("OPENAI_API_KEY")

    # Or configure explicitly
    access = AccessScript.from_config({
        "priority": ["env_var", "dotenv", "aws_secrets"],
        "forbidden": ["kms"],  # Don't attempt KMS in this env
    })
"""

import os
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any, List, Callable

from swarm_auth.ports.credential_port import CredentialPort


logger = logging.getLogger(__name__)


class SourceType(Enum):
    """Available credential source types."""
    ENV_VAR = "env_var"
    DOTENV = "dotenv"
    KEYFILE = "keyfile"
    AWS_SECRETS = "aws_secrets"
    KMS = "kms"
    VAULT = "vault"
    K8S_SECRETS = "k8s_secrets"


class OnForbidden(Enum):
    """Behavior when forbidden source is attempted."""
    SILENT = "silent"      # Skip silently
    LOG = "log"            # Log warning and skip
    ERROR = "error"        # Raise exception


@dataclass
class AccessAttempt:
    """Record of a credential access attempt."""
    timestamp: datetime
    key: str
    source: SourceType
    success: bool
    error: Optional[str] = None
    duration_ms: Optional[float] = None


@dataclass
class AccessScriptConfig:
    """Configuration for AccessScript."""
    # Sources to try, in priority order
    priority: List[SourceType] = field(default_factory=lambda: [
        SourceType.ENV_VAR,
        SourceType.DOTENV,
        SourceType.KEYFILE,
        SourceType.K8S_SECRETS,
        SourceType.AWS_SECRETS,
        SourceType.KMS,
        SourceType.VAULT,
    ])

    # Sources that must NEVER be attempted (security violations)
    forbidden: List[SourceType] = field(default_factory=list)

    # Behavior when forbidden source would be tried
    on_forbidden: OnForbidden = OnForbidden.LOG

    # JIT mode - don't pre-load, fetch on demand
    jit_mode: bool = True

    # TTL for cached credentials (seconds, 0 = no cache)
    cache_ttl: int = 300

    # Audit all access attempts
    audit_enabled: bool = True

    # Environment name (for env-specific config)
    environment: str = field(default_factory=lambda: os.environ.get("ENVIRONMENT", "dev"))

    # Environment-specific overrides
    env_overrides: Dict[str, Dict[str, Any]] = field(default_factory=dict)


class AccessScript:
    """
    Credential triage orchestration.

    Tries multiple credential sources in priority order,
    respecting forbidden sources and environment configuration.
    """

    def __init__(self, config: Optional[AccessScriptConfig] = None):
        """
        Initialize AccessScript.

        Args:
            config: Configuration (auto-discovers if None)
        """
        self._config = config or AccessScriptConfig()
        self._apply_env_overrides()

        self._adapters: Dict[SourceType, CredentialPort] = {}
        self._cache: Dict[str, tuple] = {}  # key -> (value, timestamp)
        self._audit_log: List[AccessAttempt] = []

        if not self._config.jit_mode:
            self._init_adapters()

    def _apply_env_overrides(self):
        """Apply environment-specific configuration overrides."""
        env = self._config.environment
        if env in self._config.env_overrides:
            overrides = self._config.env_overrides[env]

            if "priority" in overrides:
                self._config.priority = [
                    SourceType(s) if isinstance(s, str) else s
                    for s in overrides["priority"]
                ]

            if "forbidden" in overrides:
                self._config.forbidden = [
                    SourceType(s) if isinstance(s, str) else s
                    for s in overrides["forbidden"]
                ]

            if "on_forbidden" in overrides:
                self._config.on_forbidden = OnForbidden(overrides["on_forbidden"])

    def _get_adapter(self, source: SourceType) -> Optional[CredentialPort]:
        """Get or create adapter for source type."""
        if source in self._adapters:
            return self._adapters[source]

        adapter = self._create_adapter(source)
        if adapter:
            self._adapters[source] = adapter
        return adapter

    def _create_adapter(self, source: SourceType) -> Optional[CredentialPort]:
        """Create adapter for source type if available."""
        try:
            if source == SourceType.ENV_VAR:
                from swarm_auth.adapters.env_credential import EnvCredentialAdapter
                # Use empty prefix for direct env var access
                return EnvCredentialAdapter(prefix="")

            elif source == SourceType.DOTENV:
                from swarm_auth.adapters.dotenv_credential import DotEnvAdapter
                if DotEnvAdapter.is_available():
                    return DotEnvAdapter()
                return None

            elif source == SourceType.KEYFILE:
                from swarm_auth.adapters.keyfile_credential import KeyfileAdapter
                if KeyfileAdapter.is_available():
                    return KeyfileAdapter()
                return None

            elif source == SourceType.AWS_SECRETS:
                from swarm_auth.adapters.aws_credential import AWSSecretsAdapter
                # Only create if AWS credentials are available
                try:
                    import boto3
                    boto3.client("sts").get_caller_identity()
                    return AWSSecretsAdapter()
                except Exception:
                    return None

            elif source == SourceType.KMS:
                from swarm_auth.adapters.kms_credential import KMSAdapter
                if KMSAdapter.is_available():
                    return KMSAdapter()
                return None

            elif source == SourceType.VAULT:
                from swarm_auth.adapters.vault_credential import VaultCredentialAdapter
                vault_token = os.environ.get("VAULT_TOKEN")
                vault_addr = os.environ.get("VAULT_ADDR")
                if vault_token and vault_addr:
                    return VaultCredentialAdapter(url=vault_addr, token=vault_token)
                return None

            elif source == SourceType.K8S_SECRETS:
                from swarm_auth.adapters.k8s_credential import K8sSecretsAdapter
                if K8sSecretsAdapter.is_available():
                    return K8sSecretsAdapter()
                return None

        except ImportError:
            logger.debug(f"Adapter for {source.value} not available (missing dependency)")
            return None
        except Exception as e:
            logger.debug(f"Failed to create adapter for {source.value}: {e}")
            return None

        return None

    def _init_adapters(self):
        """Pre-initialize all configured adapters."""
        for source in self._config.priority:
            if source not in self._config.forbidden:
                self._get_adapter(source)

    def _is_cached(self, key: str) -> bool:
        """Check if key is in cache and not expired."""
        if key not in self._cache:
            return False

        if self._config.cache_ttl == 0:
            return False

        _, timestamp = self._cache[key]
        age = (datetime.utcnow() - timestamp).total_seconds()
        return age < self._config.cache_ttl

    def _record_attempt(
        self,
        key: str,
        source: SourceType,
        success: bool,
        error: Optional[str] = None,
        duration_ms: Optional[float] = None,
    ):
        """Record an access attempt for audit."""
        if not self._config.audit_enabled:
            return

        attempt = AccessAttempt(
            timestamp=datetime.utcnow(),
            key=key,
            source=source,
            success=success,
            error=error,
            duration_ms=duration_ms,
        )
        self._audit_log.append(attempt)

        # Keep audit log bounded
        if len(self._audit_log) > 1000:
            self._audit_log = self._audit_log[-500:]

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get credential, trying sources in priority order.

        Args:
            key: Credential key
            default: Default value if not found

        Returns:
            Credential value or default
        """
        # Check cache first
        if self._is_cached(key):
            return self._cache[key][0]

        # Try each source in priority order
        for source in self._config.priority:
            # Check if source is forbidden
            if source in self._config.forbidden:
                if self._config.on_forbidden == OnForbidden.ERROR:
                    raise PermissionError(
                        f"Credential source {source.value} is forbidden in this environment"
                    )
                elif self._config.on_forbidden == OnForbidden.LOG:
                    logger.warning(f"Skipping forbidden source: {source.value}")
                continue

            # Get adapter (JIT creation)
            adapter = self._get_adapter(source)
            if adapter is None:
                continue

            # Try to retrieve credential
            start = datetime.utcnow()
            try:
                value = adapter.retrieve(key)
                duration = (datetime.utcnow() - start).total_seconds() * 1000

                if value is not None:
                    # Cache the value
                    self._cache[key] = (value, datetime.utcnow())
                    self._record_attempt(key, source, success=True, duration_ms=duration)
                    return value

                self._record_attempt(key, source, success=False, duration_ms=duration)

            except Exception as e:
                duration = (datetime.utcnow() - start).total_seconds() * 1000
                self._record_attempt(key, source, success=False, error=str(e), duration_ms=duration)
                logger.debug(f"Source {source.value} failed for {key}: {e}")

        return default

    def has(self, key: str) -> bool:
        """Check if credential exists in any source."""
        return self.get(key) is not None

    def list_available_sources(self) -> List[SourceType]:
        """List sources that are available in this environment."""
        available = []
        for source in SourceType:
            if source in self._config.forbidden:
                continue
            adapter = self._get_adapter(source)
            if adapter is not None:
                available.append(source)
        return available

    def get_audit_log(self) -> List[AccessAttempt]:
        """Get the audit log of access attempts."""
        return list(self._audit_log)

    def clear_cache(self):
        """Clear the credential cache."""
        self._cache.clear()

    @classmethod
    def from_config(cls, config_dict: Dict[str, Any]) -> "AccessScript":
        """
        Create AccessScript from configuration dictionary.

        Args:
            config_dict: Configuration dict with priority, forbidden, etc.

        Returns:
            Configured AccessScript
        """
        priority = [
            SourceType(s) if isinstance(s, str) else s
            for s in config_dict.get("priority", [])
        ] or None

        forbidden = [
            SourceType(s) if isinstance(s, str) else s
            for s in config_dict.get("forbidden", [])
        ]

        on_forbidden = OnForbidden(config_dict.get("on_forbidden", "log"))

        config = AccessScriptConfig(
            priority=priority or AccessScriptConfig().priority,
            forbidden=forbidden,
            on_forbidden=on_forbidden,
            jit_mode=config_dict.get("jit_mode", True),
            cache_ttl=config_dict.get("cache_ttl", 300),
            audit_enabled=config_dict.get("audit_enabled", True),
            environment=config_dict.get("environment", os.environ.get("ENVIRONMENT", "dev")),
            env_overrides=config_dict.get("env_overrides", {}),
        )

        return cls(config)

    @classmethod
    def auto_discover(cls) -> "AccessScript":
        """
        Create AccessScript with auto-discovered available sources.

        Returns:
            AccessScript configured for available sources only
        """
        # Start with default config
        config = AccessScriptConfig()

        # Filter to only available sources
        available = []
        for source in config.priority:
            adapter = cls(config)._create_adapter(source)
            if adapter is not None:
                available.append(source)

        config.priority = available

        return cls(config)


# Convenience function for simple usage
_default_access_script: Optional[AccessScript] = None


def get_credential(key: str, default: Optional[str] = None) -> Optional[str]:
    """
    Get credential using default AccessScript.

    This is the recommended entry point for credential access.

    Args:
        key: Credential key
        default: Default value if not found

    Returns:
        Credential value or default
    """
    global _default_access_script

    if _default_access_script is None:
        _default_access_script = AccessScript()

    return _default_access_script.get(key, default)


def has_credential(key: str) -> bool:
    """Check if credential exists using default AccessScript."""
    return get_credential(key) is not None
