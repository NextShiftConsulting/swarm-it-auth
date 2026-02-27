"""
Credential Broker Port - Token vending machine for outbound provider access.

Critical for agent systems:
- Never store long-lived provider credentials
- Mint short-lived, scoped credentials on-demand
- Enforce least privilege per tool call

Providers:
- AWS: STS AssumeRole with session policies
- GCP: Workload Identity Federation + service account impersonation
- OpenAI: Project-scoped API keys
- Hugging Face: Fine-grained tokens
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class ProviderType(Enum):
    """Supported cloud/AI providers."""
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    HUGGINGFACE = "huggingface"
    BEDROCK = "bedrock"


@dataclass
class ProviderCredential:
    """
    Short-lived credential for a specific provider.

    Never contains long-lived keys. Always time-limited.
    """
    provider: ProviderType
    credential_type: str  # aws_sts, gcp_token, api_key, bearer_token

    # The actual credential (format depends on provider)
    credentials: Dict[str, Any]  # access_key, secret_key, token, api_key, etc.

    # Metadata
    expires_at: datetime
    scope: str  # What this credential can do
    issued_to: str  # Principal ID (required field)

    # Optional metadata
    session_name: Optional[str] = None
    assumed_role: Optional[str] = None
    issued_at: Optional[datetime] = None
    request_id: Optional[str] = None

    def is_expired(self) -> bool:
        """Check if credential has expired."""
        return datetime.utcnow() >= self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize to dict.

        WARNING: Contains sensitive credentials. Never log this.
        """
        return {
            "provider": self.provider.value,
            "credential_type": self.credential_type,
            "expires_at": self.expires_at.isoformat(),
            "scope": self.scope,
            "session_name": self.session_name,
            "assumed_role": self.assumed_role,
            "issued_to": self.issued_to,
            "issued_at": self.issued_at.isoformat() if self.issued_at else None,
            # NEVER include actual credentials in logs/responses
        }


@dataclass
class ToolRequest:
    """
    Request to access a specific tool/capability.

    Used by CredentialBroker to determine what credential to mint.
    """
    tool_name: str          # s3_upload, openai_chat, hf_inference
    provider: ProviderType
    action: str             # s3:PutObject, openai:files.create
    resource: str           # arn:aws:s3:::bucket/*, project-123, model-name

    # Constraints from policy decision
    max_duration: int = 3600  # seconds
    scope_restrictions: Optional[Dict[str, Any]] = None  # Region, prefix, etc.

    # Audit
    principal_id: Optional[str] = None
    request_id: Optional[str] = None


class CredentialBrokerPort(ABC):
    """
    Port: Credential Broker (Token Vending Machine).

    Mints short-lived, scoped credentials for outbound provider access.

    Design principles:
    1. Never vend long-lived credentials
    2. Scope credentials to minimum necessary (action + resource)
    3. Always set expiration (< 1 hour recommended)
    4. Audit every credential issuance
    5. Support revocation
    """

    @abstractmethod
    def vend_credential(
        self,
        principal: "User",  # From swarm_auth.domain.user
        tool_request: ToolRequest,
    ) -> ProviderCredential:
        """
        Mint a short-lived credential for a specific tool/provider.

        Args:
            principal: Authenticated user/agent requesting credential
            tool_request: What tool and action they want to perform

        Returns:
            Short-lived credential scoped to the request

        Raises:
            PermissionDeniedError: Principal not allowed to access tool
            ProviderError: Provider credential service unavailable
            QuotaExceededError: Principal over budget/rate limit

        Example (AWS):
            cred = broker.vend_credential(
                principal=agent,
                tool_request=ToolRequest(
                    tool_name="s3_upload",
                    provider=ProviderType.AWS,
                    action="s3:PutObject",
                    resource="arn:aws:s3:::my-bucket/prefix/*",
                    max_duration=900,  # 15 minutes
                    scope_restrictions={"region": "us-east-1"},
                )
            )
            # Returns: temporary STS credentials with session policy

        Example (OpenAI):
            cred = broker.vend_credential(
                principal=agent,
                tool_request=ToolRequest(
                    tool_name="openai_chat",
                    provider=ProviderType.OPENAI,
                    action="chat.completions.create",
                    resource="project-abc123",
                )
            )
            # Returns: project-scoped API key
        """
        pass

    @abstractmethod
    def revoke_credential(self, credential_id: str) -> bool:
        """
        Revoke a credential before expiration.

        Args:
            credential_id: ID of credential to revoke

        Returns:
            True if revoked, False if not found
        """
        pass

    @abstractmethod
    def list_active_credentials(
        self,
        principal: "User",
        provider: Optional[ProviderType] = None,
    ) -> list[ProviderCredential]:
        """
        List active credentials for a principal.

        Args:
            principal: User/agent
            provider: Optional provider filter

        Returns:
            List of active credentials (redacted)
        """
        pass

    @abstractmethod
    def validate_credential(self, credential: ProviderCredential) -> bool:
        """
        Validate a credential is still valid.

        Args:
            credential: Credential to validate

        Returns:
            True if valid, False otherwise
        """
        pass

    @abstractmethod
    def refresh_credential(self, credential: ProviderCredential) -> ProviderCredential:
        """
        Refresh an expiring credential.

        Args:
            credential: Credential to refresh

        Returns:
            New credential with extended expiration

        Raises:
            NotRefreshableError: Credential cannot be refreshed
        """
        pass
