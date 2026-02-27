"""
GCP Credential Broker - Vends tokens via Workload Identity Federation.

Uses Workload Identity Federation + service account impersonation
to mint short-lived access tokens without long-lived keys.
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


class GCPCredentialBroker(CredentialBrokerPort):
    """
    GCP credential broker using Workload Identity Federation.

    Best practices:
    1. Use WIF to exchange external identity → GCP token
    2. Impersonate service accounts per tool
    3. Narrow scopes per request
    4. Short-lived tokens (< 1 hour)
    """

    def __init__(
        self,
        project_id: str,
        workload_identity_pool: str,
        service_account_template: str = "{tool_name}@{project_id}.iam.gserviceaccount.com",
    ):
        """
        Initialize GCP broker.

        Args:
            project_id: GCP project ID
            workload_identity_pool: WIF pool ID
            service_account_template: Template for service account emails
        """
        try:
            from google.auth import impersonated_credentials
            from google.oauth2 import service_account
            import google.auth.transport.requests
        except ImportError:
            raise ImportError("google-auth required: pip install google-auth")

        self._project_id = project_id
        self._pool = workload_identity_pool
        self._sa_template = service_account_template

    def vend_credential(
        self,
        principal: User,
        tool_request: ToolRequest,
    ) -> ProviderCredential:
        """
        Vend GCP access token via service account impersonation.

        Workflow:
        1. Exchange principal identity → WIF token
        2. Use WIF token to impersonate service account
        3. Generate scoped access token
        """

        from google.auth import impersonated_credentials
        import google.auth.transport.requests

        # Build service account email
        sa_email = self._sa_template.format(
            tool_name=tool_request.tool_name,
            project_id=self._project_id,
        )

        # Determine scopes based on action
        scopes = self._map_action_to_scopes(tool_request.action)

        # In production, would:
        # 1. Exchange principal JWT → WIF token
        # 2. Use WIF token as source credentials for impersonation

        # For demo, assume we have source credentials
        # source_credentials = get_wif_credentials(principal)

        # Impersonate service account
        # target_credentials = impersonated_credentials.Credentials(
        #     source_credentials=source_credentials,
        #     target_principal=sa_email,
        #     target_scopes=scopes,
        #     lifetime=tool_request.max_duration,
        # )

        # target_credentials.refresh(google.auth.transport.requests.Request())

        # For demo, return structure (actual implementation requires WIF setup)
        expires_at = datetime.utcnow() + timedelta(seconds=tool_request.max_duration)

        return ProviderCredential(
            provider=ProviderType.GCP,
            credential_type="access_token",
            credentials={
                "access_token": "ya29.placeholder",  # Would be real token
                "token_type": "Bearer",
                "project_id": self._project_id,
                "service_account": sa_email,
            },
            expires_at=expires_at,
            scope=",".join(scopes),
            assumed_role=sa_email,
            issued_to=principal.user_id,
            issued_at=datetime.utcnow(),
            request_id=tool_request.request_id,
        )

    def _map_action_to_scopes(self, action: str) -> list[str]:
        """Map action to GCP OAuth scopes."""
        scope_map = {
            "storage.read": ["https://www.googleapis.com/auth/devstorage.read_only"],
            "storage.write": ["https://www.googleapis.com/auth/devstorage.read_write"],
            "bigquery.read": ["https://www.googleapis.com/auth/bigquery.readonly"],
            "bigquery.write": ["https://www.googleapis.com/auth/bigquery"],
        }

        return scope_map.get(action, ["https://www.googleapis.com/auth/cloud-platform"])

    def revoke_credential(self, credential_id: str) -> bool:
        """Revoke GCP token."""
        # Access tokens can't be revoked, but they expire quickly
        # Could revoke service account key if using key-based auth
        return True

    def list_active_credentials(
        self,
        principal: User,
        provider: Optional[ProviderType] = None,
    ) -> list[ProviderCredential]:
        """List active GCP tokens."""
        # Would need separate tracking
        return []

    def validate_credential(self, credential: ProviderCredential) -> bool:
        """Validate GCP token."""
        if credential.is_expired():
            return False

        # Could call tokeninfo endpoint
        import requests
        try:
            response = requests.get(
                "https://www.googleapis.com/oauth2/v1/tokeninfo",
                params={"access_token": credential.credentials["access_token"]},
                timeout=5,
            )
            return response.status_code == 200
        except Exception:
            return False

    def refresh_credential(self, credential: ProviderCredential) -> ProviderCredential:
        """Refresh GCP token."""
        # Would re-impersonate to get new token
        raise NotImplementedError(
            "GCP tokens cannot be refreshed. Request a new credential."
        )
