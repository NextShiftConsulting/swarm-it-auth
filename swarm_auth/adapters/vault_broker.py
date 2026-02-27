"""
Vault Credential Broker - THE credential broker for all providers.

Uses HashiCorp Vault to vend short-lived credentials:
- AWS: Dynamic STS credentials via aws/ secrets engine
- GCP: Service account tokens via gcp/ secrets engine
- OpenAI/HF: Stored keys via kv/ secrets engine (with rotation)

One broker to rule them all.
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


class VaultCredentialBroker(CredentialBrokerPort):
    """
    Vault-based credential broker for all cloud/AI providers.

    Setup:
    1. Enable secrets engines:
       - vault secrets enable aws
       - vault secrets enable gcp
       - vault secrets enable -path=secret kv-v2

    2. Configure AWS dynamic credentials:
       - vault write aws/roles/s3-upload-role credential_type=assumed_role ...

    3. Configure GCP service account tokens:
       - vault write gcp/roleset/storage-reader ...

    4. Store OpenAI/HF keys:
       - vault kv put secret/openai/project-123 api_key=sk-...
       - vault kv put secret/huggingface/prod token=hf_...
    """

    def __init__(
        self,
        vault_url: str = "http://localhost:8200",
        vault_token: Optional[str] = None,
        vault_namespace: Optional[str] = None,
    ):
        """
        Initialize Vault broker.

        Args:
            vault_url: Vault server URL
            vault_token: Vault token (or use VAULT_TOKEN env)
            vault_namespace: Vault namespace (for Vault Enterprise)
        """
        try:
            import hvac
        except ImportError:
            raise ImportError("hvac required: pip install hvac")

        self._client = hvac.Client(
            url=vault_url,
            token=vault_token,
            namespace=vault_namespace,
        )

        if not self._client.is_authenticated():
            raise ValueError("Vault authentication failed")

    def vend_credential(
        self,
        principal: User,
        tool_request: ToolRequest,
    ) -> ProviderCredential:
        """
        Vend credential from Vault based on provider.

        Routes to:
        - AWS: Vault AWS secrets engine (dynamic STS)
        - GCP: Vault GCP secrets engine (service account tokens)
        - OpenAI/HF: Vault KV secrets engine (stored keys)
        """
        if tool_request.provider == ProviderType.AWS:
            return self._vend_aws(principal, tool_request)
        elif tool_request.provider == ProviderType.GCP:
            return self._vend_gcp(principal, tool_request)
        elif tool_request.provider == ProviderType.OPENAI:
            return self._vend_openai(principal, tool_request)
        elif tool_request.provider == ProviderType.HUGGINGFACE:
            return self._vend_huggingface(principal, tool_request)
        else:
            raise ValueError(f"Unsupported provider: {tool_request.provider}")

    def _vend_aws(
        self,
        principal: User,
        tool_request: ToolRequest,
    ) -> ProviderCredential:
        """
        Vend AWS credentials via Vault AWS secrets engine.

        Vault returns temporary STS credentials with IAM role assumed.
        """
        # Map tool_name to Vault role
        role_name = self._map_tool_to_aws_role(tool_request.tool_name)

        # Request credentials from Vault
        response = self._client.secrets.aws.generate_credentials(
            name=role_name,
            role_arn=None,  # Configured in Vault role
            ttl=f"{tool_request.max_duration}s",
        )

        creds = response["data"]

        return ProviderCredential(
            provider=ProviderType.AWS,
            credential_type="aws_sts",
            credentials={
                "access_key_id": creds["access_key"],
                "secret_access_key": creds["secret_key"],
                "session_token": creds["security_token"],
            },
            expires_at=datetime.utcnow() + timedelta(seconds=tool_request.max_duration),
            scope=tool_request.action,
            issued_to=principal.user_id,
            issued_at=datetime.utcnow(),
            request_id=tool_request.request_id,
        )

    def _vend_gcp(
        self,
        principal: User,
        tool_request: ToolRequest,
    ) -> ProviderCredential:
        """
        Vend GCP credentials via Vault GCP secrets engine.

        Vault returns service account access token.
        """
        # Map tool_name to Vault roleset
        roleset = self._map_tool_to_gcp_roleset(tool_request.tool_name)

        # Request token from Vault
        response = self._client.secrets.gcp.generate_credentials(
            name=roleset,
            key_algorithm=None,  # Access token (not key)
            key_type=None,
        )

        token_data = response["data"]

        return ProviderCredential(
            provider=ProviderType.GCP,
            credential_type="access_token",
            credentials={
                "access_token": token_data["token"],
                "token_type": "Bearer",
            },
            expires_at=datetime.fromisoformat(token_data["token_ttl"]),
            scope=token_data.get("token_scopes", ""),
            issued_to=principal.user_id,
            issued_at=datetime.utcnow(),
            request_id=tool_request.request_id,
        )

    def _vend_openai(
        self,
        principal: User,
        tool_request: ToolRequest,
    ) -> ProviderCredential:
        """
        Vend OpenAI key from Vault KV store.

        Keys are pre-created in OpenAI and stored in Vault.
        """
        # Read OpenAI key from KV store
        secret_path = f"secret/data/openai/{tool_request.resource}"

        response = self._client.secrets.kv.v2.read_secret_version(
            path=secret_path.replace("/data/", "/"),
            mount_point="secret",
        )

        secret_data = response["data"]["data"]

        return ProviderCredential(
            provider=ProviderType.OPENAI,
            credential_type="api_key",
            credentials={
                "api_key": secret_data["api_key"],
                "project_id": secret_data.get("project_id"),
            },
            expires_at=datetime.utcnow() + timedelta(seconds=tool_request.max_duration),
            scope=f"project:{secret_data.get('project_id')}",
            issued_to=principal.user_id,
            issued_at=datetime.utcnow(),
            request_id=tool_request.request_id,
        )

    def _vend_huggingface(
        self,
        principal: User,
        tool_request: ToolRequest,
    ) -> ProviderCredential:
        """
        Vend Hugging Face token from Vault KV store.

        Tokens are pre-created in HF and stored in Vault.
        """
        # Read HF token from KV store
        secret_path = f"secret/data/huggingface/{tool_request.resource}"

        response = self._client.secrets.kv.v2.read_secret_version(
            path=secret_path.replace("/data/", "/"),
            mount_point="secret",
        )

        secret_data = response["data"]["data"]

        return ProviderCredential(
            provider=ProviderType.HUGGINGFACE,
            credential_type="token",
            credentials={
                "token": secret_data["token"],
            },
            expires_at=datetime.utcnow() + timedelta(seconds=tool_request.max_duration),
            scope=tool_request.action,
            issued_to=principal.user_id,
            issued_at=datetime.utcnow(),
            request_id=tool_request.request_id,
        )

    def _map_tool_to_aws_role(self, tool_name: str) -> str:
        """Map tool name to Vault AWS role name."""
        role_map = {
            "s3_upload": "s3-upload-role",
            "s3_read": "s3-read-role",
            "dynamodb_read": "dynamodb-read-role",
            "dynamodb_write": "dynamodb-write-role",
        }
        return role_map.get(tool_name, "default-role")

    def _map_tool_to_gcp_roleset(self, tool_name: str) -> str:
        """Map tool name to Vault GCP roleset name."""
        roleset_map = {
            "storage_read": "storage-reader",
            "storage_write": "storage-writer",
            "bigquery_read": "bigquery-reader",
        }
        return roleset_map.get(tool_name, "default-roleset")

    def revoke_credential(self, credential_id: str) -> bool:
        """Revoke credential (if supported by provider)."""
        # AWS STS: Can't revoke (rely on short TTL)
        # GCP: Can't revoke access tokens (rely on short TTL)
        # Could implement blacklist here
        return True

    def list_active_credentials(
        self,
        principal: User,
        provider: Optional[ProviderType] = None,
    ) -> list[ProviderCredential]:
        """List active credentials (requires separate tracking)."""
        # Vault doesn't track issued credentials
        # Would need separate audit log or database
        return []

    def validate_credential(self, credential: ProviderCredential) -> bool:
        """Validate credential is still valid."""
        return not credential.is_expired()

    def refresh_credential(self, credential: ProviderCredential) -> ProviderCredential:
        """Refresh credential (not supported - request new one)."""
        raise NotImplementedError(
            "Credentials cannot be refreshed. Request a new credential via vend_credential()."
        )
