"""
AWS Credential Broker - Vends temporary STS credentials.

Uses AWS STS AssumeRole to mint short-lived, scoped credentials.
Session policies further restrict permissions per request.
"""

from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import json
from swarm_auth.ports.credential_broker_port import (
    CredentialBrokerPort,
    ProviderCredential,
    ToolRequest,
    ProviderType,
)
from swarm_auth.domain.user import User


class AWSCredentialBroker(CredentialBrokerPort):
    """
    AWS credential broker using STS AssumeRole.

    Best practices:
    1. Use separate roles per tool/capability
    2. Apply session policies to narrow permissions further
    3. Short TTLs (< 1 hour)
    4. Tag sessions with principal ID for audit
    """

    def __init__(
        self,
        region: str = "us-east-1",
        role_arn_template: str = "arn:aws:iam::{account}:role/{tool_name}",
        account_id: Optional[str] = None,
    ):
        """
        Initialize AWS broker.

        Args:
            region: AWS region
            role_arn_template: Template for role ARNs
            account_id: AWS account ID
        """
        try:
            import boto3
        except ImportError:
            raise ImportError("boto3 required: pip install boto3")

        self._sts = boto3.client("sts", region_name=region)
        self._role_template = role_arn_template
        self._account_id = account_id or self._get_account_id()

    def _get_account_id(self) -> str:
        """Get AWS account ID."""
        identity = self._sts.get_caller_identity()
        return identity["Account"]

    def vend_credential(
        self,
        principal: User,
        tool_request: ToolRequest,
    ) -> ProviderCredential:
        """
        Vend temporary AWS credentials via STS AssumeRole.

        Creates session policy to restrict to specific resource.
        """

        # Build role ARN
        role_arn = self._role_template.format(
            account=self._account_id,
            tool_name=tool_request.tool_name,
        )

        # Build session policy (further restricts role permissions)
        session_policy = self._build_session_policy(tool_request)

        # Session name for audit
        session_name = f"{principal.user_id}-{tool_request.tool_name}"[:64]

        # AssumeRole with session policy
        response = self._sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            Policy=json.dumps(session_policy),
            DurationSeconds=min(tool_request.max_duration, 3600),
            Tags=[
                {"Key": "PrincipalId", "Value": principal.user_id},
                {"Key": "PrincipalRole", "Value": principal.role.value},
                {"Key": "ToolName", "Value": tool_request.tool_name},
            ],
        )

        creds = response["Credentials"]

        return ProviderCredential(
            provider=ProviderType.AWS,
            credential_type="aws_sts",
            credentials={
                "access_key_id": creds["AccessKeyId"],
                "secret_access_key": creds["SecretAccessKey"],
                "session_token": creds["SessionToken"],
                "region": self._sts.meta.region_name,
            },
            expires_at=creds["Expiration"],
            scope=tool_request.action,
            session_name=session_name,
            assumed_role=role_arn,
            issued_to=principal.user_id,
            issued_at=datetime.utcnow(),
            request_id=tool_request.request_id,
        )

    def _build_session_policy(self, tool_request: ToolRequest) -> Dict[str, Any]:
        """
        Build IAM session policy to restrict permissions.

        Example: If tool_request.action = "s3:PutObject" and
                 tool_request.resource = "arn:aws:s3:::bucket/prefix/*"
        Returns: Session policy allowing only PutObject on that prefix.
        """
        actions = [tool_request.action]

        # Parse resource (could be ARN or simple identifier)
        resource = tool_request.resource
        if not resource.startswith("arn:"):
            # Convert to ARN if needed
            if tool_request.tool_name.startswith("s3_"):
                resource = f"arn:aws:s3:::{resource}"

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": actions,
                    "Resource": resource,
                }
            ],
        }

        # Add region restrictions if specified
        if tool_request.scope_restrictions and "region" in tool_request.scope_restrictions:
            policy["Statement"][0]["Condition"] = {
                "StringEquals": {
                    "aws:RequestedRegion": tool_request.scope_restrictions["region"]
                }
            }

        return policy

    def revoke_credential(self, credential_id: str) -> bool:
        """
        Revoke STS credential.

        Note: STS credentials can't be revoked directly, but we can:
        1. Track them and refuse to vend new ones
        2. Revoke the role's permissions
        3. Wait for expiration (short TTL mitigates this)
        """
        # In practice, implement via blacklist or role policy update
        # For now, return True (relies on short TTLs)
        return True

    def list_active_credentials(
        self,
        principal: User,
        provider: Optional[ProviderType] = None,
    ) -> list[ProviderCredential]:
        """List active credentials (not implemented for STS)."""
        # STS doesn't provide listing of active credentials
        # Would need separate tracking database
        return []

    def validate_credential(self, credential: ProviderCredential) -> bool:
        """Check if credential is still valid."""
        if credential.is_expired():
            return False

        # Could call STS GetCallerIdentity to verify
        try:
            import boto3
            sts = boto3.client(
                "sts",
                aws_access_key_id=credential.credentials["access_key_id"],
                aws_secret_access_key=credential.credentials["secret_access_key"],
                aws_session_token=credential.credentials["session_token"],
            )
            sts.get_caller_identity()
            return True
        except Exception:
            return False

    def refresh_credential(self, credential: ProviderCredential) -> ProviderCredential:
        """Refresh credential (not supported for STS - must re-assume role)."""
        raise NotImplementedError(
            "STS credentials cannot be refreshed. Request a new credential via vend_credential()."
        )
