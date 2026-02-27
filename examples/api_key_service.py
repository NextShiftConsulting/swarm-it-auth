"""
API Key Authentication Example - Service account with API keys.
"""

from swarm_auth import User, UserRole
from swarm_auth.adapters import APIKeyAuthAdapter


def main():
    # Initialize API key auth
    auth = APIKeyAuthAdapter()

    # Create a service account
    service = User(
        user_id="svc_certifier",
        username="certification-service",
        role=UserRole.SERVICE,
        is_service_account=True,
    )

    print(f"Created service account: {service.username}")

    # Register and get API key
    api_key = auth.register_user(service)
    print(f"\nAPI Key generated: {api_key}")
    print("⚠️  Save this key! It cannot be recovered.")

    # Authenticate with API key
    authenticated = auth.authenticate(api_key)
    if authenticated:
        print(f"\n✓ Authentication successful")
        print(f"  User: {authenticated.username}")
        print(f"  Role: {authenticated.role.value}")
        print(f"  Service account: {authenticated.is_service_account}")
    else:
        print("\n✗ Authentication failed")

    # Check permissions
    can_certify = authenticated.has_permission("certify")
    can_audit = authenticated.has_permission("audit")
    print(f"\nPermissions:")
    print(f"  - certify: {can_certify}")
    print(f"  - validate: {authenticated.has_permission('validate')}")
    print(f"  - audit: {can_audit}")

    # Verify key
    is_valid = auth.verify_token(api_key)
    print(f"\nKey valid: {is_valid}")

    # Revoke key
    revoked = auth.revoke_token(api_key)
    print(f"Key revoked: {revoked}")

    # Try to authenticate after revocation (should fail)
    after_revoke = auth.authenticate(api_key)
    print(f"Authentication after revoke: {after_revoke is not None}")


if __name__ == "__main__":
    main()
