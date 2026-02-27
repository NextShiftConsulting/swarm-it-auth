"""
Basic Authentication Example - JWT tokens with in-memory sessions.
"""

from swarm_auth import AuthClient, User, UserRole
from swarm_auth.adapters import JWTAuthAdapter, MemorySessionAdapter


def main():
    # Initialize auth client
    auth = JWTAuthAdapter(secret="my-secret-key")
    sessions = MemorySessionAdapter()
    client = AuthClient(auth=auth, sessions=sessions)

    # Create a user
    user = User(
        user_id="usr_123",
        username="alice",
        role=UserRole.DEVELOPER,
        email="alice@example.com",
        org_id="org_acme",
    )

    print(f"Created user: {user.username} ({user.role.value})")

    # Login (creates token + session)
    result = client.login(user, ttl=3600)
    token = result["token"]
    session = result["session"]

    print(f"\nLogin successful!")
    print(f"Token: {token[:50]}...")
    print(f"Session ID: {session['session_id']}")
    print(f"Expires at: {session['expires_at']}")

    # Verify token
    verified_user = client.verify(token)
    if verified_user:
        print(f"\nToken verified: {verified_user.username}")
        print(f"Permissions: certify={verified_user.has_permission('certify')}")
    else:
        print("\nToken verification failed!")

    # Get session
    active_session = client.get_session(session["session_id"])
    if active_session:
        print(f"\nSession retrieved: {active_session.session_id}")
        print(f"Valid: {active_session.is_valid()}")

    # Extend session
    extended = client.extend_session(session["session_id"], ttl=1800)
    print(f"\nSession extended: {extended}")

    # Logout
    client.logout(token)
    print(f"\nLogged out successfully")

    # Verify token after logout (should fail)
    verified_after_logout = client.verify(token)
    print(f"Token valid after logout: {verified_after_logout is not None}")


if __name__ == "__main__":
    main()
