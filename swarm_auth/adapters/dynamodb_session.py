"""
DynamoDB Session Adapter - AWS-native session storage.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import json
from swarm_auth.ports.session_port import SessionPort
from swarm_auth.domain.session import Session, SessionStatus


class DynamoDBSessionAdapter(SessionPort):
    """
    DynamoDB-backed session storage.

    Sessions stored in DynamoDB with TTL-based expiration.
    Requires: pip install boto3
    """

    def __init__(
        self,
        table_name: str = "swarm-it-sessions",
        region_name: str = "us-east-1",
    ):
        """
        Initialize DynamoDB session adapter.

        Args:
            table_name: DynamoDB table name
            region_name: AWS region

        Table schema:
            - Partition key: session_id (S)
            - GSI: user_id-index (user_id as partition key)
            - TTL attribute: expires_at_timestamp
        """
        try:
            import boto3
        except ImportError:
            raise ImportError("boto3 package required: pip install boto3")

        self._table_name = table_name
        dynamodb = boto3.resource("dynamodb", region_name=region_name)
        self._table = dynamodb.Table(table_name)

    def create(
        self,
        user_id: str,
        ttl: int = 3600,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Session:
        """Create a new session in DynamoDB."""
        session = Session.create(user_id=user_id, ttl=ttl, metadata=metadata)

        # Convert to DynamoDB item
        item = self._session_to_item(session)

        # Store in DynamoDB
        self._table.put_item(Item=item)

        return session

    def get(self, session_id: str) -> Optional[Session]:
        """Get a session from DynamoDB."""
        try:
            response = self._table.get_item(Key={"session_id": session_id})

            if "Item" not in response:
                return None

            session = self._item_to_session(response["Item"])

            # Check if expired
            if not session.is_valid():
                self.delete(session_id)
                return None

            return session

        except Exception:
            return None

    def update(self, session_id: str, metadata: Dict[str, Any]) -> bool:
        """Update session metadata."""
        session = self.get(session_id)
        if not session:
            return False

        session.metadata.update(metadata)
        session.update_activity()

        # Update in DynamoDB
        item = self._session_to_item(session)
        self._table.put_item(Item=item)

        return True

    def delete(self, session_id: str) -> bool:
        """Delete a session from DynamoDB."""
        try:
            self._table.delete_item(Key={"session_id": session_id})
            return True
        except Exception:
            return False

    def list_by_user(self, user_id: str) -> List[Session]:
        """List all active sessions for a user."""
        try:
            response = self._table.query(
                IndexName="user_id-index",
                KeyConditionExpression="user_id = :user_id",
                ExpressionAttributeValues={":user_id": user_id},
            )

            sessions = []
            for item in response.get("Items", []):
                session = self._item_to_session(item)
                if session.is_valid():
                    sessions.append(session)
                else:
                    # Clean up expired
                    self.delete(session.session_id)

            return sessions

        except Exception:
            return []

    def extend(self, session_id: str, ttl: int) -> bool:
        """Extend session TTL."""
        session = self.get(session_id)
        if not session:
            return False

        if not session.extend(ttl):
            return False

        # Update in DynamoDB
        item = self._session_to_item(session)
        self._table.put_item(Item=item)

        return True

    def cleanup_expired(self) -> int:
        """
        Clean up expired sessions.

        DynamoDB TTL handles automatic deletion, so this is mostly a no-op.
        Returns 0 since cleanup is handled by DynamoDB.
        """
        return 0

    def _session_to_item(self, session: Session) -> Dict[str, Any]:
        """Convert Session to DynamoDB item."""
        return {
            "session_id": session.session_id,
            "user_id": session.user_id,
            "created_at": session.created_at.isoformat(),
            "expires_at": session.expires_at.isoformat(),
            "expires_at_timestamp": int(session.expires_at.timestamp()),  # For TTL
            "status": session.status.value,
            "ip_address": session.ip_address,
            "user_agent": session.user_agent,
            "last_activity": session.last_activity.isoformat() if session.last_activity else None,
            "metadata": json.dumps(session.metadata),
        }

    def _item_to_session(self, item: Dict[str, Any]) -> Session:
        """Convert DynamoDB item to Session."""
        return Session(
            session_id=item["session_id"],
            user_id=item["user_id"],
            created_at=datetime.fromisoformat(item["created_at"]),
            expires_at=datetime.fromisoformat(item["expires_at"]),
            status=SessionStatus(item["status"]),
            ip_address=item.get("ip_address"),
            user_agent=item.get("user_agent"),
            last_activity=datetime.fromisoformat(item["last_activity"]) if item.get("last_activity") else None,
            metadata=json.loads(item.get("metadata", "{}")),
        )
