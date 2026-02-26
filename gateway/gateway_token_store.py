"""Token store for the MCP Gateway.

Handles concatenation and splitting of gateway + upstream token pairs.
Token format: base64(gateway_token + ":" + upstream_token)
"""

import base64
import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class TokenPair:
    """A paired gateway + upstream token."""

    gateway_token: str
    upstream_token: str


@dataclass
class TokenRecord:
    """Full token record for a gateway session."""

    access: TokenPair
    refresh: TokenPair | None = None
    gateway_expires_at: int | None = None
    upstream_expires_at: int | None = None
    client_id: str = ""
    scopes: list[str] = field(default_factory=list)

    @property
    def min_expires_in(self) -> int | None:
        """Return the minimum TTL across both tokens, or None if unknown."""
        now = int(time.time())
        ttls = []
        if self.gateway_expires_at:
            ttls.append(self.gateway_expires_at - now)
        if self.upstream_expires_at:
            ttls.append(self.upstream_expires_at - now)
        return min(ttls) if ttls else None


def encode_token_pair(gateway_token: str, upstream_token: str) -> str:
    """Concatenate two tokens into a single base64-encoded string."""
    combined = f"{gateway_token}:{upstream_token}"
    return base64.urlsafe_b64encode(combined.encode()).decode()


def decode_token_pair(concatenated: str) -> TokenPair | None:
    """Split a concatenated token back into gateway + upstream parts."""
    try:
        decoded = base64.urlsafe_b64decode(concatenated.encode()).decode()
        parts = decoded.split(":", 1)
        if len(parts) != 2:
            return None
        return TokenPair(gateway_token=parts[0], upstream_token=parts[1])
    except Exception:
        logger.debug("Failed to decode concatenated token")
        return None


class GatewayTokenStore:
    """In-memory store mapping concatenated tokens to their component pairs."""

    def __init__(self):
        self._access_tokens: dict[str, TokenRecord] = {}
        self._refresh_tokens: dict[str, TokenRecord] = {}

    def store(self, record: TokenRecord) -> tuple[str, str | None]:
        """Store a token record and return (concat_access, concat_refresh)."""
        concat_access = encode_token_pair(
            record.access.gateway_token,
            record.access.upstream_token,
        )
        self._access_tokens[concat_access] = record

        concat_refresh = None
        if record.refresh:
            concat_refresh = encode_token_pair(
                record.refresh.gateway_token,
                record.refresh.upstream_token,
            )
            self._refresh_tokens[concat_refresh] = record

        return concat_access, concat_refresh

    def load_access(self, concatenated_token: str) -> TokenRecord | None:
        """Load a token record by its concatenated access token."""
        return self._access_tokens.get(concatenated_token)

    def load_refresh(self, concatenated_token: str) -> TokenRecord | None:
        """Load a token record by its concatenated refresh token."""
        return self._refresh_tokens.get(concatenated_token)

    def revoke_access(self, concatenated_token: str) -> TokenRecord | None:
        """Remove and return an access token record."""
        return self._access_tokens.pop(concatenated_token, None)

    def revoke_refresh(self, concatenated_token: str) -> TokenRecord | None:
        """Remove and return a refresh token record."""
        return self._refresh_tokens.pop(concatenated_token, None)
