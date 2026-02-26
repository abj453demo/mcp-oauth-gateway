"""Gateway OAuth provider that chains to an upstream Authorization Server.

Implements its own OAuth layer for the client, and during the authorize flow
redirects the user to the upstream AS for a second login. Concatenates both
sets of tokens so the client sees a single OAuth surface.
"""

import hashlib
import base64
import logging
import secrets
import time
import urllib.parse
from typing import Any

import httpx
from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from .gateway_token_store import (
    GatewayTokenStore,
    TokenPair,
    TokenRecord,
    decode_token_pair,
)

logger = logging.getLogger(__name__)


class UpstreamEndpoints:
    """Discovered or configured upstream OAuth endpoints."""

    def __init__(
        self,
        authorization_endpoint: str,
        token_endpoint: str,
        scopes_supported: list[str] | None = None,
    ):
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self.scopes_supported = scopes_supported


class GatewaySettings(BaseSettings):
    """Gateway settings, configurable via MCP_GATEWAY_ environment variables."""

    model_config = SettingsConfigDict(env_prefix="MCP_GATEWAY_")

    username: str = "gateway_user"
    password: str = "gateway_pass"
    mcp_scope: str = "mcp"

    # Pre-configured upstream client credentials (skip dynamic registration)
    upstream_client_id: str | None = None
    upstream_client_secret: str | None = None

    # Direct upstream endpoint overrides (skip .well-known discovery)
    upstream_authorize_endpoint: str | None = None
    upstream_token_endpoint: str | None = None


class GatewayOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    """OAuth provider for the gateway that chains to an upstream AS."""

    def __init__(
        self,
        settings: GatewaySettings,
        server_url: str,
        upstream_rs_url: str,
        upstream_as_url: str | None = None,
    ):
        self.settings = settings
        self.server_url = server_url.rstrip("/")
        self.upstream_rs_url = upstream_rs_url.rstrip("/")
        self.upstream_as_url = upstream_as_url.rstrip("/") if upstream_as_url else None

        # Gateway's own OAuth stores
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.tokens: dict[str, AccessToken] = {}
        self.refresh_tokens: dict[str, RefreshToken] = {}

        # State tracking for the chained auth flow
        self.state_mapping: dict[str, dict[str, str | None]] = {}
        # Maps upstream state → gateway state for the callback
        self.upstream_state_mapping: dict[str, str] = {}
        # Stores upstream PKCE verifiers by gateway state
        self.upstream_pkce: dict[str, str] = {}
        # Stores upstream tokens by gateway auth code
        self.upstream_tokens: dict[str, dict[str, Any]] = {}

        # Upstream client credentials (pre-configured or dynamically registered)
        self._upstream_client_id: str | None = settings.upstream_client_id
        self._upstream_client_secret: str | None = settings.upstream_client_secret

        # Discovered upstream endpoints (lazily populated)
        self._upstream_endpoints: UpstreamEndpoints | None = None

        # Concatenated token store
        self.token_store = GatewayTokenStore()

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull):
        if not client_info.client_id:
            raise ValueError("No client_id provided")
        self.clients[client_info.client_id] = client_info

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        state = params.state or secrets.token_hex(16)
        self.state_mapping[state] = {
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "redirect_uri_provided_explicitly": str(params.redirect_uri_provided_explicitly),
            "client_id": client.client_id,
            "resource": params.resource,
        }
        return f"{self.server_url}/login?state={state}&client_id={client.client_id}"

    async def get_login_page(self, state: str) -> HTMLResponse:
        if not state:
            raise HTTPException(400, "Missing state parameter")
        html = f"""<!DOCTYPE html>
<html>
<head>
  <title>Gateway OAuth Login</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 420px; margin: 60px auto; padding: 0 20px; }}
    h2 {{ color: #333; }}
    .badge {{ display: inline-block; background: #f59e0b; color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }}
    .hint {{ background: #fef3c7; padding: 12px; border-radius: 6px; margin-bottom: 20px; font-size: 14px; }}
    .form-group {{ margin-bottom: 14px; }}
    label {{ display: block; font-weight: 600; margin-bottom: 4px; }}
    input {{ width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }}
    button {{ background: #f59e0b; color: #fff; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 15px; }}
    button:hover {{ background: #d97706; }}
    .note {{ margin-top: 16px; font-size: 13px; color: #666; }}
  </style>
</head>
<body>
  <h2><span class="badge">GATEWAY</span> OAuth Login</h2>
  <div class="hint">
    <strong>Gateway credentials:</strong><br>
    Username: <code>{self.settings.username}</code><br>
    Password: <code>{self.settings.password}</code>
  </div>
  <form action="{self.server_url}/login/callback" method="post">
    <input type="hidden" name="state" value="{state}">
    <div class="form-group">
      <label>Username</label>
      <input type="text" name="username" value="{self.settings.username}" required>
    </div>
    <div class="form-group">
      <label>Password</label>
      <input type="password" name="password" value="{self.settings.password}" required>
    </div>
    <button type="submit">Sign In to Gateway</button>
  </form>
  <p class="note">After signing in here, you will be redirected to the upstream MCP server for a second authentication.</p>
</body>
</html>"""
        return HTMLResponse(content=html)

    async def handle_login_callback(self, request: Request) -> Response:
        """Handle gateway login form submission, then redirect to upstream AS."""
        form = await request.form()
        username = form.get("username")
        password = form.get("password")
        state = form.get("state")

        if not username or not password or not state:
            raise HTTPException(400, "Missing username, password, or state")
        if not isinstance(username, str) or not isinstance(password, str) or not isinstance(state, str):
            raise HTTPException(400, "Invalid parameter types")

        if username != self.settings.username or password != self.settings.password:
            raise HTTPException(401, "Invalid gateway credentials")

        state_data = self.state_mapping.get(state)
        if not state_data:
            raise HTTPException(400, "Invalid state parameter")

        # Gateway login succeeded. Now redirect to upstream AS.
        upstream_redirect_url = await self._initiate_upstream_auth(state)
        return RedirectResponse(url=upstream_redirect_url, status_code=302)

    async def _discover_upstream_endpoints(self) -> UpstreamEndpoints:
        """Discover upstream AS endpoints via .well-known metadata or direct config."""
        if self._upstream_endpoints:
            return self._upstream_endpoints

        # If endpoints are directly configured, use them (skip discovery)
        if self.settings.upstream_authorize_endpoint and self.settings.upstream_token_endpoint:
            self._upstream_endpoints = UpstreamEndpoints(
                authorization_endpoint=self.settings.upstream_authorize_endpoint,
                token_endpoint=self.settings.upstream_token_endpoint,
                scopes_supported=None,
            )
            logger.info(
                f"Using configured upstream endpoints: "
                f"authorize={self.settings.upstream_authorize_endpoint}, "
                f"token={self.settings.upstream_token_endpoint}"
            )
            return self._upstream_endpoints

        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            # Step 1: If no AS URL, discover it from the upstream RS
            as_url = self.upstream_as_url
            if not as_url:
                logger.info(f"Discovering upstream AS from RS: {self.upstream_rs_url}")
                resp = await client.get(
                    f"{self.upstream_rs_url}/.well-known/oauth-protected-resource"
                )
                if resp.status_code != 200:
                    raise HTTPException(502, "Failed to discover upstream protected resource metadata")
                pr_meta = resp.json()
                auth_servers = pr_meta.get("authorization_servers", [])
                if not auth_servers:
                    raise HTTPException(502, "Upstream RS did not advertise any authorization servers")
                as_url = str(auth_servers[0]).rstrip("/")
                self.upstream_as_url = as_url
                logger.info(f"Discovered upstream AS: {as_url}")

            # Step 2: Fetch AS metadata
            logger.info(f"Fetching upstream AS metadata from: {as_url}")
            resp = await client.get(
                f"{as_url}/.well-known/oauth-authorization-server"
            )
            if resp.status_code != 200:
                raise HTTPException(502, f"Failed to fetch upstream AS metadata (status {resp.status_code})")

            as_meta = resp.json()
            authorization_endpoint = as_meta.get("authorization_endpoint")
            token_endpoint = as_meta.get("token_endpoint")
            if not authorization_endpoint or not token_endpoint:
                raise HTTPException(502, "Upstream AS metadata missing required endpoints")

            scopes_supported = as_meta.get("scopes_supported")

            self._upstream_endpoints = UpstreamEndpoints(
                authorization_endpoint=authorization_endpoint,
                token_endpoint=token_endpoint,
                scopes_supported=scopes_supported,
            )
            logger.info(
                f"Upstream endpoints discovered: authorize={authorization_endpoint}, "
                f"token={token_endpoint}, scopes={scopes_supported}"
            )

        return self._upstream_endpoints

    async def _ensure_upstream_registration(self) -> UpstreamEndpoints:
        """Ensure we have upstream endpoints and client credentials."""
        endpoints = await self._discover_upstream_endpoints()

        # If client credentials are pre-configured, skip registration
        if self._upstream_client_id:
            return endpoints

        # Dynamic registration fallback
        assert self.upstream_as_url is not None
        callback_url = f"{self.server_url}/upstream/callback"
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.upstream_as_url}/register",
                json={
                    "redirect_uris": [callback_url],
                    "client_name": "MCP Gateway",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "client_secret_post",
                },
            )
            if resp.status_code != 201:
                logger.error(f"Upstream registration failed: {resp.status_code} {resp.text}")
                raise HTTPException(502, "Failed to register with upstream AS")

            data = resp.json()
            self._upstream_client_id = data["client_id"]
            self._upstream_client_secret = data.get("client_secret")
            logger.info(f"Registered with upstream AS as client {self._upstream_client_id}")

        return endpoints

    async def _initiate_upstream_auth(self, gateway_state: str) -> str:
        """Build the upstream /authorize URL with PKCE."""
        endpoints = await self._ensure_upstream_registration()

        # Generate PKCE for upstream
        code_verifier = secrets.token_urlsafe(64)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip("=")

        upstream_state = secrets.token_hex(16)
        self.upstream_state_mapping[upstream_state] = gateway_state
        self.upstream_pkce[gateway_state] = code_verifier

        callback_url = f"{self.server_url}/upstream/callback"

        params: dict[str, str] = {
            "response_type": "code",
            "client_id": self._upstream_client_id or "",
            "redirect_uri": callback_url,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": upstream_state,
        }
        # Use upstream's supported scopes if discovered, otherwise omit
        if endpoints.scopes_supported:
            params["scope"] = " ".join(endpoints.scopes_supported)

        query = urllib.parse.urlencode(params)
        return f"{endpoints.authorization_endpoint}?{query}"

    async def handle_upstream_callback(self, request: Request) -> Response:
        """Handle the callback from the upstream AS after user authenticates."""
        upstream_state = request.query_params.get("state")
        code = request.query_params.get("code")
        error = request.query_params.get("error")

        if error:
            raise HTTPException(502, f"Upstream auth error: {error}")
        if not upstream_state or not code:
            raise HTTPException(400, "Missing state or code from upstream")

        gateway_state = self.upstream_state_mapping.pop(upstream_state, None)
        if not gateway_state:
            raise HTTPException(400, "Unknown upstream state")

        state_data = self.state_mapping.get(gateway_state)
        if not state_data:
            raise HTTPException(400, "Gateway state expired")

        # Exchange upstream auth code for tokens
        code_verifier = self.upstream_pkce.pop(gateway_state, None)
        if not code_verifier:
            raise HTTPException(500, "Missing PKCE verifier for upstream")

        upstream_tokens = await self._exchange_upstream_code(code, code_verifier)

        # Generate gateway auth code
        gw_code = f"gw_{secrets.token_hex(16)}"
        redirect_uri = state_data["redirect_uri"]
        code_challenge = state_data["code_challenge"]
        redirect_uri_provided_explicitly = state_data["redirect_uri_provided_explicitly"] == "True"
        client_id = state_data["client_id"]
        resource = state_data.get("resource")

        assert redirect_uri is not None
        assert code_challenge is not None
        assert client_id is not None

        self.auth_codes[gw_code] = AuthorizationCode(
            code=gw_code,
            client_id=client_id,
            redirect_uri=AnyHttpUrl(redirect_uri),
            redirect_uri_provided_explicitly=redirect_uri_provided_explicitly,
            expires_at=time.time() + 300,
            scopes=[self.settings.mcp_scope],
            code_challenge=code_challenge,
            resource=resource,
        )

        # Store upstream tokens keyed by gateway auth code
        self.upstream_tokens[gw_code] = upstream_tokens

        del self.state_mapping[gateway_state]

        final_redirect = construct_redirect_uri(redirect_uri, code=gw_code, state=gateway_state)
        return RedirectResponse(url=final_redirect, status_code=302)

    async def _exchange_upstream_code(self, code: str, code_verifier: str) -> dict[str, Any]:
        """Exchange an upstream auth code for tokens."""
        endpoints = await self._discover_upstream_endpoints()
        callback_url = f"{self.server_url}/upstream/callback"

        data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": callback_url,
            "client_id": self._upstream_client_id or "",
            "code_verifier": code_verifier,
        }
        if self._upstream_client_secret:
            data["client_secret"] = self._upstream_client_secret

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                endpoints.token_endpoint,
                data=data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
            )
            if resp.status_code != 200:
                logger.error(f"Upstream token exchange failed: {resp.status_code} {resp.text}")
                raise HTTPException(502, "Failed to exchange upstream auth code")
            return self._parse_token_response(resp)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        return self.auth_codes.get(authorization_code)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        if authorization_code.code not in self.auth_codes:
            raise ValueError("Invalid authorization code")
        if not client.client_id:
            raise ValueError("No client_id provided")

        # Retrieve upstream tokens
        upstream = self.upstream_tokens.pop(authorization_code.code, None)
        if not upstream:
            raise ValueError("No upstream tokens found for this auth code")

        # Create gateway's own tokens
        gw_access_str = f"gw_{secrets.token_hex(32)}"
        gw_refresh_str = f"gw_rt_{secrets.token_hex(32)}"
        now = int(time.time())

        self.tokens[gw_access_str] = AccessToken(
            token=gw_access_str,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=now + 60,
            resource=authorization_code.resource,
        )

        self.refresh_tokens[gw_refresh_str] = RefreshToken(
            token=gw_refresh_str,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=now + 86400,
        )

        upstream_access = upstream["access_token"]
        upstream_refresh = upstream.get("refresh_token")
        upstream_expires_in = upstream.get("expires_in", 3600)
        logger.info(f"Upstream token received: has_refresh={upstream_refresh is not None}, expires_in={upstream_expires_in}")

        # Store concatenated tokens
        # If upstream has no refresh token, store the upstream access token
        # as the refresh upstream component (GitHub tokens don't expire)
        record = TokenRecord(
            access=TokenPair(gateway_token=gw_access_str, upstream_token=upstream_access),
            refresh=TokenPair(gateway_token=gw_refresh_str, upstream_token=upstream_refresh or upstream_access),
            gateway_expires_at=now + 60,
            upstream_expires_at=now + upstream_expires_in if upstream_expires_in else None,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
        )
        concat_access, concat_refresh = self.token_store.store(record)

        del self.auth_codes[authorization_code.code]

        effective_expires_in = record.min_expires_in or 3600

        return OAuthToken(
            access_token=concat_access,
            token_type="Bearer",
            expires_in=effective_expires_in,
            scope=" ".join(authorization_code.scopes),
            refresh_token=concat_refresh,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Load and validate a concatenated access token."""
        record = self.token_store.load_access(token)
        if not record:
            return None

        # Validate gateway portion
        gw_token = self.tokens.get(record.access.gateway_token)
        if not gw_token:
            self.token_store.revoke_access(token)
            return None
        if gw_token.expires_at and gw_token.expires_at < time.time():
            del self.tokens[record.access.gateway_token]
            self.token_store.revoke_access(token)
            return None

        # Return an AccessToken with the concatenated token as the identifier
        return AccessToken(
            token=token,
            client_id=gw_token.client_id,
            scopes=gw_token.scopes,
            expires_at=gw_token.expires_at,
            resource=gw_token.resource,
        )

    def get_upstream_token(self, concatenated_token: str) -> str | None:
        """Extract the upstream access token from a concatenated token."""
        record = self.token_store.load_access(concatenated_token)
        if not record:
            return None
        return record.access.upstream_token

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        logger.info(f"🔄 load_refresh_token called for client {client.client_id}")
        record = self.token_store.load_refresh(refresh_token)
        if not record:
            logger.warning("🔄 Refresh failed: no record found in token store")
            return None
        if not record.refresh:
            logger.warning("🔄 Refresh failed: record has no refresh token pair")
            return None

        gw_rt = self.refresh_tokens.get(record.refresh.gateway_token)
        if not gw_rt:
            logger.warning("🔄 Refresh failed: gateway refresh token not found")
            self.token_store.revoke_refresh(refresh_token)
            return None
        if gw_rt.expires_at and gw_rt.expires_at < time.time():
            logger.warning("🔄 Refresh failed: gateway refresh token expired")
            del self.refresh_tokens[gw_rt.token]
            self.token_store.revoke_refresh(refresh_token)
            return None
        if gw_rt.client_id != client.client_id:
            logger.warning(f"🔄 Refresh failed: client_id mismatch ({gw_rt.client_id} != {client.client_id})")
            return None
        logger.info("🔄 load_refresh_token succeeded")

        # Return a RefreshToken with the concatenated token as identifier
        return RefreshToken(
            token=refresh_token,
            client_id=gw_rt.client_id,
            scopes=gw_rt.scopes,
            expires_at=gw_rt.expires_at,
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        if not client.client_id:
            raise ValueError("No client_id provided")

        logger.info(f"🔄 REFRESH TOKEN triggered for client {client.client_id}")

        # Load the record from the store
        record = self.token_store.load_refresh(refresh_token.token)
        if not record or not record.refresh:
            raise ValueError("Invalid refresh token")

        # Refresh upstream token if we have a real upstream refresh token,
        # otherwise reuse the existing upstream access token (e.g. GitHub tokens don't expire)
        upstream_refresh = record.refresh.upstream_token
        # Check if this looks like an upstream access token (no refresh available)
        upstream_access_token = record.access.upstream_token
        if upstream_refresh != upstream_access_token:
            new_upstream = await self._refresh_upstream_token(upstream_refresh)
        else:
            logger.info("🔄 No upstream refresh token; reusing upstream access token")
            new_upstream = {"access_token": upstream_access_token}

        # Revoke old gateway tokens
        old_gw_refresh = record.refresh.gateway_token
        old_gw_access = record.access.gateway_token
        self.refresh_tokens.pop(old_gw_refresh, None)
        self.tokens.pop(old_gw_access, None)
        self.token_store.revoke_refresh(refresh_token.token)

        # Create new gateway tokens
        new_gw_access = f"gw_{secrets.token_hex(32)}"
        new_gw_refresh = f"gw_rt_{secrets.token_hex(32)}"
        now = int(time.time())
        effective_scopes = scopes if scopes else refresh_token.scopes

        self.tokens[new_gw_access] = AccessToken(
            token=new_gw_access,
            client_id=client.client_id,
            scopes=effective_scopes,
            expires_at=now + 60,
        )

        self.refresh_tokens[new_gw_refresh] = RefreshToken(
            token=new_gw_refresh,
            client_id=client.client_id,
            scopes=effective_scopes,
            expires_at=now + 86400,
        )

        upstream_access = new_upstream["access_token"]
        upstream_rt = new_upstream.get("refresh_token")
        upstream_expires_in = new_upstream.get("expires_in", 3600)

        new_record = TokenRecord(
            access=TokenPair(gateway_token=new_gw_access, upstream_token=upstream_access),
            refresh=TokenPair(gateway_token=new_gw_refresh, upstream_token=upstream_rt or upstream_access),
            gateway_expires_at=now + 60,
            upstream_expires_at=now + upstream_expires_in if upstream_expires_in else None,
            client_id=client.client_id,
            scopes=effective_scopes,
        )
        concat_access, concat_refresh = self.token_store.store(new_record)

        effective_expires_in = new_record.min_expires_in or 3600

        return OAuthToken(
            access_token=concat_access,
            token_type="Bearer",
            expires_in=effective_expires_in,
            scope=" ".join(effective_scopes),
            refresh_token=concat_refresh,
        )

    @staticmethod
    def _parse_token_response(resp: httpx.Response) -> dict[str, Any]:
        """Parse a token response that may be JSON or form-encoded."""
        content_type = resp.headers.get("content-type", "")
        text = resp.text.strip()
        if "application/json" in content_type or text.startswith("{"):
            return resp.json()
        # Fall back to form-encoded (e.g. GitHub)
        parsed = urllib.parse.parse_qs(text)
        return {k: v[0] for k, v in parsed.items()}

    async def _refresh_upstream_token(self, upstream_refresh_token: str) -> dict[str, Any]:
        """Refresh an upstream token via the upstream AS."""
        endpoints = await self._discover_upstream_endpoints()

        data: dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": upstream_refresh_token,
            "client_id": self._upstream_client_id or "",
        }
        if self._upstream_client_secret:
            data["client_secret"] = self._upstream_client_secret

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                endpoints.token_endpoint,
                data=data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
            )
            if resp.status_code != 200:
                logger.error(f"Upstream refresh failed: {resp.status_code} {resp.text}")
                raise ValueError("Failed to refresh upstream token")
            return self._parse_token_response(resp)

    async def revoke_token(self, token: str, token_type_hint: str | None = None) -> None:  # type: ignore
        # Try revoking as access token
        record = self.token_store.revoke_access(token)
        if record:
            self.tokens.pop(record.access.gateway_token, None)
            return

        # Try revoking as refresh token
        record = self.token_store.revoke_refresh(token)
        if record and record.refresh:
            self.refresh_tokens.pop(record.refresh.gateway_token, None)
