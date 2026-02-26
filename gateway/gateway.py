"""MCP Gateway with OAuth 2.0.

Sits between the MCP client and an upstream MCP server (AS + RS).
Implements its own OAuth layer and proxies MCP requests, concatenating
tokens so the client sees a single OAuth surface.

Run with: mcp-oauth-gateway --port=8002 --upstream-rs=http://localhost:8001

Upstream AS is auto-discovered from the RS's .well-known/oauth-protected-resource.
Upstream client credentials can be pre-configured via CLI flags or env vars.
"""

import asyncio
import logging
import time
from typing import Literal

import click
import httpx
from pydantic import AnyHttpUrl, BaseModel
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route
from uvicorn import Config, Server

from mcp.server.auth.routes import cors_middleware, create_auth_routes
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions

from .gateway_provider import GatewayOAuthProvider, GatewaySettings

logger = logging.getLogger(__name__)


class GatewayServerSettings(BaseModel):
    host: str = "localhost"
    port: int = 8002
    server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:8002")
    upstream_rs_url: str = "http://localhost:8001"
    upstream_as_url: str | None = None


def create_gateway_server(
    server_settings: GatewayServerSettings,
    gateway_settings: GatewaySettings,
) -> Starlette:
    provider = GatewayOAuthProvider(
        settings=gateway_settings,
        server_url=str(server_settings.server_url),
        upstream_rs_url=server_settings.upstream_rs_url,
        upstream_as_url=server_settings.upstream_as_url,
    )

    mcp_auth_settings = AuthSettings(
        issuer_url=server_settings.server_url,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=None,
            default_scopes=None,
        ),
        required_scopes=[],
        resource_server_url=server_settings.server_url,
    )

    # Build OAuth routes (metadata, authorize, token, register)
    routes = create_auth_routes(
        provider=provider,
        issuer_url=mcp_auth_settings.issuer_url,
        service_documentation_url=mcp_auth_settings.service_documentation_url,
        client_registration_options=mcp_auth_settings.client_registration_options,
        revocation_options=mcp_auth_settings.revocation_options,
    )

    # Protected resource metadata (RFC 9728)
    async def protected_resource_metadata(request: Request) -> Response:
        return JSONResponse({
            "resource": str(server_settings.server_url),
            "authorization_servers": [str(server_settings.server_url)],
            "scopes_supported": [],
            "bearer_methods_supported": ["header"],
        })

    routes.append(Route(
        "/.well-known/oauth-protected-resource",
        endpoint=cors_middleware(protected_resource_metadata, ["GET", "OPTIONS"]),
        methods=["GET", "OPTIONS"],
    ))

    # Gateway login page
    async def login_page_handler(request: Request) -> Response:
        state = request.query_params.get("state")
        if not state:
            return JSONResponse({"error": "Missing state parameter"}, status_code=400)
        return await provider.get_login_page(state)

    routes.append(Route("/login", endpoint=login_page_handler, methods=["GET"]))

    # Gateway login callback
    async def login_callback_handler(request: Request) -> Response:
        return await provider.handle_login_callback(request)

    routes.append(Route("/login/callback", endpoint=login_callback_handler, methods=["POST"]))

    # Upstream OAuth callback
    async def upstream_callback_handler(request: Request) -> Response:
        return await provider.handle_upstream_callback(request)

    routes.append(Route("/upstream/callback", endpoint=upstream_callback_handler, methods=["GET"]))

    # Introspection endpoint for internal use
    async def introspect_handler(request: Request) -> Response:
        form = await request.form()
        token = form.get("token")
        if not token or not isinstance(token, str):
            return JSONResponse({"active": False}, status_code=400)

        access_token = await provider.load_access_token(token)
        if not access_token:
            return JSONResponse({"active": False})

        return JSONResponse({
            "active": True,
            "client_id": access_token.client_id,
            "scope": " ".join(access_token.scopes),
            "exp": access_token.expires_at,
            "iat": int(time.time()),
            "token_type": "Bearer",
        })

    routes.append(
        Route(
            "/introspect",
            endpoint=cors_middleware(introspect_handler, ["POST", "OPTIONS"]),
            methods=["POST", "OPTIONS"],
        )
    )

    # MCP proxy endpoint
    upstream_mcp_url = server_settings.upstream_rs_url.rstrip('/')

    async def mcp_proxy_handler(request: Request) -> Response:
        """Proxy MCP requests to the upstream Resource Server."""
        # Extract and validate the concatenated Bearer token
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                {"error": "missing_token", "error_description": "Bearer token required"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        concat_token = auth_header[7:]

        # Validate the gateway portion
        access_token = await provider.load_access_token(concat_token)
        if not access_token:
            return JSONResponse(
                {"error": "invalid_token", "error_description": "Token is invalid or expired"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Extract the upstream token
        upstream_token = provider.get_upstream_token(concat_token)
        if not upstream_token:
            return JSONResponse(
                {"error": "invalid_token", "error_description": "Upstream token not found"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Build upstream headers
        upstream_headers: dict[str, str] = {
            "Authorization": f"Bearer {upstream_token}",
        }
        for key in ["content-type", "accept", "mcp-session-id", "mcp-protocol-version", "last-event-id"]:
            if key in request.headers:
                upstream_headers[key] = request.headers[key]

        body = await request.body()

        if request.method == "POST":
            return await _proxy_post(upstream_mcp_url, body, upstream_headers)
        elif request.method == "GET":
            return await _proxy_get(upstream_mcp_url, upstream_headers)
        elif request.method == "DELETE":
            return await _proxy_delete(upstream_mcp_url, upstream_headers)
        else:
            return JSONResponse({"error": "Method not allowed"}, status_code=405)

    routes.append(Route("/mcp", endpoint=mcp_proxy_handler, methods=["GET", "POST", "DELETE"]))

    return Starlette(routes=routes)


async def _proxy_post(url: str, body: bytes, headers: dict[str, str]) -> Response:
    """Forward a POST request to the upstream MCP server, streaming the response."""
    client = httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=10.0))
    try:
        upstream_resp = await client.send(
            client.build_request("POST", url, content=body, headers=headers),
            stream=True,
        )
    except Exception as e:
        await client.aclose()
        logger.error(f"Upstream POST failed: {e}")
        return JSONResponse({"error": "upstream_error"}, status_code=502)

    content_type = upstream_resp.headers.get("content-type", "")
    resp_headers = _filter_response_headers(upstream_resp.headers)

    if "text/event-stream" in content_type:
        # Stream SSE back to client
        async def stream_sse():
            try:
                async for chunk in upstream_resp.aiter_bytes():
                    yield chunk
            finally:
                await upstream_resp.aclose()
                await client.aclose()

        return StreamingResponse(
            stream_sse(),
            status_code=upstream_resp.status_code,
            headers=resp_headers,
            media_type="text/event-stream",
        )
    else:
        # Non-streaming response (202 Accepted or JSON)
        response_body = await upstream_resp.aread()
        await upstream_resp.aclose()
        await client.aclose()
        return Response(
            content=response_body,
            status_code=upstream_resp.status_code,
            headers=resp_headers,
        )


async def _proxy_get(url: str, headers: dict[str, str]) -> Response:
    """Forward a GET request (SSE stream) to the upstream MCP server."""
    client = httpx.AsyncClient(timeout=httpx.Timeout(None, connect=10.0))
    try:
        upstream_resp = await client.send(
            client.build_request("GET", url, headers=headers),
            stream=True,
        )
    except Exception as e:
        await client.aclose()
        logger.error(f"Upstream GET failed: {e}")
        return JSONResponse({"error": "upstream_error"}, status_code=502)

    resp_headers = _filter_response_headers(upstream_resp.headers)

    async def stream_sse():
        try:
            async for chunk in upstream_resp.aiter_bytes():
                yield chunk
        finally:
            await upstream_resp.aclose()
            await client.aclose()

    return StreamingResponse(
        stream_sse(),
        status_code=upstream_resp.status_code,
        headers=resp_headers,
        media_type="text/event-stream",
    )


async def _proxy_delete(url: str, headers: dict[str, str]) -> Response:
    """Forward a DELETE request to the upstream MCP server."""
    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0)) as client:
        try:
            resp = await client.delete(url, headers=headers)
        except Exception as e:
            logger.error(f"Upstream DELETE failed: {e}")
            return JSONResponse({"error": "upstream_error"}, status_code=502)

        resp_headers = _filter_response_headers(resp.headers)
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=resp_headers,
        )


def _filter_response_headers(headers: httpx.Headers) -> dict[str, str]:
    """Filter upstream response headers to forward to the client."""
    forward = {}
    for key in ["content-type", "mcp-session-id", "mcp-protocol-version", "cache-control", "pragma"]:
        if key in headers:
            forward[key] = headers[key]
    return forward


async def _run_server(server_settings: GatewayServerSettings, gateway_settings: GatewaySettings):
    app = create_gateway_server(server_settings, gateway_settings)
    config = Config(app, host=server_settings.host, port=server_settings.port, log_level="info")
    server = Server(config)
    logger.info(f"Gateway running on {server_settings.server_url}")
    logger.info(f"Upstream RS: {server_settings.upstream_rs_url}")
    logger.info(f"Upstream AS: {server_settings.upstream_as_url or '(auto-discover)'}")
    await server.serve()


@click.command()
@click.option("--port", default=8002, help="Port to listen on")
@click.option("--host", default="localhost", help="Host to bind to")
@click.option("--upstream-rs", required=True, help="Upstream MCP Resource Server URL")
@click.option("--upstream-as", default=None, help="Upstream Authorization Server URL (auto-discovered if omitted)")
@click.option("--upstream-client-id", default=None, envvar="MCP_GATEWAY_UPSTREAM_CLIENT_ID",
              help="Pre-configured upstream OAuth client ID (skips dynamic registration)")
@click.option("--upstream-client-secret", default=None, envvar="MCP_GATEWAY_UPSTREAM_CLIENT_SECRET",
              help="Pre-configured upstream OAuth client secret")
@click.option("--upstream-authorize-endpoint", default=None, envvar="MCP_GATEWAY_UPSTREAM_AUTHORIZE_ENDPOINT",
              help="Upstream OAuth authorize endpoint URL (skips .well-known discovery)")
@click.option("--upstream-token-endpoint", default=None, envvar="MCP_GATEWAY_UPSTREAM_TOKEN_ENDPOINT",
              help="Upstream OAuth token endpoint URL (skips .well-known discovery)")
def main(port: int, host: str, upstream_rs: str, upstream_as: str | None,
         upstream_client_id: str | None, upstream_client_secret: str | None,
         upstream_authorize_endpoint: str | None, upstream_token_endpoint: str | None) -> int:
    """Run the MCP Gateway with OAuth 2.0."""
    logging.basicConfig(level=logging.INFO)
    gateway_settings = GatewaySettings(
        upstream_client_id=upstream_client_id,
        upstream_client_secret=upstream_client_secret,
        upstream_authorize_endpoint=upstream_authorize_endpoint,
        upstream_token_endpoint=upstream_token_endpoint,
    )
    server_url = f"http://{host}:{port}"
    server_settings = GatewayServerSettings(
        host=host,
        port=port,
        server_url=AnyHttpUrl(server_url),
        upstream_rs_url=upstream_rs,
        upstream_as_url=upstream_as,
    )
    asyncio.run(_run_server(server_settings, gateway_settings))
    return 0


if __name__ == "__main__":
    main()
