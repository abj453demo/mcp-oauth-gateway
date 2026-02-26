# MCP OAuth Gateway

## Quick Start

### Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### Create a GitHub OAuth App

1. Go to [GitHub Developer Settings → OAuth Apps → New OAuth App](https://github.com/settings/developers)
2. Set **Authorization callback URL** to `http://localhost:8002/upstream/callback`
3. Fill in any **Application name** and **Homepage URL**
4. Click **Register application**
5. Copy the **Client ID** and generate a **Client Secret**

### Install & Run

```bash
# Clone and install
git clone https://github.com/abj453demo/mcp-oauth-gateway.git
cd mcp-oauth-gateway
uv venv && source .venv/bin/activate
uv pip install -e .

# Start the gateway (proxies to GitHub's remote MCP server)
mcp-oauth-gateway --port=8002 \
  --upstream-rs=https://api.githubcopilot.com/mcp/ \
  --upstream-client-id=<YOUR_GITHUB_CLIENT_ID> \
  --upstream-client-secret=<YOUR_GITHUB_CLIENT_SECRET> \
  --upstream-authorize-endpoint=https://github.com/login/oauth/authorize \
  --upstream-token-endpoint=https://github.com/login/oauth/access_token
```

Replace `<YOUR_GITHUB_CLIENT_ID>` and `<YOUR_GITHUB_CLIENT_SECRET>` with the values from your GitHub OAuth App.

The gateway will be available at `http://localhost:8002`. Point your MCP client at `http://localhost:8002/mcp`.

### Gateway Credentials

When prompted at the gateway login screen (Screen 1):

- **Username:** `gateway_user`
- **Password:** `gateway_pass`

Configurable via `MCP_GATEWAY_USERNAME` and `MCP_GATEWAY_PASSWORD` environment variables.

After gateway login, you'll be redirected to GitHub for OAuth authorization (Screen 2).

---

## Overview

The MCP OAuth Gateway is a transparent proxy that sits between an MCP client and an upstream MCP server (Authorization Server + Resource Server). It implements its own OAuth 2.1 layer and chains it with the upstream's OAuth, so the client sees a single auth surface while two independent token sets are managed behind the scenes.

The gateway acts as both an **Authorization Server** (AS) and a **Resource Server** (RS) to the client. To the upstream, it acts as a regular OAuth client.

```
┌──────────┐       ┌─────────────────────┐       ┌──────────────┐   ┌──────────────┐
│  Client   │──────▶│  Gateway (AS + RS)   │──────▶│  Upstream AS  │   │  Upstream RS  │
│ (Cascade) │◀──────│  :8002               │◀──────│  :9000        │   │  :8001        │
└──────────┘       └─────────────────────┘       └──────────────┘   └──────────────┘
```

## Client Registration

The gateway supports **OAuth 2.0 Dynamic Client Registration** (RFC 7591).

1. Client discovers the gateway via `GET /.well-known/oauth-protected-resource`, which returns the gateway as both the resource and its own authorization server.
2. Client fetches `GET /.well-known/oauth-authorization-server` to learn the gateway's OAuth endpoints (`/authorize`, `/token`, `/register`).
3. Client calls `POST /register` with its redirect URIs and grant types. The gateway stores the client in memory and returns a `client_id` and `client_secret`.

The gateway also registers **itself** as a client with the upstream AS — either via pre-configured credentials (`--upstream-client-id` / `--upstream-client-secret`) or dynamically by calling the upstream's `/register` endpoint on first use.

## Two-Screen Auth Flow

The authorization flow chains two OAuth flows into one client-facing redirect sequence.

```
Client                     Gateway                    Upstream AS
  │                           │                           │
  ├─ GET /authorize ─────────▶│                           │
  │                           ├─ redirect to /login       │
  │◀──────────────────────────┤  (Screen 1: gateway creds)│
  │                           │                           │
  ├─ POST /login/callback ───▶│                           │
  │   (gateway_user/pass)     ├─ redirect to upstream ───▶│
  │                           │  /authorize (Screen 2)    │
  │◀──────────────────────────┤◀──────────────────────────┤
  │                           │                           │
  │  (user logs in upstream)  │                           │
  │───────────────────────────┼──▶ upstream callback ────▶│
  │                           │◀── upstream code ─────────┤
  │                           │                           │
  │                           ├─ exchange upstream code    │
  │                           │  for upstream tokens ─────▶
  │                           │◀── upstream access_token ─┤
  │                           │    + refresh_token        │
  │                           │                           │
  │◀─ redirect with gw code ──┤                           │
  │                           │                           │
  ├─ POST /token (gw code) ──▶│                           │
  │◀── concatenated tokens ───┤                           │
```

### Step-by-step

1. **Client → `GET /authorize`** — Gateway stores the client's redirect URI, PKCE `code_challenge`, and state. Redirects to its own `/login` page.
2. **Screen 1: Gateway login** — User enters gateway credentials. On success, the gateway generates a PKCE pair for the upstream and redirects the user to the upstream AS's `/authorize`.
3. **Screen 2: Upstream login** — User authenticates with the upstream. The upstream AS redirects back to the gateway's `/upstream/callback` with an auth code.
4. **Gateway callback** — The gateway exchanges the upstream auth code for upstream access + refresh tokens (using PKCE). It generates a gateway auth code, stashes the upstream tokens, and redirects back to the client's original `redirect_uri` with the gateway auth code.
5. **Client → `POST /token`** — Client exchanges the gateway auth code (with its own PKCE verifier). The gateway creates its own access + refresh tokens, pairs them with the upstream tokens, and returns **concatenated tokens** to the client.

## Token Format

Tokens returned to the client are base64-encoded pairs:

```
access_token  = base64url( gateway_access_token + ":" + upstream_access_token )
refresh_token = base64url( gateway_refresh_token + ":" + upstream_refresh_token )
```

The client treats these as opaque strings. The gateway splits them on every request to validate the gateway half and forward the upstream half.

`expires_in` is set to `min(gateway_ttl, upstream_ttl)` so the client refreshes before either token expires.

## MCP Proxying

On every `POST /mcp` request:

1. Extract the `Bearer` token from the `Authorization` header.
2. Look up the token record — validate the gateway access token (expiry, revocation).
3. Extract the upstream access token from the pair.
4. Forward the request to the upstream RS with `Authorization: Bearer <upstream_token>`, passing through `Content-Type`, `Accept`, `Mcp-Session-Id`, and `Mcp-Protocol-Version` headers.
5. Stream the upstream response (including SSE) back to the client.

`GET` (SSE streams) and `DELETE` (session teardown) are proxied similarly.

## Token Refresh

The client only interacts with the gateway for refresh — it never contacts the upstream directly.

1. Client sends `POST /token` with `grant_type=refresh_token` and the concatenated refresh token.
2. Gateway splits the refresh token, validates the gateway half.
3. If a real upstream refresh token exists, the gateway calls the upstream AS's `/token` with `grant_type=refresh_token`. If the upstream doesn't use refresh tokens (e.g., GitHub), the existing upstream access token is reused.
4. Gateway revokes old tokens, creates new gateway + upstream pairs, and returns new concatenated tokens.

## In-Memory State

All state is held in memory (no database). Key stores:

| Store | Contents | Lifetime |
|---|---|---|
| `clients` | Registered OAuth clients | Until restart |
| `auth_codes` | Gateway auth codes | Consumed on `/token` exchange |
| `tokens` / `refresh_tokens` | Gateway-issued tokens | Until expiry or revocation |
| `state_mapping` | In-flight authorize flow state | Consumed on callback |
| `upstream_tokens` | Raw upstream token responses | Consumed on `/token` exchange |
| `GatewayTokenStore` | Concatenated token → token pair records | Until expiry or revocation |

## Configuration

| Flag / Env Var | Purpose |
|---|---|
| `--upstream-rs` | Upstream MCP Resource Server URL (required) |
| `--upstream-as` | Upstream AS URL (auto-discovered from RS if omitted) |
| `--upstream-client-id` / `MCP_GATEWAY_UPSTREAM_CLIENT_ID` | Pre-configured upstream client ID (skips dynamic registration) |
| `--upstream-client-secret` / `MCP_GATEWAY_UPSTREAM_CLIENT_SECRET` | Pre-configured upstream client secret |
| `--upstream-authorize-endpoint` / `MCP_GATEWAY_UPSTREAM_AUTHORIZE_ENDPOINT` | Direct upstream authorize URL (skips `.well-known` discovery) |
| `--upstream-token-endpoint` / `MCP_GATEWAY_UPSTREAM_TOKEN_ENDPOINT` | Direct upstream token URL (skips `.well-known` discovery) |
| `MCP_GATEWAY_USERNAME` / `MCP_GATEWAY_PASSWORD` | Gateway login credentials (default: `gateway_user` / `gateway_pass`) |
