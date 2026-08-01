# MARS_X_TOKEN_RELAY

Minimal **server-to-server** X OAuth 1.0a access-token exchange relay.

## Endpoints

- `GET /health`
- `POST /api/x-token-exchange`

## Exchange contract

1. `Authorization` header must begin with `OAuth ` (already-signed OAuth 1.0a)
2. `Content-Type: application/x-www-form-urlencoded`
3. Body: **only** `oauth_verifier=<value>` (max 2 KB)
4. Forwards unchanged to locked destination: `https://api.x.com/oauth/access_token`
5. Returns X status, content-type, and body unchanged

## Security

- POST only on exchange
- Destination hardcoded (not client-controlled)
- No secrets stored, no DB, no CORS
- `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`
- Never logs Authorization, body, tokens, verifier, or X response body

## Run locally

```bash
node server.mjs
# GET http://127.0.0.1:8080/health
```

## Vercel

Deploy this repo; routes are under `api/` with `/health` rewritten.
