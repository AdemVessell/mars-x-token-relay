/**
 * MARS X OAuth 1.0a token-exchange relay.
 *
 * Server-to-server only. Hardcoded destination. No secrets stored.
 * Never log Authorization, request body, tokens, verifier, or upstream body.
 */

const X_ACCESS_TOKEN_URL = "https://api.x.com/oauth/access_token" as const;
const MAX_BODY_BYTES = 2048;

const SECURITY_HEADERS: Record<string, string> = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
};

function plainError(status: number, message: string): Response {
  return new Response(message, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      ...SECURITY_HEADERS,
    },
  });
}

function isFormUrlEncoded(contentType: string | null): boolean {
  if (!contentType) return false;
  const mediaType = contentType.split(";", 1)[0]?.trim().toLowerCase() ?? "";
  return mediaType === "application/x-www-form-urlencoded";
}

/**
 * Accept only a single field: oauth_verifier=<non-empty value>.
 * Reject extra fields, missing verifier, empty value, or malformed pairs.
 * Returns the original body string for unchanged forwarding.
 */
function validateVerifierBody(
  raw: string,
): { ok: true; body: string } | { ok: false } {
  if (raw.length === 0) return { ok: false };

  // Reject query-style separators that should not appear in a pure form body.
  if (raw.includes("?") || raw.includes("#")) return { ok: false };

  const pairs = raw.split("&");
  if (pairs.length !== 1) return { ok: false };

  const pair = pairs[0]!;
  const eq = pair.indexOf("=");
  if (eq <= 0) return { ok: false };

  const key = pair.slice(0, eq);
  if (key !== "oauth_verifier") return { ok: false };

  const value = pair.slice(eq + 1);
  if (value.length === 0) return { ok: false };

  // Verifier must decode to a non-empty string (no bare whitespace-only).
  let decoded: string;
  try {
    decoded = decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return { ok: false };
  }
  if (decoded.length === 0 || decoded.trim().length === 0) return { ok: false };

  return { ok: true, body: raw };
}

async function readBodyLimited(
  request: Request,
  maxBytes: number,
): Promise<{ ok: true; body: string } | { ok: false; status: number }> {
  const contentLength = request.headers.get("Content-Length");
  if (contentLength !== null) {
    const n = Number(contentLength);
    if (!Number.isFinite(n) || n < 0 || n > maxBytes) {
      return { ok: false, status: 413 };
    }
  }

  if (!request.body) {
    return { ok: true, body: "" };
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > maxBytes) {
      try {
        await reader.cancel();
      } catch {
        // ignore cancel errors
      }
      return { ok: false, status: 413 };
    }
    chunks.push(value);
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return { ok: true, body: new TextDecoder("utf-8").decode(merged) };
}

/**
 * POST /api/x-token-exchange
 * Forwards a pre-signed OAuth 1.0a access-token request to X.
 * Destination is locked; never accepts a client-supplied URL.
 */
export async function handleXTokenExchange(request: Request): Promise<Response> {
  if (request.method !== "POST") {
    return plainError(405, "Method Not Allowed");
  }

  const authorization = request.headers.get("Authorization");
  if (!authorization || !authorization.startsWith("OAuth ")) {
    return plainError(401, "Unauthorized");
  }

  const contentType = request.headers.get("Content-Type");
  if (!isFormUrlEncoded(contentType)) {
    return plainError(415, "Unsupported Media Type");
  }

  const bodyResult = await readBodyLimited(request, MAX_BODY_BYTES);
  if (!bodyResult.ok) {
    return plainError(bodyResult.status, "Payload Too Large");
  }

  const validated = validateVerifierBody(bodyResult.body);
  if (!validated.ok) {
    return plainError(400, "Bad Request");
  }

  // Hardcoded destination only — never take a URL from the client.
  let upstream: Response;
  try {
    upstream = await fetch(X_ACCESS_TOKEN_URL, {
      method: "POST",
      headers: {
        Authorization: authorization,
        "Content-Type": contentType!,
      },
      body: validated.body,
      redirect: "manual",
    });
  } catch {
    // Do not log request details.
    return plainError(502, "Bad Gateway");
  }

  const upstreamContentType = upstream.headers.get("Content-Type");
  const upstreamBody = await upstream.arrayBuffer();

  const headers = new Headers(SECURITY_HEADERS);
  if (upstreamContentType) {
    headers.set("Content-Type", upstreamContentType);
  }

  return new Response(upstreamBody, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers,
  });
}

/** GET /health */
export function handleHealth(): Response {
  const payload = {
    ok: true,
    service: "MARS_X_TOKEN_RELAY",
    destinationLocked: true,
    storesSecrets: false,
  };
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...SECURITY_HEADERS,
    },
  });
}

/** Locked destination — exported for assertions only. */
export const DESTINATION_LOCKED = X_ACCESS_TOKEN_URL;
