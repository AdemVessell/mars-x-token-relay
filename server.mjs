/**
 * MARS_X_TOKEN_RELAY
 * Minimal server-to-server X OAuth 1.0a access-token exchange relay.
 * Destination is locked. No secrets stored. No CORS.
 */
import http from "node:http";

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || "0.0.0.0";
const X_ACCESS_TOKEN_URL = "https://api.x.com/oauth/access_token";
const MAX_BODY_BYTES = 2048;

const SECURITY_HEADERS = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
};

function send(res, status, body, headers = {}) {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type":
      typeof body === "string"
        ? "text/plain; charset=utf-8"
        : "application/json; charset=utf-8",
    ...SECURITY_HEADERS,
    ...headers,
  });
  res.end(payload);
}

function isFormUrlEncoded(contentType) {
  if (!contentType) return false;
  const mediaType = contentType.split(";", 1)[0]?.trim().toLowerCase() ?? "";
  return mediaType === "application/x-www-form-urlencoded";
}

function validateVerifierBody(raw) {
  if (raw.length === 0) return { ok: false };
  if (raw.includes("?") || raw.includes("#")) return { ok: false };
  const pairs = raw.split("&");
  if (pairs.length !== 1) return { ok: false };
  const pair = pairs[0];
  const eq = pair.indexOf("=");
  if (eq <= 0) return { ok: false };
  const key = pair.slice(0, eq);
  if (key !== "oauth_verifier") return { ok: false };
  const value = pair.slice(eq + 1);
  if (value.length === 0) return { ok: false };
  let decoded;
  try {
    decoded = decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return { ok: false };
  }
  if (decoded.length === 0 || decoded.trim().length === 0) return { ok: false };
  return { ok: true, body: raw };
}

function readBodyLimited(req, maxBytes) {
  return new Promise((resolve) => {
    const cl = req.headers["content-length"];
    if (cl !== undefined) {
      const n = Number(cl);
      if (!Number.isFinite(n) || n < 0 || n > maxBytes) {
        resolve({ ok: false, status: 413 });
        return;
      }
    }
    const chunks = [];
    let total = 0;
    let done = false;
    req.on("data", (chunk) => {
      if (done) return;
      total += chunk.length;
      if (total > maxBytes) {
        done = true;
        resolve({ ok: false, status: 413 });
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (done) return;
      done = true;
      resolve({ ok: true, body: Buffer.concat(chunks).toString("utf8") });
    });
    req.on("error", () => {
      if (done) return;
      done = true;
      resolve({ ok: false, status: 400 });
    });
  });
}

async function handleExchange(req, res) {
  if (req.method !== "POST") {
    send(res, 405, "Method Not Allowed");
    return;
  }

  const authorization = req.headers["authorization"];
  if (!authorization || !authorization.startsWith("OAuth ")) {
    send(res, 401, "Unauthorized");
    return;
  }

  const contentType = req.headers["content-type"] ?? null;
  if (!isFormUrlEncoded(contentType)) {
    send(res, 415, "Unsupported Media Type");
    return;
  }

  const bodyResult = await readBodyLimited(req, MAX_BODY_BYTES);
  if (!bodyResult.ok) {
    send(res, bodyResult.status || 413, "Payload Too Large");
    return;
  }

  const validated = validateVerifierBody(bodyResult.body);
  if (!validated.ok) {
    send(res, 400, "Bad Request");
    return;
  }

  let upstream;
  try {
    upstream = await fetch(X_ACCESS_TOKEN_URL, {
      method: "POST",
      headers: {
        Authorization: authorization,
        "Content-Type": contentType,
      },
      body: validated.body,
      redirect: "manual",
    });
  } catch {
    // Never log Authorization, body, tokens, verifier, or upstream body.
    send(res, 502, "Bad Gateway");
    return;
  }

  const upstreamCt = upstream.headers.get("Content-Type");
  const upstreamBody = Buffer.from(await upstream.arrayBuffer());
  const headers = { ...SECURITY_HEADERS };
  if (upstreamCt) headers["Content-Type"] = upstreamCt;
  res.writeHead(upstream.status, headers);
  res.end(upstreamBody);
}

function handleHealth(_req, res) {
  send(res, 200, {
    ok: true,
    service: "MARS_X_TOKEN_RELAY",
    destinationLocked: true,
    storesSecrets: false,
  });
}

const server = http.createServer(async (req, res) => {
  // No CORS headers ever.
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
  if (url.pathname === "/health" && req.method === "GET") {
    handleHealth(req, res);
    return;
  }
  if (url.pathname === "/api/x-token-exchange") {
    await handleExchange(req, res);
    return;
  }
  if (url.pathname === "/" && req.method === "GET") {
    send(
      res,
      200,
      "MARS_X_TOKEN_RELAY\nGET /health\nPOST /api/x-token-exchange\n",
    );
    return;
  }
  send(res, 404, "Not Found");
});

server.listen(PORT, HOST, () => {
  // Operational log only — no request secrets.
  console.log(`MARS_X_TOKEN_RELAY listening on ${HOST}:${PORT}`);
});
