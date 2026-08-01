const X_ACCESS_TOKEN_URL = "https://api.x.com/oauth/access_token";
const MAX_BODY_BYTES = 2048;
const SECURITY_HEADERS = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
};

function isFormUrlEncoded(contentType) {
  if (!contentType) return false;
  const mediaType = contentType.split(";", 1)[0]?.trim().toLowerCase() ?? "";
  return mediaType === "application/x-www-form-urlencoded";
}

function validateVerifierBody(raw) {
  if (!raw || raw.length === 0) return { ok: false };
  if (raw.includes("?") || raw.includes("#")) return { ok: false };
  const pairs = raw.split("&");
  if (pairs.length !== 1) return { ok: false };
  const pair = pairs[0];
  const eq = pair.indexOf("=");
  if (eq <= 0) return { ok: false };
  if (pair.slice(0, eq) !== "oauth_verifier") return { ok: false };
  const value = pair.slice(eq + 1);
  if (value.length === 0) return { ok: false };
  try {
    const decoded = decodeURIComponent(value.replace(/\+/g, " "));
    if (!decoded || !decoded.trim()) return { ok: false };
  } catch {
    return { ok: false };
  }
  return { ok: true, body: raw };
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");

  if (req.method !== "POST") {
    res.statusCode = 405;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end("Method Not Allowed");
    return;
  }

  const authorization = req.headers["authorization"];
  if (!authorization || !String(authorization).startsWith("OAuth ")) {
    res.statusCode = 401;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end("Unauthorized");
    return;
  }

  const contentType = req.headers["content-type"] || null;
  if (!isFormUrlEncoded(contentType)) {
    res.statusCode = 415;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end("Unsupported Media Type");
    return;
  }

  // Vercel may already parse body; prefer raw
  let raw = "";
  if (typeof req.body === "string") {
    raw = req.body;
  } else if (req.body && typeof req.body === "object") {
    // Reject object bodies that might have been JSON-parsed — rebuild only if single field
    const keys = Object.keys(req.body);
    if (keys.length === 1 && keys[0] === "oauth_verifier") {
      raw = `oauth_verifier=${encodeURIComponent(String(req.body.oauth_verifier))}`;
    } else {
      res.statusCode = 400;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("Bad Request");
      return;
    }
  }

  if (Buffer.byteLength(raw, "utf8") > MAX_BODY_BYTES) {
    res.statusCode = 413;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end("Payload Too Large");
    return;
  }

  const validated = validateVerifierBody(raw);
  if (!validated.ok) {
    res.statusCode = 400;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end("Bad Request");
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
    res.statusCode = 502;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end("Bad Gateway");
    return;
  }

  const upstreamCt = upstream.headers.get("Content-Type");
  const buf = Buffer.from(await upstream.arrayBuffer());
  res.statusCode = upstream.status;
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
  if (upstreamCt) res.setHeader("Content-Type", upstreamCt);
  res.end(buf);
};
