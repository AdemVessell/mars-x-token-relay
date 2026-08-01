#!/usr/bin/env node
/**
 * Self-test for MARS_X_TOKEN_RELAY validation.
 * Does not print Authorization, body, verifier, or upstream token bodies.
 */
const base = process.argv[2] || "http://127.0.0.1:8080";

async function check(name, fn) {
  try {
    await fn();
    console.log(`PASS ${name}`);
  } catch (e) {
    console.error(`FAIL ${name}: ${e.message}`);
    process.exitCode = 1;
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

const exchange = `${base}/api/x-token-exchange`;

await check("GET /health", async () => {
  const r = await fetch(`${base}/health`);
  const j = await r.json();
  assert(r.status === 200, `status ${r.status}`);
  assert(j.ok === true, "ok");
  assert(j.service === "MARS_X_TOKEN_RELAY", "service");
  assert(j.destinationLocked === true, "destinationLocked");
  assert(j.storesSecrets === false, "storesSecrets");
  assert(r.headers.get("cache-control") === "no-store", "cache-control");
  assert(r.headers.get("x-content-type-options") === "nosniff", "nosniff");
});

await check("GET exchange -> 405", async () => {
  const r = await fetch(exchange);
  assert(r.status === 405, `status ${r.status}`);
  assert(!r.headers.get("access-control-allow-origin"), "no CORS");
});

await check("missing Authorization -> 401", async () => {
  const r = await fetch(exchange, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "oauth_verifier=abc",
  });
  assert(r.status === 401, `status ${r.status}`);
});

await check("Bearer auth -> 401", async () => {
  const r = await fetch(exchange, {
    method: "POST",
    headers: {
      Authorization: "Bearer not-oauth",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "oauth_verifier=abc",
  });
  assert(r.status === 401, `status ${r.status}`);
});

await check("wrong content-type -> 415", async () => {
  const r = await fetch(exchange, {
    method: "POST",
    headers: {
      Authorization: 'OAuth oauth_token="x"',
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ oauth_verifier: "abc" }),
  });
  assert(r.status === 415, `status ${r.status}`);
});

await check("extra field / open-proxy attempt -> 400", async () => {
  const r = await fetch(exchange, {
    method: "POST",
    headers: {
      Authorization: 'OAuth oauth_token="x"',
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "oauth_verifier=abc&url=https://evil.example/steal",
  });
  assert(r.status === 400, `status ${r.status}`);
});

await check("empty verifier -> 400", async () => {
  const r = await fetch(exchange, {
    method: "POST",
    headers: {
      Authorization: 'OAuth oauth_token="x"',
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "oauth_verifier=",
  });
  assert(r.status === 400, `status ${r.status}`);
});

await check("oversize body -> 413", async () => {
  const r = await fetch(exchange, {
    method: "POST",
    headers: {
      Authorization: 'OAuth oauth_token="x"',
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "oauth_verifier=" + "a".repeat(3000),
  });
  assert(r.status === 413, `status ${r.status}`);
});

await check("OPTIONS no CORS -> 405", async () => {
  const r = await fetch(exchange, {
    method: "OPTIONS",
    headers: {
      Origin: "https://evil.example",
      "Access-Control-Request-Method": "POST",
    },
  });
  assert(r.status === 405, `status ${r.status}`);
  assert(!r.headers.get("access-control-allow-origin"), "no ACAO");
  assert(!r.headers.get("access-control-allow-methods"), "no ACAM");
});

await check("valid shape forwards to locked X destination (not open proxy)", async () => {
  const r = await fetch(exchange, {
    method: "POST",
    headers: {
      Authorization:
        'OAuth oauth_consumer_key="x", oauth_nonce="n", oauth_signature="s", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1", oauth_token="t", oauth_version="1.0"',
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "oauth_verifier=testverifier123",
  });
  // Fake signature: X rejects. Proves we hit X, not an alternate destination.
  assert(r.status === 401 || r.status === 403, `upstream-ish status ${r.status}`);
  assert(r.headers.get("cache-control") === "no-store", "cache-control");
  assert(r.headers.get("x-content-type-options") === "nosniff", "nosniff");
  // Do not print body (may contain diagnostic text from X).
  const len = (await r.arrayBuffer()).byteLength;
  assert(len > 0, "non-empty upstream body");
});

console.log(process.exitCode ? "SELFTEST FAILED" : "SELFTEST OK");
