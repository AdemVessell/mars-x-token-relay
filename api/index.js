module.exports = function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.statusCode = 200;
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.end("MARS_X_TOKEN_RELAY\nGET /health\nPOST /api/x-token-exchange\n");
};
