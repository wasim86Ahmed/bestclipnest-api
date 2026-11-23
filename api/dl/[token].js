const core = require("../../lib/core");

module.exports = (req, res) => {
  if (req.method === "OPTIONS") return core.handleOptions(req, res);
  const token = (req.query && req.query.token) || "";
  const target = core.verifyToken(decodeURIComponent(token));
  if (!target) {
    return core.sendJson(req, res, 403, { error: "invalid_or_expired_link", message: "This download link is invalid or has expired. Resolve the video again to get a fresh link." });
  }
  core.applyCors(req, res);
  res.setHeader("Cache-Control", "no-store");
  res.writeHead(302, { "Location": target });
  return res.end();
};
