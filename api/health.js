const core = require("../lib/core");

module.exports = (req, res) => {
  if (req.method === "OPTIONS") return core.handleOptions(req, res);
  if (req.method !== "GET") {
    return core.sendJson(req, res, 404, { error: "not_found", message: "Unknown endpoint." });
  }
  return core.sendJson(req, res, 200, {
    status: "ok", version: core.VERSION, time: new Date().toISOString(),
  });
};
