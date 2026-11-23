const core = require("../lib/core");

module.exports = (req, res) => {
  if (req.method === "OPTIONS") return core.handleOptions(req, res);
  if (req.method !== "POST") {
    return core.sendJson(req, res, 404, { error: "not_found", message: "Unknown endpoint." });
  }
  if (!core.hasClientHeader(req)) {
    return core.sendJson(req, res, 400, { error: "invalid_url", message: "Missing required client header." });
  }
  const body = core.parseBody(req);
  if (body === null) {
    return core.sendJson(req, res, 400, { error: "invalid_url", message: "Request body must be valid JSON." });
  }
  if (core.bodyHasCredentials(body)) {
    return core.sendJson(req, res, 400, { error: "invalid_url", message: "Credentials and session data are never accepted by BestClipNest." });
  }
  const info = core.inspectUrl(body.url);
  if (!info.ok) {
    return core.sendJson(req, res, 200, { valid: false, platform: null, contentType: null,
      normalisedUrl: null, requiresBackendResolution: false, message: info.message });
  }
  return core.sendJson(req, res, 200, { valid: true, platform: info.platform,
    contentType: info.contentType, normalisedUrl: info.normalisedUrl,
    requiresBackendResolution: !info.isDirect,
    message: info.isDirect
      ? "Direct video file link. The browser tool can preview and download it now."
      : "Link format is valid. Resolution is available only for public posts you own or are authorised to save." });
};
