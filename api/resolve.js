const core = require("../lib/core");

module.exports = async (req, res) => {
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
  if (core.rateLimited(core.clientIp(req))) {
    return core.sendJson(req, res, 429,
      { error: "rate_limited", message: "Too many requests. Please wait a moment and try again." },
      { "Retry-After": "60" });
  }
  if (!body.attestation || body.attestation.ownsOrAuthorised !== true) {
    return core.sendJson(req, res, 400, { error: "attestation_required", message: "Please confirm the video is yours or that you are authorised to save it." });
  }
  const info = core.inspectUrl(body.url);
  if (!info.ok) {
    const status = info.error === "domain_not_allowed" ? 403 : 400;
    return core.sendJson(req, res, status, { error: info.error, message: info.message });
  }

  if (info.isDirect) {
    const minted = core.mintToken(info.normalisedUrl);
    const proto = (req.headers && req.headers["x-forwarded-proto"]) || "https";
    const base = proto + "://" + req.headers.host;
    const filename = decodeURIComponent(new URL(info.normalisedUrl).pathname.split("/").pop() || "video.mp4");
    const ext = (filename.split(".").pop() || "mp4").toLowerCase();
    return core.sendJson(req, res, 200, {
      resolved: true, platform: "direct", contentType: "video",
      title: filename, thumbnailUrl: null, durationSeconds: null, isPublic: true,
      download: { url: base + "/api/dl/" + minted.token, expiresAt: minted.expiresAt, format: ext, sizeBytes: null, filename },
      notice: "Download link expires in 15 minutes.",
    });
  }

  const fetched = await core.fetchPublicMeta(info.normalisedUrl);
  if (fetched.error) {
    const status = fetched.error === "not_public" ? 403
      : fetched.error === "not_found" ? 404
      : fetched.error === "domain_not_allowed" ? 403 : 502;
    return core.sendJson(req, res, status, { error: fetched.error, message: fetched.message });
  }
  const meta = core.parseOg(fetched.html);
  return core.sendJson(req, res, 200, {
    resolved: true, platform: info.platform, contentType: info.contentType,
    title: meta.title, thumbnailUrl: meta.thumbnailUrl,
    durationSeconds: meta.durationSeconds, isPublic: true,
    download: null,
    notice: "This platform does not offer a permitted third-party download method. Use the platform's own save/download option for your content.",
  });
};
