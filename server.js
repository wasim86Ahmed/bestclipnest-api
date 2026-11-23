/**
 * BestClipNest — Optional Backend API (implements BACKEND-SPEC.md v1.0)
 *
 * What this service does:
 *  - GET  /api/health          liveness check
 *  - POST /api/validate        URL shape + platform check (no fetching)
 *  - POST /api/resolve         public-metadata resolution for a user's OWN or
 *                              AUTHORISED public videos. Metadata-only by
 *                              default; a short-lived signed download
 *                              reference is returned ONLY for direct media
 *                              files (sources that expose a public file URL).
 *  - GET  /api/dl/:token       verifies an HMAC-signed, expiring token and
 *                              redirects to the original source file.
 *
 * What it never does (spec §8): no credential handling, no session cookies,
 * no login/DRM/privacy bypass, no rate-limit evasion, no media storage,
 * no watermark removal, no bulk harvesting.
 *
 * Run:  SIGNING_KEY=<long random string> node server.js
 * Optional env: PORT (default 8080), ALLOWED_ORIGINS (comma-separated,
 * default "https://bestclipnest.blogspot.com").
 */
"use strict";

const http = require("http");
const crypto = require("crypto");

const PORT = parseInt(process.env.PORT || "8080", 10);
const SIGNING_KEY = process.env.SIGNING_KEY || "";
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS ||
  "https://bestclipnest.blogspot.com,http://localhost:8080")
  .split(",").map((s) => s.trim()).filter(Boolean);
const VERSION = "1.0.0";
const DL_TTL_MS = 15 * 60 * 1000; // signed download references live 15 minutes
const FETCH_TIMEOUT_MS = 8000;
const MAX_META_BYTES = 512 * 1024;
const MAX_URL_LEN = 2048;

if (!SIGNING_KEY) {
  console.error("WARNING: SIGNING_KEY is not set — using an ephemeral key. " +
    "Signed download links will stop working on restart. Set SIGNING_KEY in production.");
}
const signingKey = SIGNING_KEY || crypto.randomBytes(32).toString("hex");

/* ------------------------------------------------------------------ */
/* Platform allowlist (spec §4.1)                                      */
/* ------------------------------------------------------------------ */
const PLATFORM_HOSTS = {
  facebook: ["facebook.com", "www.facebook.com", "m.facebook.com", "fb.watch"],
  instagram: ["instagram.com", "www.instagram.com"],
  tiktok: ["tiktok.com", "www.tiktok.com", "vm.tiktok.com", "vt.tiktok.com"],
  pinterest: ["pinterest.com", "www.pinterest.com", "pin.it"],
  x: ["x.com", "www.x.com", "twitter.com", "www.twitter.com", "mobile.twitter.com"],
  linkedin: ["linkedin.com", "www.linkedin.com"],
};
const ALL_HOSTS = new Set(Object.values(PLATFORM_HOSTS).flat());
const MEDIA_EXT = /\.(mp4|webm|mov|m4v|mkv)$/i;

function platformForHost(host) {
  for (const [name, hosts] of Object.entries(PLATFORM_HOSTS)) {
    if (hosts.includes(host)) return name;
  }
  return null;
}

function contentTypeFor(platform, path) {
  if (platform === "facebook") return /\/reel/.test(path) ? "reel" : "video";
  if (platform === "instagram") return /\/reel/.test(path) ? "reel" : "post";
  if (platform === "pinterest") return "pin";
  if (platform === "x") return "post";
  if (platform === "linkedin") return "post";
  return "video";
}

/**
 * Strict URL validation shared by /validate and /resolve.
 * Returns { ok, platform, contentType, normalisedUrl, isDirect, host, path }
 * or { ok:false, error, message }.
 */
function inspectUrl(raw) {
  if (typeof raw !== "string" || !raw || raw.length > MAX_URL_LEN) {
    return { ok: false, error: "invalid_url", message: "That link is missing, too long, or not text." };
  }
  let u;
  try { u = new URL(raw.trim()); } catch (e) {
    return { ok: false, error: "invalid_url", message: "This does not look like a supported public video link. Check the link and try again." };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { ok: false, error: "invalid_url", message: "Only web links starting with http:// or https:// can be checked." };
  }
  if (u.username || u.password) {
    return { ok: false, error: "invalid_url", message: "Links with embedded credentials are not accepted." };
  }
  const host = u.hostname.toLowerCase();
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host === "localhost") {
    return { ok: false, error: "domain_not_allowed", message: "This host is not on the supported platform list." };
  }
  const path = u.pathname.toLowerCase();
  // Direct media file (user's own hosting / CDN etc.)
  if (MEDIA_EXT.test(path)) {
    return { ok: true, platform: "direct", contentType: "video", isDirect: true,
             normalisedUrl: u.href, host, path };
  }
  const platform = platformForHost(host);
  if (!platform) {
    return { ok: false, error: "domain_not_allowed", message: "This does not look like a supported public video link. Check the link and try again." };
  }
  return { ok: true, platform, contentType: contentTypeFor(platform, path),
           isDirect: false, normalisedUrl: u.href, host, path };
}

/* ------------------------------------------------------------------ */
/* Rate limiting (spec §4.5): 10/min and 60/hour per IP on /resolve    */
/* ------------------------------------------------------------------ */
const rateBuckets = new Map(); // ip -> [timestamps]
function rateLimited(ip) {
  const now = Date.now();
  const arr = (rateBuckets.get(ip) || []).filter((t) => now - t < 3600_000);
  const lastMinute = arr.filter((t) => now - t < 60_000).length;
  if (lastMinute >= 10 || arr.length >= 60) {
    rateBuckets.set(ip, arr);
    return true;
  }
  arr.push(now);
  rateBuckets.set(ip, arr);
  return false;
}

/* ------------------------------------------------------------------ */
/* Signed download tokens (spec §4.7): HMAC, 15-minute expiry          */
/* ------------------------------------------------------------------ */
function mintToken(url) {
  const exp = Date.now() + DL_TTL_MS;
  const payload = Buffer.from(JSON.stringify({ u: url, e: exp })).toString("base64url");
  const sig = crypto.createHmac("sha256", signingKey).update(payload).digest("base64url");
  return { token: payload + "." + sig, expiresAt: new Date(exp).toISOString() };
}
function verifyToken(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  const expect = crypto.createHmac("sha256", signingKey).update(payload).digest("base64url");
  const a = Buffer.from(sig), b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let data;
  try { data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")); } catch (e) { return null; }
  if (!data.u || !data.e || Date.now() > data.e) return null;
  return data.u;
}

/* ------------------------------------------------------------------ */
/* Public metadata fetch (spec §4.3/§4.4): no credentials, login wall  */
/* detection, allowlist re-check after redirects, size/time caps.     */
/* ------------------------------------------------------------------ */
function isLoginWall(finalUrl, html) {
  const u = finalUrl.toLowerCase();
  if (u.includes("/accounts/login") || u.includes("/login") || u.includes("login.php")) return true;
  if (/<title[^>]*>\s*(log in|login|sign up)\b/i.test(html) && /password/i.test(html)) return true;
  return false;
}

async function fetchPublicMeta(startUrl) {
  let current = startUrl;
  for (let hop = 0; hop <= 3; hop++) {
    const host = new URL(current).hostname.toLowerCase();
    if (!ALL_HOSTS.has(host) && !MEDIA_EXT.test(new URL(current).pathname.toLowerCase())) {
      return { error: "domain_not_allowed", message: "The link redirected to a host that is not supported." };
    }
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    let res;
    try {
      res = await fetch(current, {
        redirect: "manual",
        signal: ctrl.signal,
        headers: {
          "User-Agent": "BestClipNestMeta/1.0 (+https://bestclipnest.blogspot.com/p/about-us.html)",
          "Accept": "text/html,application/xhtml+xml",
        },
      });
    } catch (e) {
      return { error: "upstream_unavailable", message: "The platform could not be reached. Please try again later." };
    } finally { clearTimeout(timer); }

    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      if (!loc) break;
      current = new URL(loc, current).href;
      continue;
    }
    if (res.status === 404) return { error: "not_found", message: "This public page does not exist or was removed." };
    if (res.status === 401 || res.status === 403) {
      return { error: "not_public", message: "This post is not public. BestClipNest can only resolve public posts, and only for content you own or are authorised to save." };
    }
    if (!res.ok) return { error: "upstream_unavailable", message: "The platform returned an unexpected response." };

    const reader = res.body.getReader();
    let html = "", bytes = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.length;
      if (bytes > MAX_META_BYTES) { try { await reader.cancel(); } catch (e) {} break; }
      html += Buffer.from(value).toString("utf8");
    }
    if (isLoginWall(current, html)) {
      return { error: "not_public", message: "This post is not public. BestClipNest can only resolve public posts, and only for content you own or are authorised to save." };
    }
    return { html, finalUrl: current };
  }
  return { error: "upstream_unavailable", message: "Too many redirects while reading the page." };
}

function parseOg(html) {
  const get = (prop) => {
    const re = new RegExp('<meta[^>]+(?:property|name)=["\']og:' + prop + '["\'][^>]+content=["\']([^"\']*)["\']', "i");
    const re2 = new RegExp('<meta[^>]+content=["\']([^"\']*)["\'][^>]+(?:property|name)=["\']og:' + prop + '["\']', "i");
    const m = html.match(re) || html.match(re2);
    return m ? m[1].replace(/&amp;/g, "&") : null;
  };
  const dur = get("video:duration");
  return {
    title: get("title"),
    thumbnailUrl: get("image"),
    durationSeconds: dur && /^\d+$/.test(dur) ? parseInt(dur, 10) : null,
  };
}

/* ------------------------------------------------------------------ */
/* HTTP plumbing                                                       */
/* ------------------------------------------------------------------ */
function clientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  return (xff ? String(xff).split(",")[0].trim() : "") || req.socket.remoteAddress || "unknown";
}
function corsHeaders(req) {
  const origin = req.headers.origin || "";
  const h = { "Vary": "Origin" };
  if (ALLOWED_ORIGINS.includes(origin)) h["Access-Control-Allow-Origin"] = origin;
  return h;
}
function sendJson(req, res, status, obj, extraHeaders) {
  const body = JSON.stringify(obj);
  res.writeHead(status, Object.assign(
    { "Content-Type": "application/json; charset=utf-8" }, corsHeaders(req), extraHeaders || {}));
  res.end(body);
}
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => { data += c; if (data.length > 64 * 1024) reject(new Error("too_large")); });
    req.on("end", () => { try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); } });
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  const path = url.pathname;

  if (req.method === "OPTIONS") {
    res.writeHead(204, Object.assign({}, corsHeaders(req), {
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-BestClipNest-Client",
      "Access-Control-Max-Age": "600",
    }));
    return res.end();
  }

  try {
    if (req.method === "GET" && path === "/api/health") {
      return sendJson(req, res, 200, { status: "ok", version: VERSION, time: new Date().toISOString() });
    }

    if (req.method === "GET" && path.startsWith("/api/dl/")) {
      const target = verifyToken(decodeURIComponent(path.slice("/api/dl/".length)));
      if (!target) return sendJson(req, res, 403, { error: "invalid_or_expired_link", message: "This download link is invalid or has expired. Resolve the video again to get a fresh link." });
      res.writeHead(302, { "Location": target, "Cache-Control": "no-store" });
      return res.end();
    }

    if (req.method === "POST" && (path === "/api/validate" || path === "/api/resolve")) {
      if (req.headers["x-bestclipnest-client"] !== "web") {
        return sendJson(req, res, 400, { error: "invalid_url", message: "Missing required client header." });
      }
      let body;
      try { body = await readJsonBody(req); }
      catch (e) { return sendJson(req, res, 400, { error: "invalid_url", message: "Request body must be valid JSON." }); }

      // Spec §6: never accept credentials/cookies for third-party platforms.
      const rawBody = JSON.stringify(body).toLowerCase();
      if (rawBody.includes("password") || rawBody.includes("cookie") || rawBody.includes("session")) {
        return sendJson(req, res, 400, { error: "invalid_url", message: "Credentials and session data are never accepted by BestClipNest." });
      }

      const info = inspectUrl(body.url);

      if (path === "/api/validate") {
        if (!info.ok) {
          return sendJson(req, res, 200, { valid: false, platform: null, contentType: null,
            normalisedUrl: null, requiresBackendResolution: false, message: info.message });
        }
        return sendJson(req, res, 200, { valid: true, platform: info.platform,
          contentType: info.contentType, normalisedUrl: info.normalisedUrl,
          requiresBackendResolution: !info.isDirect,
          message: info.isDirect
            ? "Direct video file link. The browser tool can preview and download it now."
            : "Link format is valid. Resolution is available only for public posts you own or are authorised to save." });
      }

      /* ---- /api/resolve ---- */
      if (rateLimited(clientIp(req))) {
        return sendJson(req, res, 429, { error: "rate_limited", message: "Too many requests. Please wait a moment and try again." }, { "Retry-After": "60" });
      }
      if (!body.attestation || body.attestation.ownsOrAuthorised !== true) {
        return sendJson(req, res, 400, { error: "attestation_required", message: "Please confirm the video is yours or that you are authorised to save it." });
      }
      if (!info.ok) {
        const status = info.error === "domain_not_allowed" ? 403 : 400;
        return sendJson(req, res, status, { error: info.error, message: info.message });
      }

      if (info.isDirect) {
        // The source itself exposes a public file URL — a permitted reference.
        const minted = mintToken(info.normalisedUrl);
        const base = (req.headers["x-forwarded-proto"] || "http") + "://" + req.headers.host;
        const filename = decodeURIComponent(new URL(info.normalisedUrl).pathname.split("/").pop() || "video.mp4");
        const ext = (filename.split(".").pop() || "mp4").toLowerCase();
        return sendJson(req, res, 200, {
          resolved: true, platform: "direct", contentType: "video",
          title: filename, thumbnailUrl: null, durationSeconds: null, isPublic: true,
          download: { url: base + "/api/dl/" + minted.token, expiresAt: minted.expiresAt, format: ext, sizeBytes: null, filename },
          notice: "Download link expires in 15 minutes.",
        });
      }

      const fetched = await fetchPublicMeta(info.normalisedUrl);
      if (fetched.error) {
        const status = fetched.error === "not_public" ? 403
          : fetched.error === "not_found" ? 404
          : fetched.error === "domain_not_allowed" ? 403 : 502;
        return sendJson(req, res, status, { error: fetched.error, message: fetched.message });
      }
      const meta = parseOg(fetched.html);
      return sendJson(req, res, 200, {
        resolved: true, platform: info.platform, contentType: info.contentType,
        title: meta.title, thumbnailUrl: meta.thumbnailUrl,
        durationSeconds: meta.durationSeconds, isPublic: true,
        download: null,
        notice: "This platform does not offer a permitted third-party download method. Use the platform's own save/download option for your content.",
      });
    }

    return sendJson(req, res, 404, { error: "not_found", message: "Unknown endpoint." });
  } catch (e) {
    return sendJson(req, res, 500, { error: "upstream_unavailable", message: "Something went wrong on our side. Please try again." });
  }
});

server.listen(PORT, () => {
  console.log("BestClipNest API listening on port " + PORT + " (v" + VERSION + ")");
});
