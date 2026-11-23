/**
 * BestClipNest API — shared core logic (used by the Vercel functions in /api
 * and mirroring server.js, which remains for VPS/local use).
 * Implements BACKEND-SPEC.md v1.0. See ../README.md for the honest limits.
 */
"use strict";

const crypto = require("crypto");

const VERSION = "1.0.0";
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS ||
  "https://bestclipnest.blogspot.com")
  .split(",").map((s) => s.trim()).filter(Boolean);
const signingKey = process.env.SIGNING_KEY || crypto.randomBytes(32).toString("hex");
const DL_TTL_MS = 15 * 60 * 1000;
const FETCH_TIMEOUT_MS = 8000;
const MAX_META_BYTES = 512 * 1024;
const MAX_URL_LEN = 2048;

const PLATFORM_HOSTS = {
  facebook: ["facebook.com", "www.facebook.com", "m.facebook.com", "fb.watch"],
  instagram: ["instagram.com", "www.instagram.com"],
  tiktok: ["tiktok.com", "www.tiktok.com", "vm.tiktok.com", "vt.tiktok.com"],
  pinterest: ["pinterest.com", "www.pinterest.com", "pin.it"],
  x: ["x.com", "www.x.com", "twitter.com", "www.twitter.com", "mobile.twitter.com"],
  linkedin: ["linkedin.com", "www.linkedin.com"],
  youtube: ["youtube.com", "www.youtube.com", "m.youtube.com", "music.youtube.com", "youtu.be"],
  reddit: ["reddit.com", "www.reddit.com", "old.reddit.com", "redd.it"],
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
  if (platform === "youtube") return /\/shorts\//.test(path) ? "short" : "video";
  if (platform === "reddit") return "post";
  return "video";
}
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

/* Rate limiting: best-effort per warm instance (10/min, 60/hour per IP). */
const rateBuckets = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const arr = (rateBuckets.get(ip) || []).filter((t) => now - t < 3600_000);
  const lastMinute = arr.filter((t) => now - t < 60_000).length;
  if (lastMinute >= 10 || arr.length >= 60) { rateBuckets.set(ip, arr); return true; }
  arr.push(now); rateBuckets.set(ip, arr); return false;
}

/* Signed download tokens: HMAC, 15-minute expiry. */
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

/* Public metadata fetch: no credentials, login-wall detection, allowlist
   re-check after redirects, size/time caps. */
function isLoginWall(finalUrl, html) {
  const u = finalUrl.toLowerCase();
  if (u.includes("/accounts/login") || u.includes("/login") || u.includes("login.php")) return true;
  if (u.includes("consent.youtube.com") || u.includes("consent.google.com")) return true;
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

/* HTTP helpers (raw Node style, shared by handlers and the local harness). */
function applyCors(req, res) {
  const origin = (req.headers && req.headers.origin) || "";
  res.setHeader("Vary", "Origin");
  if (ALLOWED_ORIGINS.includes(origin)) res.setHeader("Access-Control-Allow-Origin", origin);
}
function handleOptions(req, res) {
  applyCors(req, res);
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-BestClipNest-Client");
  res.setHeader("Access-Control-Max-Age", "600");
  res.writeHead(204);
  res.end();
  return true;
}
function sendJson(req, res, status, obj, extraHeaders) {
  applyCors(req, res);
  if (extraHeaders) for (const [k, v] of Object.entries(extraHeaders)) res.setHeader(k, v);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.writeHead(status);
  res.end(JSON.stringify(obj));
}
function clientIp(req) {
  const xff = req.headers && req.headers["x-forwarded-for"];
  return (xff ? String(xff).split(",")[0].trim() : "") ||
    (req.socket && req.socket.remoteAddress) || "unknown";
}
function parseBody(req) {
  if (!req.body) return {};
  if (typeof req.body === "string") {
    try { return JSON.parse(req.body); } catch (e) { return null; }
  }
  return req.body;
}
function hasClientHeader(req) {
  return req.headers && req.headers["x-bestclipnest-client"] === "web";
}
function bodyHasCredentials(body) {
  const s = JSON.stringify(body || {}).toLowerCase();
  return s.includes("password") || s.includes("cookie") || s.includes("session");
}

module.exports = {
  VERSION, inspectUrl, rateLimited, mintToken, verifyToken,
  fetchPublicMeta, parseOg, applyCors, handleOptions, sendJson,
  clientIp, parseBody, hasClientHeader, bodyHasCredentials,
};
