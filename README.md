# BestClipNest Backend API

Implements `../BACKEND-SPEC.md` v1.0. Plain Node.js (18+), **zero dependencies** —
one file, `server.js`.

## Run it

```bash
SIGNING_KEY=$(openssl rand -hex 32) node server.js
# → BestClipNest API listening on port 8080 (v1.0.0)
```

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | Port to listen on |
| `SIGNING_KEY` | *(ephemeral, warns)* | HMAC key for signed download links. **Set this in production** or links die on restart |
| `ALLOWED_ORIGINS` | `https://bestclipnest.blogspot.com,http://localhost:8080` | CORS allowlist — only these origins may call the API |

## Endpoints

| Endpoint | What it does |
|---|---|
| `GET /api/health` | Liveness check: `{status:"ok", version, time}` |
| `POST /api/validate` | Checks a link's shape and platform without fetching it. Header `X-BestClipNest-Client: web` required |
| `POST /api/resolve` | Requires an ownership attestation (`attestation.ownsOrAuthorised: true`). Returns public metadata for platform links, or a **15-minute signed download link** for direct media files |
| `GET /api/dl/:token` | Verifies a signed token and 302-redirects to the original source file. Tampered/expired tokens get `403` |

## Built-in protections (spec §4–§6)

- Platform-domain allowlist, re-checked after every redirect (SSRF guard);
  look-alike hosts, IP hosts and credential-bearing URLs are rejected.
- Public content only — login walls and private posts return `403 not_public`.
- Rate limit: 10 resolve requests/minute and 60/hour per IP (`429` + `Retry-After`).
- Requests containing passwords/cookies/session fields are refused outright.
- No media is ever downloaded, stored, transcoded or re-hosted by this service.
- Metadata-only by default; a download reference exists only where the source
  itself exposes a public file (direct links / the user's own hosting).

## Tests

```bash
SIGNING_KEY=test PORT=18080 node server.js &   # in one terminal
node test.js                                    # 14 end-to-end checks
```

Last run (22 Nov 2026): **14 passed, 0 failed** — including attestation
enforcement, credential refusal, signed-link redirect, tamper rejection, and a
live Instagram resolve returning a spec-shaped metadata-only response.

## Honest limits

This backend does **not** turn BestClipNest into a universal downloader, and no
lawful backend can: Facebook, Instagram and TikTok do not offer a permitted
third-party download method for other people's videos. For platform links the
API returns whatever details the platform exposes publicly (often just the
honest notice), and the site keeps pointing users to each platform's own
save/download route for their own content. See spec §8 for the never-build list.
