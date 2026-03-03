const express = require("express");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

// Google OAuth credentials
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

// GitHub PAT — used for all CMS operations (shared token)
const GITHUB_PAT = process.env.GITHUB_PAT;

// Allowed emails (comma-separated). If empty, any Google email can login.
const ALLOWED_EMAILS = (process.env.ALLOWED_EMAILS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

// CORS origins
const ALLOWED_ORIGINS = (process.env.ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// Keep GitHub OAuth as fallback (for devs)
const GH_CLIENT_ID = process.env.OAUTH_CLIENT_ID;
const GH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET;

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GITHUB_PAT) {
  console.error("Missing required env vars: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GITHUB_PAT");
  process.exit(1);
}

// State store (in-memory, fine for single instance)
const states = new Map();

// CORS
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.some((o) => origin.includes(o))) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// Health check
app.get("/", (req, res) => {
  res.json({ status: "ok", service: "decap-oauth-proxy", auth: "google" });
});

// ── Google OAuth Flow ──

// Step 1: Redirect to Google OAuth
app.get("/auth", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  states.set(state, Date.now());

  // Clean old states (older than 10 min)
  for (const [key, ts] of states) {
    if (Date.now() - ts > 600000) states.delete(key);
  }

  const redirectUri = `${getBaseUrl(req)}/callback/google`;
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "email profile",
    state,
    prompt: "select_account",
  });

  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

// Step 2: Google callback
app.get("/callback/google", async (req, res) => {
  const { code, state } = req.query;

  if (!code) return res.status(400).send("Missing code parameter");
  if (!state || !states.has(state)) return res.status(400).send("Invalid state");
  states.delete(state);

  try {
    const redirectUri = `${getBaseUrl(req)}/callback/google`;

    // Exchange code for tokens
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: redirectUri,
        grant_type: "authorization_code",
      }),
    });

    const tokenData = await tokenRes.json();
    if (tokenData.error) {
      console.error("Google token error:", tokenData);
      return res.status(401).send(`Google auth error: ${tokenData.error_description || tokenData.error}`);
    }

    // Get user info
    const userRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const user = await userRes.json();
    const email = (user.email || "").toLowerCase();

    console.log(`Login attempt: ${email} (${user.name || "unknown"})`);

    // Check allowlist
    if (ALLOWED_EMAILS.length > 0 && !ALLOWED_EMAILS.includes(email)) {
      console.warn(`Blocked: ${email} not in allowlist`);
      return res.status(403).send(`
        <html><body style="font-family:sans-serif;text-align:center;padding:60px;">
          <h2>Access Denied</h2>
          <p>${email} is not authorized to access this CMS.</p>
          <p>Contact your administrator to get access.</p>
        </body></html>
      `);
    }

    // Return GitHub PAT to Decap CMS via postMessage
    const postMessage = JSON.stringify({ token: GITHUB_PAT, provider: "github" });

    res.send(`
      <html><body><script>
        (function() {
          function receiveMessage(e) {
            console.log("receiveMessage %o", e);
            window.opener.postMessage(
              'authorization:github:success:${postMessage}',
              e.origin
            );
            window.removeEventListener("message", receiveMessage, false);
          }
          window.addEventListener("message", receiveMessage, false);
          window.opener.postMessage("authorizing:github", "*");
        })();
      </script></body></html>
    `);
  } catch (err) {
    console.error("Google OAuth callback error:", err);
    res.status(500).send("Authentication failed");
  }
});

// ── GitHub OAuth Flow (fallback for devs) ──

app.get("/auth/github", (req, res) => {
  if (!GH_CLIENT_ID) return res.status(501).send("GitHub OAuth not configured");
  const state = crypto.randomBytes(16).toString("hex");
  const params = new URLSearchParams({
    client_id: GH_CLIENT_ID,
    scope: "repo,user",
    state,
  });
  res.redirect(`https://github.com/login/oauth/authorize?${params}`);
});

app.get("/callback", async (req, res) => {
  if (!GH_CLIENT_ID || !GH_CLIENT_SECRET) {
    return res.status(501).send("GitHub OAuth not configured");
  }

  const { code } = req.query;
  if (!code) return res.status(400).send("Missing code parameter");

  try {
    const response = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        client_id: GH_CLIENT_ID,
        client_secret: GH_CLIENT_SECRET,
        code,
      }),
    });

    const data = await response.json();
    if (data.error) {
      return res.status(401).send(`GitHub OAuth error: ${data.error_description || data.error}`);
    }

    const postMessage = JSON.stringify({ token: data.access_token, provider: "github" });

    res.send(`
      <html><body><script>
        (function() {
          function receiveMessage(e) {
            window.opener.postMessage(
              'authorization:github:success:${postMessage}',
              e.origin
            );
            window.removeEventListener("message", receiveMessage, false);
          }
          window.addEventListener("message", receiveMessage, false);
          window.opener.postMessage("authorizing:github", "*");
        })();
      </script></body></html>
    `);
  } catch (err) {
    console.error("GitHub OAuth callback error:", err);
    res.status(500).send("Authentication failed");
  }
});

function getBaseUrl(req) {
  const proto = req.headers["x-forwarded-proto"] || req.protocol;
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return `${proto}://${host}`;
}

app.listen(PORT, () => {
  console.log(`Decap OAuth proxy running on port ${PORT}`);
  console.log(`Auth mode: Google OAuth → GitHub PAT`);
  console.log(`Allowed emails: ${ALLOWED_EMAILS.length ? ALLOWED_EMAILS.join(", ") : "ALL"}`);
  console.log(`Allowed origins: ${ALLOWED_ORIGINS.join(", ") || "ALL"}`);
});
