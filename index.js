const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Google OAuth credentials
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

// GitHub App credentials (replaces GITHUB_PAT)
const GITHUB_APP_ID = process.env.GITHUB_APP_ID;
const GITHUB_APP_PRIVATE_KEY_B64 = process.env.GITHUB_APP_PRIVATE_KEY; // base64-encoded PEM
const GITHUB_APP_INSTALLATION_ID = process.env.GITHUB_APP_INSTALLATION_ID;

// Fallback: legacy GITHUB_PAT (for migration period)
const GITHUB_PAT = process.env.GITHUB_PAT;

// Allowed emails — from env var + allowed-emails.json file
const envEmails = (process.env.ALLOWED_EMAILS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

let fileEmails = [];
try {
  const emailsFile = path.join(__dirname, "allowed-emails.json");
  if (fs.existsSync(emailsFile)) {
    fileEmails = JSON.parse(fs.readFileSync(emailsFile, "utf8")).map((s) =>
      s.trim().toLowerCase()
    );
  }
} catch (err) {
  console.warn("Could not read allowed-emails.json:", err.message);
}

const ALLOWED_EMAILS = [...new Set([...envEmails, ...fileEmails])];

// CORS origins
const ALLOWED_ORIGINS = (process.env.ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// Keep GitHub OAuth as fallback (for devs)
const GH_CLIENT_ID = process.env.OAUTH_CLIENT_ID;
const GH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET;

// Validate required env vars
const useGitHubApp = GITHUB_APP_ID && GITHUB_APP_PRIVATE_KEY_B64 && GITHUB_APP_INSTALLATION_ID;
const useLegacyPAT = !!GITHUB_PAT;

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  console.error("Missing required env vars: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET");
  process.exit(1);
}

if (!useGitHubApp && !useLegacyPAT) {
  console.error("Missing GitHub auth: set GITHUB_APP_ID+GITHUB_APP_PRIVATE_KEY+GITHUB_APP_INSTALLATION_ID or GITHUB_PAT");
  process.exit(1);
}

// ── GitHub App Token Management ──

let cachedToken = null;
let tokenExpiry = 0;

function getPrivateKey() {
  return Buffer.from(GITHUB_APP_PRIVATE_KEY_B64, "base64").toString("utf8");
}

function createAppJWT() {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iat: now - 60, // 60s clock drift allowance
    exp: now + 600, // 10 min max
    iss: GITHUB_APP_ID,
  };
  return jwt.sign(payload, getPrivateKey(), { algorithm: "RS256" });
}

async function getInstallationToken() {
  // Return cached token if still valid
  if (cachedToken && Date.now() < tokenExpiry) return cachedToken;

  const appJWT = createAppJWT();
  const res = await fetch(
    `https://api.github.com/app/installations/${GITHUB_APP_INSTALLATION_ID}/access_tokens`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${appJWT}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
    }
  );

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Failed to get installation token: ${res.status} ${err}`);
  }

  const data = await res.json();
  cachedToken = data.token;
  // Refresh 5 min before expiry (tokens last 1 hour)
  tokenExpiry = Date.now() + 55 * 60 * 1000;

  console.log("GitHub App installation token refreshed");
  return cachedToken;
}

async function getGitHubToken() {
  if (useGitHubApp) return getInstallationToken();
  return GITHUB_PAT;
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
  res.json({
    status: "ok",
    service: "decap-oauth-proxy",
    auth: "google",
    github: useGitHubApp ? "app" : "pat",
    emails: ALLOWED_EMAILS.length || "all",
  });
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

    // Get GitHub token (from App or PAT)
    const ghToken = await getGitHubToken();
    const postMessage = JSON.stringify({ token: ghToken, provider: "github" });

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
  console.log(`Auth mode: Google OAuth → GitHub ${useGitHubApp ? "App" : "PAT"}`);
  console.log(`Allowed emails: ${ALLOWED_EMAILS.length ? ALLOWED_EMAILS.join(", ") : "ALL"}`);
  console.log(`Allowed origins: ${ALLOWED_ORIGINS.join(", ") || "ALL"}`);
});
