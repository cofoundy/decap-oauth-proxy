const express = require("express");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID = process.env.OAUTH_CLIENT_ID;
const CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET;
const ALLOWED_ORIGINS = (process.env.ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
const SCOPE = process.env.OAUTH_SCOPE || "repo,user";

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error("Missing OAUTH_CLIENT_ID or OAUTH_CLIENT_SECRET");
  process.exit(1);
}

// CORS middleware
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
  res.json({ status: "ok", service: "decap-oauth-proxy" });
});

// Step 1: Redirect to GitHub OAuth
app.get("/auth", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    scope: SCOPE,
    state,
  });
  res.redirect(`https://github.com/login/oauth/authorize?${params}`);
});

// Step 2: GitHub callback — exchange code for token, return to Decap CMS
app.get("/callback", async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send("Missing code parameter");

  try {
    const response = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code,
      }),
    });

    const data = await response.json();

    if (data.error) {
      return res.status(401).send(`GitHub OAuth error: ${data.error_description || data.error}`);
    }

    // Decap CMS expects this exact postMessage format
    const postMessage = JSON.stringify({
      token: data.access_token,
      provider: "github",
    });

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
    console.error("OAuth callback error:", err);
    res.status(500).send("Authentication failed");
  }
});

app.listen(PORT, () => {
  console.log(`Decap OAuth proxy running on port ${PORT}`);
  console.log(`Allowed origins: ${ALLOWED_ORIGINS.join(", ") || "ALL (no ORIGINS set)"}`);
});
