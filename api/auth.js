// /api/auth.js
const crypto = require("crypto");

function getRedirectURI(req) {
  const proto =
    (req.headers["x-forwarded-proto"] || "").split(",")[0] || "https";
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return `${proto}://${host}/api/callback`;
}

module.exports = (req, res) => {
  const { GITHUB_CLIENT_ID } = process.env;
  if (!GITHUB_CLIENT_ID) {
    res.status(500).send("Missing GITHUB_CLIENT_ID");
    return;
  }

  // Optional scope: "repo" (private) or "public_repo"
  const scope = req.query.scope || "repo";

  // CSRF protection
  const state = crypto.randomBytes(16).toString("hex");
  const cookie = [
    `oauth_state=${state}`,
    "Path=/api/callback",
    "HttpOnly",
    "SameSite=Lax",
    "Secure"
  ].join("; ");
  res.setHeader("Set-Cookie", cookie);

  const redirect_uri = getRedirectURI(req);
  const url = new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", GITHUB_CLIENT_ID);
  url.searchParams.set("redirect_uri", redirect_uri);
  url.searchParams.set("scope", scope);
  url.searchParams.set("state", state);

  res.writeHead(302, { Location: url.toString() });
  res.end();
};
