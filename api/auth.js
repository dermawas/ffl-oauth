// /api/auth.js
const crypto = require("crypto");

function setStateCookie(res, state, req) {
  const proto = (req.headers["x-forwarded-proto"] || "").split(",")[0] || "https";
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  const basePath = "/"; // cookie available site-wide

  // 10 minutes expiry
  const maxAge = 10 * 60;
  const cookie =
    `oauth_state=${state}; Path=${basePath}; Max-Age=${maxAge}; HttpOnly; ` +
    `SameSite=Lax; Secure`;
  res.setHeader("Set-Cookie", cookie);

  // return redirect_uri (same host)
  return `${proto}://${host}/api/callback`;
}

module.exports = async (req, res) => {
  const {
    GITHUB_CLIENT_ID,
  } = process.env;

  if (!GITHUB_CLIENT_ID) {
    res.status(500).send("Missing GITHUB_CLIENT_ID");
    return;
  }

  const state = crypto.randomBytes(16).toString("hex");
  const redirect_uri = setStateCookie(res, state, req);

  const authorizeURL = new URL("https://github.com/login/oauth/authorize");
  authorizeURL.searchParams.set("client_id", GITHUB_CLIENT_ID);
  authorizeURL.searchParams.set("redirect_uri", redirect_uri);
  authorizeURL.searchParams.set("scope", "repo,user"); // minimal is "repo"
  authorizeURL.searchParams.set("state", state);
  // optional UX nicety:
  // authorizeURL.searchParams.set("allow_signup", "false");

  res.writeHead(302, { Location: authorizeURL.toString() });
  res.end();
};
