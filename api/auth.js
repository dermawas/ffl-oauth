const crypto = require("crypto");

function setStateCookie(res, state) {
  // 10 minutes
  const maxAge = 10 * 60;
  res.setHeader(
    "Set-Cookie",
    `oauth_state=${state}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax; Secure`
  );
}

function getRedirectURI(req) {
  const proto = (req.headers["x-forwarded-proto"] || "").split(",")[0] || "https";
  const host  = req.headers["x-forwarded-host"] || req.headers.host;
  return `${proto}://${host}/api/callback`;
}

module.exports = async (req, res) => {
  const { GITHUB_CLIENT_ID } = process.env;
  if (!GITHUB_CLIENT_ID) {
    res.status(500).send("Missing GITHUB_CLIENT_ID");
    return;
  }

  const state = crypto.randomBytes(16).toString("hex");
  setStateCookie(res, state);
  const redirect_uri = getRedirectURI(req);

  const u = new URL("https://github.com/login/oauth/authorize");
  u.searchParams.set("client_id", GITHUB_CLIENT_ID);
  u.searchParams.set("redirect_uri", redirect_uri);
  u.searchParams.set("scope", "repo,user");
  u.searchParams.set("state", state);

  res.writeHead(302, { Location: u.toString() });
  res.end();
};
