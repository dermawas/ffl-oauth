// /api/auth.js
// Redirects the browser to GitHub's OAuth authorize screen with the correct scopes.
// Also sets a short-lived state cookie that we verify in /api/callback.

module.exports = (req, res) => {
  const { GITHUB_CLIENT_ID } = process.env;

  if (!GITHUB_CLIENT_ID) {
    res.statusCode = 500;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.end("Missing env: GITHUB_CLIENT_ID");
  }

  // Create a simple random state and set it as an HttpOnly cookie
  const state = Math.random().toString(36).slice(2);
  // Cookie is scoped to /api/callback so we only send it back there
  res.setHeader(
    "Set-Cookie",
    `oauth_state=${state}; Path=/api/callback; HttpOnly; SameSite=Lax; Secure`
  );

  // Compute our redirect_uri (the URL GitHub will send users back to)
  const proto = (req.headers["x-forwarded-proto"] || "").split(",")[0] || "https";
  const host  = req.headers["x-forwarded-host"] || req.headers.host;
  const redirect_uri = `${proto}://${host}/api/callback`;

  // IMPORTANT: Decap needs write access to your repo → use scope=repo,user:email
  const params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    redirect_uri,
    scope: "repo,user:email",
    state
  });

  const location = `https://github.com/login/oauth/authorize?${params.toString()}`;
  res.writeHead(302, { Location: location });
  res.end();
};
