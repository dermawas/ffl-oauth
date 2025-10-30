// /api/auth.js
// Redirect to GitHub's authorize page and set a short-lived state cookie

module.exports = (req, res) => {
  const { GITHUB_CLIENT_ID } = process.env;

  if (!GITHUB_CLIENT_ID) {
    res.statusCode = 500;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    return res.end('Missing env: GITHUB_CLIENT_ID');
  }

  // Random state to mitigate CSRF
  const state = Math.random().toString(36).slice(2);

  // Cookie scoped only to /api/callback so we only send it back there
  res.setHeader('Set-Cookie', [
    `oauth_state=${state}; Path=/api/callback; HttpOnly; SameSite=Lax; Secure`,
  ]);

  // Build redirect_uri dynamically for current deployment
  const proto = (req.headers['x-forwarded-proto'] || '').split(',')[0] || 'https';
  const host  = req.headers['x-forwarded-host']  || req.headers.host;
  const redirect_uri = `${proto}://${host}/api/callback`;

  const scope = 'repo'; // includes public_repo + needed endpoints for Decap GitHub backend
  const url =
    `https://github.com/login/oauth/authorize` +
    `?client_id=${encodeURIComponent(GITHUB_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(redirect_uri)}` +
    `&scope=${encodeURIComponent(scope)}` +
    `&state=${encodeURIComponent(state)}`;

  res.statusCode = 302;
  res.setHeader('Location', url);
  res.end();
};
