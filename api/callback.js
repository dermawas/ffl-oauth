const https = require("https");

function htmlSuccess(token, openerOrigin = "*") {
  // send to '*' AND to your exact site origin as a fallback
  const siteOrigin = "https://flowformlab.com";
  return `
<!doctype html>
<meta charset="utf-8">
<title>Authorized</title>
<script>
  (function () {
    var msg = \`authorization:github:success:${token}\`;
    try {
      if (window.opener) {
        window.opener.postMessage(msg, "*");
        window.opener.postMessage(msg, "${siteOrigin}");
      }
    } catch (e) {}
    window.close();
  })();
</script>
<p>Authorized. You can close this window.</p>`;
}

function htmlError(err) {
  return `
<!doctype html>
<meta charset="utf-8">
<title>Authorization Error</title>
<script>
  (function () {
    var msg = \`authorization:github:error:${String(err).replace(/'/g,"\\'")}\`;
    try { window.opener && window.opener.postMessage(msg, "*"); } catch (e) {}
    window.close();
  })();
</script>
<p>Authorization failed: ${String(err)}</p>`;
}

function exchangeCode({ code, client_id, client_secret, redirect_uri }) {
  const body = JSON.stringify({ client_id, client_secret, code, redirect_uri });
  const opts = {
    method: "POST",
    hostname: "github.com",
    path: "/login/oauth/access_token",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json",
      "Content-Length": Buffer.byteLength(body),
      "User-Agent": "decap-oauth-proxy"
    }
  };
  return new Promise((resolve, reject) => {
    const req = https.request(opts, res => {
      let data = "";
      res.on("data", d => (data += d));
      res.on("end", () => {
        try {
          const json = JSON.parse(data);
          if (json.error) return reject(json.error_description || json.error);
          if (!json.access_token) return reject("No access_token in response");
          resolve(json.access_token);
        } catch {
          reject("Invalid token response");
        }
      });
    });
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

function getRedirectURI(req) {
  const proto = (req.headers["x-forwarded-proto"] || "").split(",")[0] || "https";
  const host  = req.headers["x-forwarded-host"] || req.headers.host;
  return `${proto}://${host}/api/callback`;
}

module.exports = async (req, res) => {
  const { code, state } = req.query || {};
  const { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET } = process.env;

  if (!code)      return res.status(400).send(htmlError("Missing ?code"));
  if (!state)     return res.status(400).send(htmlError("Missing ?state"));
  if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET)
    return res.status(500).send(htmlError("Missing GITHUB_CLIENT_ID/SECRET"));

  const cookies = String(req.headers.cookie || "")
    .split(";").map(s => s.trim());
  const stateCookie = cookies.find(c => c.startsWith("oauth_state="))?.split("=")[1] || "";
  if (state !== stateCookie) {
    return res.status(400).send(htmlError("Invalid state"));
  }

  try {
    const token = await exchangeCode({
      code,
      client_id: GITHUB_CLIENT_ID,
      client_secret: GITHUB_CLIENT_SECRET,
      redirect_uri: getRedirectURI(req)
    });

    // clear state cookie
    res.setHeader("Set-Cookie", "oauth_state=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure");
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.end(htmlSuccess(token));
  } catch (err) {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.status(400).end(htmlError(String(err)));
  }
};
