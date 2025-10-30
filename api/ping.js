export default (req, res) => {
  res.json({ ok: true, env: !!process.env.GITHUB_CLIENT_ID });
};
