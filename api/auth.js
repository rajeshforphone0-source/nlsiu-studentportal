// api/auth.js — Vercel Serverless Function

const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const ALLOWED_ORIGIN   = 'https://nlsiustudent.vercel.app';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin',  ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  const { action } = req.body;
  const CLIENT_ID     = process.env.GOOGLE_CLIENT_ID;
  const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

  if (!CLIENT_ID || !CLIENT_SECRET)
    return res.status(500).json({ error: 'Server not configured' });

  // exchange: authorization code → access token + refresh token
  if (action === 'exchange') {
    const { code, code_verifier, redirect_uri } = req.body;
    if (!code || !code_verifier || !redirect_uri)
      return res.status(400).json({ error: 'Missing params' });

    const resp = await fetch(GOOGLE_TOKEN_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'authorization_code',
        client_id:     CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code,
        code_verifier,
        redirect_uri,
      }).toString(),
    });
    const data = await resp.json();
    if (data.error) return res.status(400).json({ error: data.error, description: data.error_description });
    return res.status(200).json({
      access_token:  data.access_token,
      refresh_token: data.refresh_token,
      expires_in:    data.expires_in,
    });
  }

  // refresh: refresh token → new access token (silent, no user interaction)
  if (action === 'refresh') {
    const { refresh_token } = req.body;
    if (!refresh_token) return res.status(400).json({ error: 'Missing refresh_token' });

    const resp = await fetch(GOOGLE_TOKEN_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'refresh_token',
        client_id:     CLIENT_ID,
        client_secret: CLIENT_SECRET,
        refresh_token,
      }).toString(),
    });
    const data = await resp.json();
    if (data.error) return res.status(401).json({ error: data.error });
    return res.status(200).json({
      access_token: data.access_token,
      expires_in:   data.expires_in,
    });
  }

  return res.status(400).json({ error: 'Unknown action' });
}
