// netlify/functions/auth.js
// Handles Google OAuth token exchange and refresh for nlsiuportal.netlify.app
// Environment variables needed (set in Netlify dashboard):
//   GOOGLE_CLIENT_ID     — your OAuth 2.0 client ID
//   GOOGLE_CLIENT_SECRET — your OAuth 2.0 client secret

const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const ALLOWED_ORIGIN   = 'https://nlsiuportal.netlify.app';

exports.handler = async (event) => {
  // CORS headers — only allow requests from your portal
  const headers = {
    'Access-Control-Allow-Origin':  ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };

  // Handle CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers, body: '' };
  }
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid JSON' }) };
  }

  const { action } = body;
  const CLIENT_ID     = process.env.GOOGLE_CLIENT_ID;
  const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

  if (!CLIENT_ID || !CLIENT_SECRET) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'Server not configured' }) };
  }

  // ── ACTION: exchange ──────────────────────────────────────────────────────
  // Trade an authorization code for access + refresh tokens
  if (action === 'exchange') {
    const { code, code_verifier, redirect_uri } = body;
    if (!code || !code_verifier || !redirect_uri) {
      return { statusCode: 400, headers, body: JSON.stringify({ error: 'Missing params' }) };
    }

    const params = new URLSearchParams({
      grant_type:    'authorization_code',
      client_id:     CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code,
      code_verifier,
      redirect_uri,
    });

    const resp = await fetch(GOOGLE_TOKEN_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body:    params.toString(),
    });

    const data = await resp.json();
    if (data.error) {
      return { statusCode: 400, headers, body: JSON.stringify({ error: data.error, description: data.error_description }) };
    }

    // Return access_token + refresh_token to client
    // Client stores refresh_token in localStorage (acceptable for personal single-user app)
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        access_token:  data.access_token,
        refresh_token: data.refresh_token,
        expires_in:    data.expires_in,   // seconds (typically 3600)
      }),
    };
  }

  // ── ACTION: refresh ───────────────────────────────────────────────────────
  // Trade a refresh token for a new access token (silent, no user interaction)
  if (action === 'refresh') {
    const { refresh_token } = body;
    if (!refresh_token) {
      return { statusCode: 400, headers, body: JSON.stringify({ error: 'Missing refresh_token' }) };
    }

    const params = new URLSearchParams({
      grant_type:    'refresh_token',
      client_id:     CLIENT_ID,
      client_secret: CLIENT_SECRET,
      refresh_token,
    });

    const resp = await fetch(GOOGLE_TOKEN_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body:    params.toString(),
    });

    const data = await resp.json();
    if (data.error) {
      // refresh_token itself has expired or been revoked — client must re-auth
      return { statusCode: 401, headers, body: JSON.stringify({ error: data.error }) };
    }

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        access_token: data.access_token,
        expires_in:   data.expires_in,
      }),
    };
  }

  return { statusCode: 400, headers, body: JSON.stringify({ error: 'Unknown action' }) };
};
