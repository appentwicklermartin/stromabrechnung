// Stromabrechnung – Server mit Google-Login (gleiches Prinzip wie der Parqet Rebalancer).
// OAuth-2.0-Authorization-Code-Flow mit Google + eigenes, HMAC-signiertes Session-Cookie.
// Keine Zusatzpakete: nur node:http, node:crypto und fetch.
//
// Umgebungsvariablen (in Render eintragen):
//   GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET  – Google Cloud Console, OAuth-Client "Webanwendung"
//   SESSION_SECRET                          – zufälliger String, signiert das Session-Cookie
//   ALLOWED_EMAILS                          – Komma-Liste erlaubter Google-Adressen
//
// Lokal ohne diese Variablen läuft die App ungeschützt (bequem zum Entwickeln).
// Auf Render dagegen bleibt die Seite gesperrt, bis alle vier gesetzt sind.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const ALLOWED_EMAILS = (process.env.ALLOWED_EMAILS || process.env.ALLOWED_EMAIL || '')
  .toLowerCase().split(',').map((e) => e.trim()).filter(Boolean);
const GOOGLE_AUTH_ENABLED = Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET && SESSION_SECRET && ALLOWED_EMAILS.length);
const ON_RENDER = Boolean(process.env.RENDER);

const COOKIE_NAME = 'strom_session';
const SESSION_DAYS = 30;
const STATE_TTL_MS = 10 * 60 * 1000;
const APP_FILE = path.join(__dirname, 'app', 'index.html');
const PUBLIC_AUTH_PATHS = new Set(['/auth/google/login', '/auth/google/callback', '/auth/logout', '/healthz']);

// ---------- Google OAuth ----------
const pendingStates = new Map(); // state -> Ablaufzeit
function randomState() {
  const now = Date.now();
  for (const [s, exp] of pendingStates) if (exp < now) pendingStates.delete(s);
  const state = crypto.randomBytes(24).toString('base64url');
  pendingStates.set(state, now + STATE_TTL_MS);
  return state;
}
function consumeState(state) {
  const exp = pendingStates.get(state);
  pendingStates.delete(state);
  return Boolean(exp && exp > Date.now());
}
function redirectUri(req) {
  const proto = req.headers['x-forwarded-proto'] || 'https';
  return proto + '://' + req.headers.host + '/auth/google/callback';
}
function buildGoogleAuthUrl(req, state) {
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri(req),
    response_type: 'code',
    scope: 'openid email',
    state,
    prompt: 'select_account'
  });
  return 'https://accounts.google.com/o/oauth2/v2/auth?' + params;
}
async function exchangeCodeForEmail(req, code) {
  const tokRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri(req),
      grant_type: 'authorization_code'
    })
  });
  const tok = await tokRes.json();
  if (!tok.access_token) return null;
  const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
    headers: { Authorization: 'Bearer ' + tok.access_token }
  });
  const user = await userRes.json();
  if (user.email_verified !== true || !user.email) return null;
  return String(user.email).toLowerCase();
}
function isAllowedEmail(email) { return ALLOWED_EMAILS.includes(String(email || '').toLowerCase()); }

// ---------- Session-Cookie: base64url({email, expires}) + "." + HMAC-SHA256 ----------
function sign(payload) { return crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url'); }
function createSessionValue(email) {
  const payload = Buffer.from(JSON.stringify({ email, expires: Date.now() + SESSION_DAYS * 864e5 })).toString('base64url');
  return payload + '.' + sign(payload);
}
function readSessionEmail(cookieHeader) {
  const raw = parseCookies(cookieHeader)[COOKIE_NAME];
  if (!raw || !raw.includes('.')) return null;
  const [payload, sig] = raw.split('.');
  const expected = sign(payload);
  if (!sig || sig.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (!data.expires || data.expires < Date.now()) return null;
    return data.email || null;
  } catch { return null; }
}
function parseCookies(header) {
  const out = {};
  (header || '').split(';').forEach((c) => {
    const i = c.indexOf('=');
    if (i > 0) out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
  });
  return out;
}
function sessionCookie(value, maxAgeSec) {
  return COOKIE_NAME + '=' + encodeURIComponent(value) + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=' + maxAgeSec;
}

// ---------- Antworten ----------
function redirect(res, to, cookie) {
  const headers = { Location: to, 'Cache-Control': 'no-store' };
  if (cookie) headers['Set-Cookie'] = cookie;
  res.writeHead(302, headers);
  res.end();
}
function page(res, status, title, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end('<!DOCTYPE html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + title + '</title>' +
    '<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#161616;color:#eee;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}' +
    '.box{max-width:380px;padding:28px;border:1px solid #333;border-radius:12px;background:#202020;text-align:center}' +
    'h1{font:400 26px Georgia,serif;margin:0 0 8px}p{color:#a0a0a0;margin:0 0 18px}' +
    'a.btn{display:inline-block;background:#eee;color:#161616;text-decoration:none;padding:10px 18px;border-radius:8px}</style></head>' +
    '<body><div class="box">' + html + '</div></body></html>');
}

// ---------- Server ----------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  try {
    if (p === '/healthz') { res.writeHead(200); return res.end('ok'); }

    // Auf Render ohne vollständige Login-Konfiguration: gesperrt lassen.
    if (!GOOGLE_AUTH_ENABLED && ON_RENDER) {
      return page(res, 503, 'Nicht eingerichtet', '<h1>Stromabrechnung</h1><p>Der Google-Login ist noch nicht eingerichtet. In Render fehlen GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, SESSION_SECRET oder ALLOWED_EMAILS.</p>');
    }

    if (GOOGLE_AUTH_ENABLED) {
      if (p === '/auth/google/login') return redirect(res, buildGoogleAuthUrl(req, randomState()));

      if (p === '/auth/google/callback') {
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        if (!code || !state || !consumeState(state)) return redirect(res, '/auth/google/login');
        const email = await exchangeCodeForEmail(req, code);
        if (!email || !isAllowedEmail(email)) {
          return page(res, 403, 'Kein Zugriff', '<h1>Kein Zugriff</h1><p>Dieses Google-Konto ist für diese Seite nicht freigeschaltet.</p><a class="btn" href="/auth/google/login">Anderes Konto wählen</a>');
        }
        return redirect(res, '/', sessionCookie(createSessionValue(email), SESSION_DAYS * 86400));
      }

      if (p === '/auth/logout') return redirect(res, '/auth/google/login', sessionCookie('', 0));

      // Globale Schutzschicht: alles andere nur mit gültiger Session, sonst direkt zu Google.
      if (!PUBLIC_AUTH_PATHS.has(p)) {
        const email = readSessionEmail(req.headers.cookie);
        if (!email || !isAllowedEmail(email)) return redirect(res, buildGoogleAuthUrl(req, randomState()));
      }
    }

    if (p === '/' || p === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY' });
      return fs.createReadStream(APP_FILE).pipe(res);
    }
    res.writeHead(404); res.end('Nicht gefunden');
  } catch (e) {
    console.error(e);
    page(res, 500, 'Fehler', '<h1>Fehler</h1><p>Etwas ist schiefgelaufen.</p><a class="btn" href="/">Neu laden</a>');
  }
});

server.listen(PORT, () => console.log('Stromabrechnung läuft auf Port ' + PORT + (GOOGLE_AUTH_ENABLED ? ' (Google-Login aktiv)' : ' (Google-Login nicht konfiguriert)')));
