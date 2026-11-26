// Stromabrechnung – kleiner Server mit GitHub-Login.
// Nur der GitHub-Benutzer aus ALLOWED_USER kommt auf die Seite.
// Benötigte Umgebungsvariablen (in Render eintragen):
//   GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, SESSION_SECRET, ALLOWED_USER
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const CLIENT_ID = process.env.GITHUB_CLIENT_ID || '';
const CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const ALLOWED_USER = (process.env.ALLOWED_USER || '').toLowerCase();
const SESSION_DAYS = 30;
const APP_FILE = path.join(__dirname, 'app', 'index.html');

const configured = CLIENT_ID && CLIENT_SECRET && SESSION_SECRET.length >= 16 && ALLOWED_USER;

function sign(value) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('base64url');
}
function makeToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return body + '.' + sign(body);
}
function readToken(token) {
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expected = sign(body);
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const data = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (!data.exp || data.exp < Date.now()) return null;
    return data;
  } catch { return null; }
}
function cookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((c) => {
    const i = c.indexOf('=');
    if (i > 0) out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
  });
  return out;
}
function setCookie(res, name, value, maxAgeSec) {
  const prev = res.getHeader('Set-Cookie') || [];
  res.setHeader('Set-Cookie', prev.concat(
    name + '=' + encodeURIComponent(value) + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=' + maxAgeSec
  ));
}
function baseUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || 'https';
  return proto + '://' + req.headers.host;
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
function redirect(res, to) { res.writeHead(302, { Location: to, 'Cache-Control': 'no-store' }); res.end(); }

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  try {
    if (!configured) {
      return page(res, 503, 'Nicht eingerichtet', '<h1>Stromabrechnung</h1><p>Der Login ist noch nicht eingerichtet. In Render fehlen GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, SESSION_SECRET oder ALLOWED_USER.</p>');
    }
    if (url.pathname === '/healthz') { res.writeHead(200); return res.end('ok'); }

    if (url.pathname === '/login') {
      const state = crypto.randomBytes(16).toString('hex');
      setCookie(res, 'oauth_state', state, 600);
      const q = new URLSearchParams({ client_id: CLIENT_ID, redirect_uri: baseUrl(req) + '/auth/callback', scope: 'read:user', state, allow_signup: 'false' });
      return redirect(res, 'https://github.com/login/oauth/authorize?' + q);
    }

    if (url.pathname === '/auth/callback') {
      const c = cookies(req);
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      if (!code || !state || state !== c.oauth_state) return page(res, 400, 'Fehler', '<h1>Anmeldung fehlgeschlagen</h1><p>Bitte nochmal versuchen.</p><a class="btn" href="/login">Erneut anmelden</a>');
      setCookie(res, 'oauth_state', '', 0);
      const tokRes = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code, redirect_uri: baseUrl(req) + '/auth/callback' })
      });
      const tok = await tokRes.json();
      if (!tok.access_token) return page(res, 401, 'Fehler', '<h1>Anmeldung fehlgeschlagen</h1><p>GitHub hat keinen Zugang bestätigt.</p><a class="btn" href="/login">Erneut anmelden</a>');
      const userRes = await fetch('https://api.github.com/user', { headers: { Authorization: 'Bearer ' + tok.access_token, 'User-Agent': 'stromabrechnung' } });
      const user = await userRes.json();
      const login = String(user.login || '').toLowerCase();
      if (login !== ALLOWED_USER) return page(res, 403, 'Kein Zugriff', '<h1>Kein Zugriff</h1><p>Dieses GitHub-Konto ist für diese Seite nicht freigeschaltet.</p>');
      setCookie(res, 'session', makeToken({ u: login, exp: Date.now() + SESSION_DAYS * 864e5 }), SESSION_DAYS * 86400);
      return redirect(res, '/');
    }

    if (url.pathname === '/logout') {
      setCookie(res, 'session', '', 0);
      return page(res, 200, 'Abgemeldet', '<h1>Abgemeldet</h1><p>Du bist abgemeldet.</p><a class="btn" href="/login">Wieder anmelden</a>');
    }

    const session = readToken(cookies(req).session);
    if (!session || session.u !== ALLOWED_USER) {
      return page(res, 401, 'Anmelden', '<h1>Stromabrechnung</h1><p>Privater Bereich. Bitte mit deinem GitHub-Konto anmelden.</p><a class="btn" href="/login">Mit GitHub anmelden</a>');
    }

    if (url.pathname === '/' || url.pathname === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY' });
      return fs.createReadStream(APP_FILE).pipe(res);
    }
    res.writeHead(404); res.end('Nicht gefunden');
  } catch (e) {
    console.error(e);
    page(res, 500, 'Fehler', '<h1>Fehler</h1><p>Etwas ist schiefgelaufen. Bitte neu laden.</p>');
  }
});

server.listen(PORT, () => console.log('Stromabrechnung läuft auf Port ' + PORT + (configured ? '' : ' (Login noch nicht eingerichtet)')));
