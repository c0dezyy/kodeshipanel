const express = require('express');
const multer = require('multer');
const SftpClient = require('ssh2-sftp-client');
const net = require('net');
const crypto = require('crypto');
const path = require('path');

/* ============ CONFIG (server-side only, never sent to the browser) ============ */
const env = process.env;
const PANEL_USER = env.PANEL_USER || 'kingsav';
const PANEL_PASS = env.PANEL_PASS || 'kingsav12345';

const RCON_HOST = env.RCON_HOST || '15.235.165.81';
const RCON_PORT = parseInt(env.RCON_PORT || '26098', 10);
const RCON_PASS = env.RCON_PASS || 'kodeshi019019';

const SFTP_HOST = env.SFTP_HOST || 'as-sg-n01.pixelforge.gg';
const SFTP_PORT = parseInt(env.SFTP_PORT || '2022', 10);
const SFTP_USER = env.SFTP_USER || 'codezyy.046d87d4';
const SFTP_PASS = env.SFTP_PASS || 'codezyy@72443';

const LOG_PATH = env.LOG_PATH || '/logs/latest.log';

// OPTIONAL real power control through a Pterodactyl-style panel API
const PANEL_URL = env.PANEL_URL || '';
const PANEL_API_KEY = env.PANEL_API_KEY || '';
const PANEL_SERVER = env.PANEL_SERVER || '046d87d4';

const BLOCKED = ['tp', 'give', 'teleport'];
/* ============================================================================== */

const SECRET = env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_MS = 12 * 3600 * 1000;

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

class HttpError extends Error { constructor(msg, code = 400) { super(msg); this.code = code; } }

/* ---------- sessions (signed cookie, no storage needed) ---------- */
const sign = v => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
function makeToken() { const exp = String(Date.now() + SESSION_MS); return exp + '.' + sign(exp); }
function validToken(t) {
  if (!t) return false;
  const [exp, sig] = t.split('.');
  if (!exp || !sig) return false;
  const good = sign(exp);
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return false;
  return Number(exp) > Date.now();
}
function getCookie(req, name) {
  const m = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : '';
}
const authed = req => validToken(getCookie(req, 'sid'));
function setCookie(res, req, val, maxAge) {
  res.append('Set-Cookie', `sid=${encodeURIComponent(val)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${req.secure ? '; Secure' : ''}`);
}
const safeEq = (a, b) => {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
};

/* ---------- login throttle ---------- */
const fails = new Map();
function throttled(ip) { const f = fails.get(ip); return f && f.lock > Date.now(); }
function noteFail(ip) {
  const f = fails.get(ip) || { n: 0, lock: 0 };
  f.n++;
  if (f.n >= 5) { f.lock = Date.now() + 60000; f.n = 0; }
  fails.set(ip, f);
}

/* ---------- path safety ---------- */
function cp(p) {
  const parts = [];
  for (const s of String(p || '').replace(/\\/g, '/').split('/')) {
    if (s === '' || s === '.') continue;
    if (s === '..') throw new HttpError('Invalid path');
    parts.push(s);
  }
  return '/' + parts.join('/');
}

/* ---------- RCON ---------- */
function rcon(cmd) {
  return new Promise((resolve, reject) => {
    const s = net.createConnection({ host: RCON_HOST, port: RCON_PORT });
    let buf = Buffer.alloc(0), stage = 0, out = '', done = false;
    const finish = (err, val) => {
      if (done) return; done = true; clearTimeout(timer); s.destroy();
      err ? reject(err) : resolve(val);
    };
    const timer = setTimeout(() => finish(new Error('RCON timed out. Is the server online?')), 8000);
    const send = (id, type, body) => {
      const b = Buffer.from(body, 'utf8'), p = Buffer.alloc(14 + b.length);
      p.writeInt32LE(10 + b.length, 0); p.writeInt32LE(id, 4); p.writeInt32LE(type, 8); b.copy(p, 12);
      s.write(p);
    };
    s.on('connect', () => send(1, 3, RCON_PASS));
    s.on('error', e => finish(new Error('Cannot reach RCON: ' + e.message)));
    s.on('close', () => finish(null, out));
    s.on('data', d => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 4) {
        const len = buf.readInt32LE(0);
        if (buf.length < 4 + len) break;
        const id = buf.readInt32LE(4);
        const body = buf.toString('utf8', 12, 4 + len - 2);
        buf = buf.subarray(4 + len);
        if (stage === 0) {
          if (id === -1) return finish(new Error('RCON authentication failed'));
          stage = 1; send(2, 2, cmd); send(3, 0, '');   // 2nd packet marks the end of a multi-packet reply
        } else if (id === 2) out += body;
        else if (id === 3) return finish(null, out);
      }
    });
  }).then(t => t.replace(/§./g, ''));
}
function blocked(cmd) {
  let c = cmd.toLowerCase().trim().replace(/^[\/\s]+/, '').replace(/^minecraft:/, '');
  const first = c.split(/\s+/)[0] || '';
  if (BLOCKED.includes(first)) return true;
  if (first === 'execute' && new RegExp('\\brun\\s+/?(minecraft:)?(' + BLOCKED.join('|') + ')\\b').test(c)) return true;
  return false;
}

/* ---------- SFTP ---------- */
async function sftp(fn) {
  const c = new SftpClient();
  try {
    await c.connect({ host: SFTP_HOST, port: SFTP_PORT, username: SFTP_USER, password: SFTP_PASS, readyTimeout: 15000 });
    return await fn(c);
  } catch (e) {
    if (e instanceof HttpError) throw e;
    throw new HttpError('SFTP: ' + (e.message || e), 500);
  } finally {
    c.end().catch(() => {});
  }
}
async function tailLog(c) {
  const max = 40000;
  let st;
  try { st = await c.stat(LOG_PATH); } catch { throw new HttpError('Log not found: ' + LOG_PATH, 500); }
  const start = Math.max(0, st.size - max);
  if (st.size === 0) return '';
  const stream = c.createReadStream(LOG_PATH, { start, end: st.size - 1 });
  const chunks = [];
  for await (const ch of stream) chunks.push(ch);
  return Buffer.concat(chunks).toString('utf8').replace(/\x1b\[[0-9;?]*[A-Za-z]|§./g, '');
}

/* ---------- power ---------- */
async function panelPower(signal) {
  const r = await fetch(PANEL_URL.replace(/\/$/, '') + '/api/client/servers/' + PANEL_SERVER + '/power', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + PANEL_API_KEY, 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ signal })
  });
  if (r.status !== 204) throw new HttpError('Panel API returned HTTP ' + r.status, 500);
}

/* ======================= ROUTES ======================= */
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

app.get(['/', '/index.html'], (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.use('/api.php', express.json({ limit: '5mb' }), upload.single('file'));

app.all('/api.php', async (req, res) => {
  const send = (obj, code = 200) => res.status(code).json(obj);
  try {
    const post = req.method === 'POST';
    if (post && req.headers['x-requested-with'] !== 'panel') throw new HttpError('Bad request', 403);
    const q = post ? (req.body || {}) : {};
    const action = q.action || req.query.action || '';

    if (action === 'login') {
      const ip = req.ip;
      if (throttled(ip)) throw new HttpError('Too many attempts. Wait a minute.', 429);
      if (safeEq(q.username || '', PANEL_USER) && safeEq(q.password || '', PANEL_PASS)) {
        fails.delete(ip);
        setCookie(res, req, makeToken(), SESSION_MS / 1000);
        return send({ ok: true });
      }
      noteFail(ip);
      await new Promise(r => setTimeout(r, 1000));
      throw new HttpError('Invalid username or password', 401);
    }
    if (action === 'logout') { setCookie(res, req, '', 0); return send({ ok: true }); }
    if (action === 'me') return send({ ok: true, auth: authed(req) });

    if (!authed(req)) throw new HttpError('Not logged in', 401);

    switch (action) {
      case 'status':
        try { return send({ ok: true, online: true, info: await rcon('list') }); }
        catch (e) { return send({ ok: true, online: false, info: e.message }); }

      case 'console': {
        const cmd = String(q.command || '').trim();
        if (!cmd || cmd.length > 500) throw new HttpError('Empty or too long command');
        if (blocked(cmd)) throw new HttpError('This command is forbidden: /tp and /give cannot be used here', 403);
        return send({ ok: true, output: await rcon(cmd) });
      }

      case 'log':
        return send({ ok: true, log: await sftp(tailLog) });

      case 'power': {
        const sig = q.signal;
        if (!['start', 'stop', 'restart'].includes(sig)) throw new HttpError('Bad signal');
        if (PANEL_URL && PANEL_API_KEY) {
          await panelPower(sig);
          return send({ ok: true, message: sig[0].toUpperCase() + sig.slice(1) + ' signal sent' });
        }
        if (sig === 'start') throw new HttpError('Start is not possible over RCON while the server is offline. Set PANEL_URL and PANEL_API_KEY, or start it from your host.');
        await rcon('stop');
        return send({ ok: true, message: sig === 'restart'
          ? 'Stop command sent. The server comes back only if your host auto-restarts it.'
          : 'Stop command sent' });
      }

      case 'list': {
        const p = cp(q.path || '/');
        const items = await sftp(async c => (await c.list(p)).map(f => ({
          name: f.name, dir: f.type === 'd', size: f.size || 0, mtime: Math.floor((f.modifyTime || 0) / 1000)
        })));
        items.sort((a, b) => (b.dir - a.dir) || a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
        return send({ ok: true, path: p, items });
      }
      case 'read': {
        const p = cp(q.path);
        const d = await sftp(c => c.get(p));
        if (d.length > 2000000) throw new HttpError('File too large to edit (2 MB max)');
        if (d.includes(0)) throw new HttpError('Binary file, download it instead');
        return send({ ok: true, content: d.toString('utf8') });
      }
      case 'write':
        await sftp(c => c.put(Buffer.from(String(q.content ?? ''), 'utf8'), cp(q.path)));
        return send({ ok: true });
      case 'delete': {
        const p = cp(q.path);
        if (p === '/') throw new HttpError('Refusing');
        await sftp(async c => {
          const st = await c.stat(p);
          if (st.isDirectory) await c.rmdir(p, true); else await c.delete(p);
        });
        return send({ ok: true });
      }
      case 'mkdir':
        await sftp(c => c.mkdir(cp(q.path), true));
        return send({ ok: true });
      case 'rename':
        await sftp(c => c.rename(cp(q.from), cp(q.to)));
        return send({ ok: true });
      case 'upload': {
        if (!req.file) throw new HttpError('Upload failed');
        const dir = cp(q.path || '/');
        const name = path.basename(req.file.originalname).replace(/[\/\\]/g, '');
        await sftp(c => c.put(req.file.buffer, (dir === '/' ? '' : dir) + '/' + name));
        return send({ ok: true });
      }
      case 'download': {
        const p = cp(req.query.path);
        const d = await sftp(c => c.get(p));
        res.set({
          'Content-Type': 'application/octet-stream',
          'Content-Disposition': 'attachment; filename="' + encodeURIComponent(path.basename(p)) + '"'
        });
        return res.send(d);
      }
      default: throw new HttpError('Unknown action', 404);
    }
  } catch (e) {
    send({ ok: false, error: e.message || 'Server error' }, e.code || 500);
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Control panel running on port ' + PORT));
