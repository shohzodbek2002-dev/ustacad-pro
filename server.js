#!/usr/bin/env node
/* UstaCAD 5.8 PRO — yordamchi server (Node 18+, qo'shimcha paketsiz)
 *
 *   GET  /            -> {ok:true,service,version}      (ulanishni tekshirish)
 *   POST /upload      -> stanok fayli (multipart: file, machine, name) UPLOAD_DIR ga saqlanadi
 *   POST /telegram    -> Telegramga uzatish (multipart: chat_id, caption, filename, initData, document)
 *   POST /pro         -> Pro tarif holati (multipart: initData) -> {ok,pro,until,id}
 *
 * Bot tokeni FAQAT shu yerda (muhit o'zgaruvchisi) turadi — brauzerga/HTML ga hech qachon yuborilmaydi.
 *
 * Muhit o'zgaruvchilari:
 *   PORT=8080  HOST=127.0.0.1
 *   ALLOWED_ORIGINS="https://sizning-sayt.uz,null"   (vergul bilan; "*" = hammasi; bo'sh = faqat "null" va localhost)
 *   UPLOAD_DIR=./uploads  MAX_BYTES=20971520  REQUEST_TIMEOUT_MS=30000  RATE_LIMIT_PER_MIN=60
 *   TELEGRAM_BOT_TOKEN=123456:ABC...   TELEGRAM_ALLOWED_CHATS="123456789,-1001234567890"
 *   TELEGRAM_API_BASE=https://api.telegram.org   TELEGRAM_TIMEOUT_MS=20000
 *   PRO_IDS="5023880281,111222333:2026-12-31"   Pro tarif ochilgan Telegram ID'lar (vergul bilan).
 *            "ID:YYYY-MM-DD" = shu sanagacha (shu kun ham kiradi). "*" = hamma uchun Pro (qulf o'chiq).
 *
 * DIQQAT: server stanokni O'ZI ishga tushirmaydi — faylni qabul qilib saqlaydi, xolos.
 */
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const VERSION = '5.8';
const ALLOWED_EXT = ['.tap', '.nc', '.gcode', '.dxf', '.csv', '.txt', '.json', '.pdf'];

function cfgFromEnv(env) {
  env = env || process.env;
  const num = (k, d) => { const v = Number(env[k]); return Number.isFinite(v) && v > 0 ? v : d; };
  const list = (k) => String(env[k] || '').split(',').map(s => s.trim()).filter(Boolean);
  return {
    port: (env.PORT !== undefined && env.PORT !== '' && Number.isInteger(Number(env.PORT)) && Number(env.PORT) >= 0 && Number(env.PORT) < 65536) ? Number(env.PORT) : 8080,
    host: env.HOST || '127.0.0.1',
    origins: list('ALLOWED_ORIGINS'),
    uploadDir: path.resolve(env.UPLOAD_DIR || './uploads'),
    maxBytes: num('MAX_BYTES', 20 * 1024 * 1024),
    reqTimeout: num('REQUEST_TIMEOUT_MS', 30000),
    rate: num('RATE_LIMIT_PER_MIN', 60),
    tgToken: String(env.TELEGRAM_BOT_TOKEN || '').trim(),
    tgChats: list('TELEGRAM_ALLOWED_CHATS'),
    proIds: list('PRO_IDS'),
    tgBase: String(env.TELEGRAM_API_BASE || 'https://api.telegram.org').replace(/\/+$/, ''),
    tgTimeout: num('TELEGRAM_TIMEOUT_MS', 20000)
  };
}

class HttpErr extends Error { constructor(status, msg) { super(msg); this.status = status; } }

function originAllowed(cfg, origin) {
  if (!origin) return true; // brauzersiz mijoz (curl) — CORS ishlatmaydi
  if (cfg.origins.includes('*')) return true;
  if (cfg.origins.length) return cfg.origins.includes(origin);
  return origin === 'null' || /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(origin);
}

/* Telegram Mini App initData tekshiruvi (rasmiy algoritm: HMAC-SHA256, "WebAppData") */
function verifyInitData(initData, token, maxAgeSec) {
  if (!initData || !token) return null;
  const p = new URLSearchParams(initData);
  const hash = p.get('hash');
  if (!hash) return null;
  p.delete('hash');
  const dcs = [...p.entries()].map(([k, v]) => k + '=' + v).sort().join('\n');
  const secret = crypto.createHmac('sha256', 'WebAppData').update(token).digest();
  const calc = crypto.createHmac('sha256', secret).update(dcs).digest('hex');
  const a = Buffer.from(calc, 'hex'), b = Buffer.from(hash, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  const age = Math.floor(Date.now() / 1000) - Number(p.get('auth_date') || 0);
  if (!(age >= 0 && age <= (maxAgeSec || 86400))) return null;
  try { return JSON.parse(p.get('user') || 'null'); } catch (e) { return null; }
}

/* Pro tarif: PRO_IDS ro'yxati bo'yicha. "*" = hamma Pro; "ID:YYYY-MM-DD" = muddatli. */
function proStatus(cfg, userId) {
  const list = (cfg && cfg.proIds) || [];
  if (list.includes('*')) return { pro: true, until: null, all: true };
  if (!userId) return { pro: false };
  const today = new Date().toISOString().slice(0, 10);
  for (const item of list) {
    const i = item.indexOf(':');
    const id = i < 0 ? item : item.slice(0, i);
    const until = i < 0 ? '' : item.slice(i + 1);
    if (id !== String(userId)) continue;
    if (until && !/^\d{4}-\d{2}-\d{2}$/.test(until)) continue;
    if (until && until < today) return { pro: false, expired: until };
    return { pro: true, until: until || null };
  }
  return { pro: false };
}

function readBody(req, limit, timeoutMs) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0, done = false;
    const fail = (err) => { if (done) return; done = true; clearTimeout(timer); req.removeAllListeners('data'); reject(err); req.resume(); };
    const timer = setTimeout(() => fail(new HttpErr(408, 'So\'rov vaqti tugadi')), timeoutMs);
    const declared = Number(req.headers['content-length'] || 0);
    if (declared > limit) return fail(new HttpErr(413, 'Fayl juda katta (maks. ' + Math.round(limit / 1048576) + ' MB)'));
    req.on('data', (c) => { size += c.length; if (size > limit) return fail(new HttpErr(413, 'Fayl juda katta (maks. ' + Math.round(limit / 1048576) + ' MB)')); chunks.push(c); });
    req.on('end', () => { if (done) return; done = true; clearTimeout(timer); resolve(Buffer.concat(chunks)); });
    req.on('error', () => fail(new HttpErr(400, 'So\'rov uzildi')));
    req.on('aborted', () => fail(new HttpErr(400, 'So\'rov uzildi')));
  });
}

async function readForm(req, cfg) {
  const ct = String(req.headers['content-type'] || '');
  if (!/^multipart\/form-data;\s*boundary=/i.test(ct)) throw new HttpErr(415, 'multipart/form-data kerak');
  const buf = await readBody(req, cfg.maxBytes + 65536, cfg.reqTimeout);
  try { return await new Response(buf, { headers: { 'content-type': ct } }).formData(); }
  catch (e) { throw new HttpErr(400, 'multipart noto\'g\'ri'); }
}

function safeName(n) {
  let b = path.basename(String(n || 'fayl')).replace(/[^\w.\-]+/g, '_').replace(/^\.+/, '').slice(0, 80) || 'fayl';
  return b;
}

function createApp(cfg) {
  const hits = new Map();
  function limited(ip) {
    const now = Date.now(), w = hits.get(ip) || [];
    const recent = w.filter(t => now - t < 60000); recent.push(now); hits.set(ip, recent);
    if (hits.size > 5000) hits.clear();
    return recent.length > cfg.rate;
  }
  function send(res, status, obj, extra) {
    const body = JSON.stringify(obj);
    const close = (status === 408 || status === 413) ? { 'Connection': 'close' } : {};
    res.writeHead(status, Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(body) }, close, extra || {}));
    res.end(body);
  }

  async function handleUpload(req, res, cors) {
    const form = await readForm(req, cfg);
    const f = form.get('file');
    if (!f || typeof f === 'string' || typeof f.arrayBuffer !== 'function') throw new HttpErr(400, '"file" maydoni yo\'q');
    const name = safeName(form.get('name') || f.name);
    const ext = path.extname(name).toLowerCase();
    if (!ALLOWED_EXT.includes(ext)) throw new HttpErr(400, 'Fayl turi ruxsat etilmagan (' + (ext || 'kengaytmasiz') + ')');
    const data = Buffer.from(await f.arrayBuffer());
    if (!data.length) throw new HttpErr(400, 'Fayl bo\'sh');
    if (data.length > cfg.maxBytes) throw new HttpErr(413, 'Fayl juda katta');
    await fs.promises.mkdir(cfg.uploadDir, { recursive: true });
    const saved = new Date().toISOString().replace(/[:.]/g, '-') + '_' + crypto.randomBytes(3).toString('hex') + '_' + name;
    await fs.promises.writeFile(path.join(cfg.uploadDir, saved), data, { flag: 'wx' });
    send(res, 200, { ok: true, saved, bytes: data.length }, cors);
  }

  async function handleTelegram(req, res, cors) {
    if (!cfg.tgToken) throw new HttpErr(503, 'Telegram serverda sozlanmagan (TELEGRAM_BOT_TOKEN yo\'q)');
    const form = await readForm(req, cfg);
    const chat = String(form.get('chat_id') || '').trim();
    if (!/^-?\d+$|^@\w+$/.test(chat)) throw new HttpErr(400, 'chat_id noto\'g\'ri');
    const doc = form.get('document');
    if (!doc || typeof doc === 'string' || typeof doc.arrayBuffer !== 'function') throw new HttpErr(400, '"document" maydoni yo\'q');
    if (doc.size > cfg.maxBytes) throw new HttpErr(413, 'Fayl juda katta');
    const user = verifyInitData(String(form.get('initData') || ''), cfg.tgToken);
    const ok = (user && String(user.id) === chat) || cfg.tgChats.includes(chat);
    if (!ok) throw new HttpErr(403, 'Bu chatga yuborishga ruxsat yo\'q');
    const fd = new FormData();
    fd.append('chat_id', chat);
    fd.append('caption', String(form.get('caption') || '').slice(0, 1000));
    fd.append('document', new Blob([await doc.arrayBuffer()]), safeName(form.get('filename') || doc.name));
    const ac = new AbortController(); const tm = setTimeout(() => ac.abort(), cfg.tgTimeout);
    let r, j;
    try {
      r = await fetch(cfg.tgBase + '/bot' + cfg.tgToken + '/sendDocument', { method: 'POST', body: fd, signal: ac.signal });
      j = await r.json().catch(() => null);
    } catch (e) {
      throw new HttpErr(e && e.name === 'AbortError' ? 504 : 502, e && e.name === 'AbortError' ? 'Telegram javob bermadi (vaqt tugadi)' : 'Telegramga ulanib bo\'lmadi');
    } finally { clearTimeout(tm); }
    if (!r.ok || !j || j.ok !== true) throw new HttpErr(502, 'Telegram: ' + String((j && j.description) || ('HTTP ' + r.status)).replace(cfg.tgToken, '***').slice(0, 160));
    send(res, 200, { ok: true }, cors);
  }

  async function handlePro(req, res, cors) {
    const form = await readForm(req, cfg);
    const user = verifyInitData(String(form.get('initData') || ''), cfg.tgToken);
    send(res, 200, Object.assign({ ok: true, id: user ? String(user.id) : null }, proStatus(cfg, user && user.id)), cors);
  }

  return async function app(req, res) {
    const origin = req.headers.origin;
    const cors = {};
    try {
      const ip = req.socket.remoteAddress || '?';
      if (!originAllowed(cfg, origin)) throw new HttpErr(403, 'Origin ruxsat etilmagan');
      if (origin) { cors['Access-Control-Allow-Origin'] = cfg.origins.includes('*') ? '*' : origin; cors['Vary'] = 'Origin'; }
      if (req.method === 'OPTIONS') {
        res.writeHead(204, Object.assign({ 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '600' }, cors));
        return res.end();
      }
      if (limited(ip)) throw new HttpErr(429, 'Juda ko\'p so\'rov');
      const url = new URL(req.url, 'http://x'); const p = url.pathname.replace(/\/+$/, '') || '/';
      const routes = { '/': ['GET'], '/health': ['GET'], '/upload': ['GET', 'POST'], '/telegram': ['GET', 'POST'], '/pro': ['GET', 'POST'] };
      if (!routes[p]) throw new HttpErr(404, 'Topilmadi');
      if (!routes[p].includes(req.method)) { cors['Allow'] = routes[p].join(', '); throw new HttpErr(405, 'Usul ruxsat etilmagan'); }
      if (req.method === 'GET') return send(res, 200, { ok: true, service: 'ustacad-server', version: VERSION, telegram: !!cfg.tgToken }, cors);
      if (p === '/upload') return await handleUpload(req, res, cors);
      if (p === '/pro') return await handlePro(req, res, cors);
      return await handleTelegram(req, res, cors);
    } catch (e) {
      const status = e instanceof HttpErr ? e.status : 500;
      if (!(e instanceof HttpErr)) console.error('Ichki xato:', e && e.message);
      send(res, status, { ok: false, error: e instanceof HttpErr ? e.message : 'Ichki server xatosi' }, cors);
    }
  };
}

function start(cfg) {
  cfg = cfg || cfgFromEnv();
  const server = http.createServer(createApp(cfg));
  server.requestTimeout = cfg.reqTimeout + 5000;
  server.headersTimeout = Math.min(cfg.reqTimeout, 15000);
  server.keepAliveTimeout = 5000;
  return new Promise((resolve) => server.listen(cfg.port, cfg.host, () => resolve(server)));
}

module.exports = { cfgFromEnv, createApp, start, verifyInitData, originAllowed, proStatus };

if (require.main === module) {
  const cfg = cfgFromEnv();
  start(cfg).then((s) => console.log('UstaCAD server ' + VERSION + ' http://' + cfg.host + ':' + s.address().port + '  (telegram: ' + (cfg.tgToken ? 'yoqilgan' : 'sozlanmagan') + ')'));
}
