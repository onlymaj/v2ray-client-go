// In-memory fake backend state plus a 1 Hz simulation of traffic, health
// checks, group selection and connections.
import { randomUUID, randomBytes } from 'node:crypto';
import { blankClient } from './links.js';

let seq = 100;
export const newId = (p) => `${p}${++seq}`;
const now = () => Math.floor(Date.now() / 1000);
const iso = (sec) => new Date(sec * 1000).toISOString();
const rnd = (a, b) => a + Math.random() * (b - a);
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

const reality = (o) => ({
  ...blankClient(),
  protocol: 'vless', port: 443, flow: 'xtls-rprx-vision', tls: 'reality', fingerprint: 'chrome',
  publicKey: randomBytes(32).toString('base64url'), shortId: randomBytes(4).toString('hex'), ...o,
});

const seedClients = [
  reality({ name: 'DE Hetzner Reality', address: '91.107.188.24', sni: 'www.microsoft.com' }),
  reality({ name: 'NL Reality Vision', address: '45.144.31.7', sni: 'dl.google.com', spiderX: '/' }),
  { ...blankClient(), name: 'FI WS CDN', protocol: 'vless', address: 'cdn.fastnode.ir', port: 443, network: 'ws',
    tls: 'tls', sni: 'fi.fastnode.ir', host: 'fi.fastnode.ir', path: '/ws?ed=2048', alpn: ['h2', 'http/1.1'] },
  { ...blankClient(), name: 'TR gRPC', protocol: 'vless', address: '185.231.59.12', port: 2053, network: 'grpc',
    tls: 'tls', sni: 'tr.example.net', serviceName: 'GunService', fingerprint: 'firefox' },
  { ...blankClient(), name: 'AM VMess WS', protocol: 'vmess', address: '217.76.14.90', port: 8443, network: 'ws',
    security: 'auto', tls: 'tls', sni: 'am.relaybox.org', host: 'am.relaybox.org', path: '/vm' },
  { ...blankClient(), name: 'FR VMess plain', protocol: 'vmess', address: '51.38.112.4', port: 8080, network: 'ws',
    security: 'aes-128-gcm', path: '/', host: '' },
  reality({ name: 'UAE Reality', address: '5.182.36.201', sni: 'www.apple.com', fingerprint: 'safari' }),
  { ...blankClient(), name: 'Old backup', protocol: 'vmess', address: '103.21.244.9', port: 443, network: 'tcp',
    security: 'auto', tls: 'tls', sni: 'old.backup.example', enabled: false },
];

/** Per-client simulation knobs, not part of the API. */
const sim = new Map();

export const db = {
  clients: [],
  groups: [],
  rules: [],
  subscriptions: [],
  connections: [],
  settings: {
    ports: { transparent: 12345, socks: 1080, http: 8118, dns: 5353, ui: 8080 },
    healthUrl: 'https://www.gstatic.com/generate_204',
    healthInterval: 30,
    killSwitch: 'block',
    dnsUpstream: '1.1.1.1:53',
    routeros: { enabled: true, url: 'http://192.168.88.1', user: 'v2ray', password: 'secret', addressList: 'v2ray-bypass' },
  },
  sessions: new Set(),
};

export function addClient(c) {
  const id = c.id || newId('c');
  const t = now();
  const client = {
    ...blankClient(), ...c, id,
    status: { state: c.enabled === false ? 'disabled' : 'unknown', tcpMs: null, delayMs: null, lastError: '', lastSuccess: '', lastCheck: '' },
    traffic: { up: 0, down: 0, upRate: 0, downRate: 0, conns: 0 },
  };
  if (!client.uuid) client.uuid = randomUUID();
  if (client.enabled && !c.status) {
    client.status = { state: 'up', tcpMs: 0, delayMs: 0, lastError: '', lastSuccess: iso(t), lastCheck: iso(t) };
  }
  sim.set(id, { lat: rnd(60, 260), up: rnd(5e3, 6e4), down: rnd(5e4, 9e5), broken: false });
  db.clients.push(client);
  pingClient(client, false);
  return client;
}

seedClients.forEach((c, i) => addClient({ ...c, id: `c${i + 1}` }));
{
  const t = now();
  const uae = db.clients[6];
  sim.get('c7').broken = true;
  uae.status = { state: 'down', tcpMs: null, delayMs: null, lastError: 'dial tcp 5.182.36.201:443: i/o timeout',
    lastSuccess: iso(t - 3 * 3600 - 412), lastCheck: iso(t - 4) };
  db.clients[7].status = { state: 'disabled', tcpMs: null, delayMs: null, lastError: '', lastSuccess: iso(t - 9 * 86400), lastCheck: iso(t - 9 * 86400) };
  db.clients[0].traffic.up = 1.9e9; db.clients[0].traffic.down = 41.2e9;
  db.clients[1].traffic.up = 0.8e9; db.clients[1].traffic.down = 17.5e9;
}

const emptyTraffic = () => ({ up: 0, down: 0, upRate: 0, downRate: 0, conns: 0 });
db.groups = [
  { id: 'g1', name: 'Main', strategy: 'least-ping', members: ['c1', 'c2', 'c3', 'c7'], stickyIncludeDest: false, current: 'c1', traffic: emptyTraffic() },
  { id: 'g2', name: 'Streaming', strategy: 'failover', members: ['c3', 'c4', 'c5'], stickyIncludeDest: false, current: 'c3', traffic: emptyTraffic() },
  { id: 'g3', name: 'Work sticky', strategy: 'sticky', members: ['c2', 'c1', 'c6'], stickyIncludeDest: true, current: 'c2', traffic: emptyTraffic() },
];

db.rules = [
  { id: 'r1', type: 'source', values: ['192.168.88.50'], target: { kind: 'direct', id: '' } },
  { id: 'r2', type: 'domain', values: ['doubleclick.net', 'googlesyndication.com', 'app-measurement.com'], target: { kind: 'block', id: '' } },
  { id: 'r3', type: 'domain', values: ['ir', 'digikala.com', 'aparat.com', 'snapp.ir'], target: { kind: 'direct', id: '' } },
  { id: 'r4', type: 'dest', values: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'], target: { kind: 'direct', id: '' } },
  { id: 'r5', type: 'domain', values: ['netflix.com', 'nflxvideo.net', 'googlevideo.com', 'youtube.com'], target: { kind: 'group', id: 'g2' } },
  { id: 'r6', type: 'source', values: ['192.168.88.20/30'], target: { kind: 'group', id: 'g3' } },
  { id: 'r7', type: 'domain', values: ['telegram.org', 't.me', 'web.telegram.org'], target: { kind: 'client', id: 'c1' } },
  { id: 'r8', type: 'default', values: [], target: { kind: 'group', id: 'g1' } },
];

db.subscriptions = [
  { id: 's1', name: 'FastNode', url: 'https://sub.fastnode.ir/s/8f2c1a7e', lastUpdate: iso(now() - 5400), count: 0, lastError: '' },
];
for (const n of ['FastNode SE', 'FastNode PL']) {
  addClient({ name: n, address: `${n.slice(-2).toLowerCase()}.fastnode.ir`, protocol: 'vless', network: 'ws', tls: 'tls',
    sni: `${n.slice(-2).toLowerCase()}.fastnode.ir`, path: '/ws', subscriptionId: 's1' });
}
db.subscriptions[0].count = 2;

// ---------- subscriptions ----------

export function refreshSubscription(s) {
  s.lastUpdate = iso(now());
  if (/fail|bad|invalid/.test(s.url)) {
    s.lastError = 'GET ' + s.url + ': 403 Forbidden';
    return;
  }
  s.lastError = '';
  const existing = db.clients.filter((c) => c.subscriptionId === s.id);
  if (existing.length < 2) {
    for (let i = existing.length; i < 3; i++) {
      const cc = pick(['SE', 'PL', 'DE', 'GB', 'CA']);
      addClient({ name: `${s.name} ${cc}-${i + 1}`, address: `${cc.toLowerCase()}${i}.${new URL(s.url).hostname}`,
        protocol: 'vless', network: pick(['ws', 'grpc']), tls: 'tls', sni: new URL(s.url).hostname,
        path: '/ws', serviceName: 'grpc', subscriptionId: s.id });
    }
  }
  s.count = db.clients.filter((c) => c.subscriptionId === s.id).length;
}

// ---------- events ----------

const listeners = new Set();
export const onEvent = (fn) => (listeners.add(fn), () => listeners.delete(fn));
const emit = (type, data) => listeners.forEach((fn) => fn(type, data));

// ---------- health checks ----------

function pingClient(c, announce = true) {
  const s = sim.get(c.id);
  const t = iso(now());
  if (!c.enabled) return;
  const prev = c.status.state;
  if (s.broken) {
    c.status = { ...c.status, state: 'down', tcpMs: null, delayMs: null, lastCheck: t,
      lastError: c.status.lastError || `dial tcp ${c.address}:${c.port}: i/o timeout` };
  } else {
    const delay = Math.round(s.lat * rnd(0.8, 1.35));
    c.status = { ...c.status, state: 'up', tcpMs: Math.round(delay * rnd(0.3, 0.45)), delayMs: delay, lastCheck: t, lastSuccess: t };
  }
  if (!announce) return;
  emit('ping', { id: c.id, tcpMs: c.status.tcpMs, delayMs: c.status.delayMs, state: c.status.state });
  if (prev !== c.status.state) emit('status', { id: c.id, state: c.status.state, lastError: c.status.lastError });
}

export function checkNow(c) {
  setTimeout(() => pingClient(c), 400);
}

export function setEnabled(c, enabled) {
  c.enabled = enabled;
  if (!enabled) {
    c.status = { ...c.status, state: 'disabled', tcpMs: null, delayMs: null };
    c.traffic = { ...c.traffic, upRate: 0, downRate: 0, conns: 0 };
    emit('status', { id: c.id, state: 'disabled', lastError: c.status.lastError });
  } else {
    c.status = { ...c.status, state: 'unknown' };
    emit('status', { id: c.id, state: 'unknown', lastError: c.status.lastError });
    setTimeout(() => pingClient(c), 1200);
  }
  updateGroups();
}

const isUp = (id) => db.clients.find((c) => c.id === id)?.status.state === 'up';

function updateGroups() {
  for (const g of db.groups) {
    const up = g.members.filter(isUp);
    let cur = g.current;
    if (!up.length) cur = '';
    else if (g.strategy === 'least-ping') {
      const d = (id) => db.clients.find((c) => c.id === id).status.delayMs ?? 1e9;
      cur = up.reduce((a, b) => (d(b) < d(a) * 0.9 ? b : a), up.includes(cur) ? cur : up[0]);
    } else if (g.strategy === 'round-robin') {
      cur = up[(up.indexOf(cur) + 1) % up.length];
    } else if (!up.includes(cur) || g.strategy === 'failover') {
      cur = up[0];
    }
    if (cur !== g.current) {
      g.current = cur;
      emit('group', { id: g.id, current: cur });
    }
  }
}

// ---------- rule matching for fake connections ----------

const ip2n = (ip) => ip.split('.').reduce((a, o) => a * 256 + Number(o), 0);
function inCidr(ip, v) {
  const [net, bits = '32'] = v.split('/');
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(net) || !/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return false;
  const mask = Number(bits) === 0 ? 0 : 2 ** 32 - 2 ** (32 - Number(bits));
  return (ip2n(ip) & mask) >>> 0 === (ip2n(net) & mask) >>> 0;
}
const domainMatch = (d, v) => !!d && (d === v || d.endsWith('.' + v.replace(/^\./, '')));

function matchRule(conn) {
  const [ip, port] = conn.dst.split(':');
  for (let i = 0; i < db.rules.length; i++) {
    const r = db.rules[i];
    const hit =
      r.type === 'default' ||
      (r.type === 'source' && r.values.some((v) => inCidr(conn.src, v))) ||
      (r.type === 'domain' && r.values.some((v) => domainMatch(conn.domain, v))) ||
      (r.type === 'dest' && r.values.some((v) => (v.startsWith(':') ? v.slice(1) === port : inCidr(ip, v))));
    if (hit) return r;
  }
  return null;
}

const sites = [
  ['www.google.com', '142.250.185.68'], ['rr4---sn-4g5e6nsz.googlevideo.com', '173.194.182.9'],
  ['i.ytimg.com', '142.250.186.150'], ['www.youtube.com', '142.250.181.238'], ['web.telegram.org', '149.154.167.99'],
  ['', '149.154.167.51'], ['', '91.108.56.130'], ['api.instagram.com', '157.240.0.174'],
  ['scontent-fra5-1.cdninstagram.com', '157.240.20.63'], ['www.netflix.com', '54.155.178.5'],
  ['ipv4-c071-fra002-ix.1.oca.nflxvideo.net', '45.57.90.1'], ['github.com', '140.82.121.4'],
  ['objects.githubusercontent.com', '185.199.108.133'], ['chatgpt.com', '104.18.32.47'], ['x.com', '104.244.42.1'],
  ['pbs.twimg.com', '151.101.84.159'], ['discord.com', '162.159.128.233'], ['open.spotify.com', '35.186.224.25'],
  ['www.wikipedia.org', '185.15.59.224'], ['www.digikala.com', '185.147.178.11'], ['www.aparat.com', '185.147.176.7'],
  ['update.googleapis.com', '142.250.74.67'], ['', '8.8.8.8'], ['play.googleapis.com', '172.217.16.138'],
  ['gateway.icloud.com', '17.248.185.68'], ['securepubads.g.doubleclick.net', '142.250.185.66'], ['192.168.88.1', '192.168.88.1'],
];
const lanHosts = [10, 11, 21, 22, 23, 34, 35, 42, 50, 101, 102, 117];

function newConnection(startOffset = 0) {
  for (let tries = 0; tries < 20; tries++) {
    const [domain, ip] = pick(sites);
    const port = domain === '' && ip === '8.8.8.8' ? 853 : domain === '' ? pick([443, 5222]) : 443;
    const conn = {
      id: newId('k'), src: `192.168.88.${pick(lanHosts)}`, dst: `${ip}:${port}`,
      domain: /^\d/.test(domain) ? '' : domain, rule: '', client: '', group: '', up: 0, down: 0,
      start: iso(now() - startOffset),
    };
    // rule, client and group are ids, as in the Go API. Blocked connections
    // (client "") show up only briefly, so only new ones are kept.
    const r = matchRule(conn);
    if (!r || (r.target.kind === 'block' && startOffset > 0)) continue;
    conn.rule = r.id;
    if (r.target.kind === 'block') {
      conn.up = Math.round(rnd(200, 900));
      return conn;
    }
    if (r.target.kind === 'direct') conn.client = 'direct';
    let clientId = r.target.kind === 'client' ? r.target.id : '';
    if (r.target.kind === 'group') {
      const g = db.groups.find((x) => x.id === r.target.id);
      conn.group = g?.id || '';
      clientId = g?.current || '';
    }
    if (r.target.kind === 'client' || r.target.kind === 'group') {
      const c = db.clients.find((x) => x.id === clientId);
      if (!c || c.status.state !== 'up') continue;
      conn.client = c.id;
      conn._cid = c.id;
    }
    conn.up = Math.round(rnd(1e3, 4e5) * (startOffset / 60 + 1));
    conn.down = Math.round(rnd(1e4, 8e6) * (startOffset / 60 + 1));
    return conn;
  }
  return null;
}

db.connections = Array.from({ length: 25 }, () => newConnection(Math.floor(rnd(1, 1800)))).filter(Boolean);

export const publicConnection = ({ _cid, ...c }) => c;

// ---------- stats history ----------

const hist = new Map(); // target -> {t, up, down, delay} last 60 s
function record(target, t, up, down, delay) {
  let h = hist.get(target);
  if (!h) hist.set(target, (h = { t: [], up: [], down: [], delay: [] }));
  h.t.push(t); h.up.push(up); h.down.push(down); h.delay.push(delay);
  if (h.t.length > 60) for (const k of ['t', 'up', 'down', 'delay']) h[k].shift();
}

function baseFor(target) {
  if (target === 'total') {
    let up = 0, down = 0;
    for (const c of db.clients) if (c.enabled && !sim.get(c.id).broken) { up += sim.get(c.id).up; down += sim.get(c.id).down; }
    return { up, down, lat: null, broken: false };
  }
  const [kind, id] = target.split(':');
  if (kind === 'client') return sim.get(id) || { up: 0, down: 0, lat: null, broken: true };
  const g = db.groups.find((x) => x.id === id);
  const s = g && sim.get(g.current);
  return s ? { ...s } : { up: 0, down: 0, lat: null, broken: true };
}

// Deterministic-ish pseudo noise so repeated requests do not jump around.
const noise = (n) => {
  const x = Math.sin(n * 12.9898) * 43758.5453;
  return x - Math.floor(x);
};

export function stats(target, range) {
  if (range === '1m') {
    const h = hist.get(target) || { t: [], up: [], down: [], delay: [] };
    const t0 = now() - 59;
    const pad = 60 - h.t.length;
    const fill = (arr, v) => [...Array(pad).fill(v), ...arr];
    return { t: [...Array.from({ length: pad }, (_, i) => t0 + i), ...h.t], up: fill(h.up, 0), down: fill(h.down, 0), delay: fill(h.delay, null) };
  }
  const n = range === '24h' ? 1440 : 60;
  const b = baseFor(target);
  const end = Math.floor(now() / 60) * 60;
  const out = { t: [], up: [], down: [], delay: [] };
  const seed = [...target].reduce((a, ch) => a + ch.charCodeAt(0), 0);
  for (let i = 0; i < n; i++) {
    const t = end - (n - 1 - i) * 60;
    const m = t / 60;
    const hour = new Date(t * 1000).getHours() + new Date(t * 1000).getMinutes() / 60;
    const diurnal = 0.35 + 0.65 * Math.max(0, Math.sin(((hour - 7) / 24) * 2 * Math.PI)) ** 1.5 + (hour > 19 ? 0.4 : 0);
    const k = diurnal * (0.6 + 0.8 * noise(m + seed));
    // A recently broken client stopped carrying traffic about 3h ago.
    const dead = b.broken && t > now() - 3 * 3600 - 412;
    out.t.push(t);
    out.up.push(dead ? 0 : Math.round(b.up * k));
    out.down.push(dead ? 0 : Math.round(b.down * k * (0.8 + 0.4 * noise(m * 3 + seed))));
    out.delay.push(dead || b.lat == null ? null : Math.round(b.lat * (0.85 + 0.5 * noise(m * 7 + seed) ** 3)));
  }
  return out;
}

// ---------- 1 Hz tick ----------

let tick = 0;
setInterval(() => {
  tick++;
  const t = now();
  // Health checks: a couple of clients per second, a flapping client now and then.
  for (const c of db.clients) {
    if (!c.enabled) continue;
    if ((tick + c.id.length + Number(c.id.slice(1))) % 5 === 0) pingClient(c);
  }
  if (tick % 37 === 0) {
    const fr = db.clients.find((c) => c.id === 'c6');
    if (fr?.enabled) {
      const s = sim.get('c6');
      s.broken = !s.broken;
      if (s.broken) fr.status.lastError = 'websocket: bad handshake (HTTP 502)';
      pingClient(fr);
    }
  }
  updateGroups();

  // Connections churn and byte counters.
  db.connections = db.connections.filter((k) => !k._cid || isUp(k._cid));
  if (Math.random() < 0.35 && db.connections.length > 18) db.connections.splice(Math.floor(Math.random() * db.connections.length), 1);
  if (Math.random() < 0.4 && db.connections.length < 32) {
    const k = newConnection(0);
    if (k) db.connections.push(k);
  }
  const conns = new Map();
  for (const k of db.connections) if (k._cid) conns.set(k._cid, (conns.get(k._cid) || 0) + 1);

  const clients = {};
  let tu = 0, td = 0;
  for (const c of db.clients) {
    const s = sim.get(c.id);
    const on = c.status.state === 'up';
    const n = conns.get(c.id) || 0;
    const busy = on ? 0.3 + Math.min(n, 6) / 6 : 0;
    // Smooth random walk around the client's base rate.
    const target = (base) => base * busy * rnd(0.3, 1.7) * (Math.random() < 0.05 ? 3 : 1);
    const upRate = on ? Math.round(c.traffic.upRate * 0.5 + target(s.up) * 0.5) : 0;
    const downRate = on ? Math.round(c.traffic.downRate * 0.5 + target(s.down) * 0.5) : 0;
    c.traffic = { up: c.traffic.up + upRate, down: c.traffic.down + downRate, upRate, downRate, conns: on ? n : 0 };
    tu += upRate; td += downRate;
    clients[c.id] = { upRate, downRate, conns: c.traffic.conns };
    record(`client:${c.id}`, t, upRate, downRate, c.status.delayMs);
    for (const k of db.connections) if (k._cid === c.id && n) { k.up += Math.round(upRate / n); k.down += Math.round(downRate / n); }
  }
  for (const k of db.connections) if (k.client === 'direct') { k.up += Math.round(rnd(0, 3e3)); k.down += Math.round(rnd(0, 6e4)); }
  for (const g of db.groups) {
    const up = g.members.reduce((a, id) => a + (clients[id]?.upRate || 0), 0);
    const down = g.members.reduce((a, id) => a + (clients[id]?.downRate || 0), 0);
    const cn = g.members.reduce((a, id) => a + (clients[id]?.conns || 0), 0);
    g.traffic = { up: g.traffic.up + up, down: g.traffic.down + down, upRate: up, downRate: down, conns: cn };
    const cur = db.clients.find((c) => c.id === g.current);
    record(`group:${g.id}`, t, up, down, cur?.status.delayMs ?? null);
  }
  record('total', t, tu, td, null);
  emit('traffic', { t, total: { upRate: tu, downRate: td }, clients });
}, 1000).unref();

export function removeClientRefs(id) {
  sim.delete(id);
  for (const g of db.groups) {
    g.members = g.members.filter((m) => m !== id);
    if (g.current === id) g.current = '';
  }
  for (const r of db.rules) if (r.target.kind === 'client' && r.target.id === id) r.target = { kind: 'direct', id: '' };
}

export const nowIso = () => iso(now());
