// Vite dev-server plugin that serves a fake /api backed by mock/state.js.
// apply: 'serve' keeps it (and its imports) out of production builds.
import { randomBytes } from 'node:crypto';
import { buildLink, parseLink, splitLinks, blankClient } from './links.js';

const COOKIE = 'nv2_session';
const PROTOCOLS = ['vless', 'vmess'];
const NETWORKS = ['tcp', 'ws', 'grpc'];
const TLS = ['none', 'tls', 'reality'];
const STRATEGIES = ['failover', 'least-ping', 'round-robin', 'sticky'];
const RULE_TYPES = ['source', 'domain', 'dest', 'default'];
const TARGETS = ['client', 'group', 'direct', 'block'];

class HttpError extends Error {
  constructor(status, msg) {
    super(msg);
    this.status = status;
  }
}
const bad = (msg) => new HttpError(400, msg);

function readBody(req) {
  return new Promise((resolve, reject) => {
    let s = '';
    req.on('data', (d) => (s += d));
    req.on('end', () => {
      if (!s) return resolve({});
      try {
        resolve(JSON.parse(s));
      } catch {
        reject(bad('invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function send(res, status, body) {
  res.statusCode = status;
  if (body === undefined) return res.end();
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(body));
}

const pickClientFields = (b) => {
  const out = {};
  for (const k of Object.keys(blankClient())) if (k in b) out[k] = b[k];
  if ('subscriptionId' in b) out.subscriptionId = b.subscriptionId;
  return out;
};

function validateClient(c) {
  if (!String(c.name || '').trim()) throw bad('name is required');
  if (!String(c.address || '').trim()) throw bad('address is required');
  const port = Number(c.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw bad('port must be 1-65535');
  c.port = port;
  if (!PROTOCOLS.includes(c.protocol)) throw bad('protocol must be vless or vmess');
  if (!NETWORKS.includes(c.network)) throw bad('network must be tcp, ws or grpc');
  if (!TLS.includes(c.tls)) throw bad('tls must be none, tls or reality');
  if (c.tls === 'reality' && c.protocol !== 'vless') throw bad('reality requires vless');
  if (c.tls === 'reality' && !c.publicKey) throw bad('reality requires publicKey');
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(c.uuid || '')) throw bad('uuid is invalid');
  if (!['', 'chrome', 'firefox', 'safari', 'random'].includes(c.fingerprint || '')) throw bad('unknown fingerprint ' + c.fingerprint);
  if (!['', 'xtls-rprx-vision', 'xtls-rprx-vision-udp443'].includes(c.flow || '')) throw bad('unsupported flow ' + c.flow);
  if (!Array.isArray(c.alpn)) c.alpn = String(c.alpn || '').split(',').map((s) => s.trim()).filter(Boolean);
}

function validateGroup(g, db) {
  if (!String(g.name || '').trim()) throw bad('name is required');
  if (!STRATEGIES.includes(g.strategy)) throw bad('invalid strategy');
  if (!Array.isArray(g.members)) throw bad('members must be an array');
  for (const m of g.members) if (!db.clients.some((c) => c.id === m)) throw bad(`unknown client ${m}`);
  g.stickyIncludeDest = !!g.stickyIncludeDest;
}

export function mockApi() {
  return {
    name: 'v2ray-mock-api',
    apply: 'serve',
    async configureServer(server) {
      const S = await import('./state.js');
      const { db } = S;
      const publicSettings = () => {
        const { password, ...ros } = db.settings.routeros;
        return { ...db.settings, routeros: { ...ros, password: '', passwordSet: !!password } };
      };
      const findOr404 = (list, id, what) => {
        const x = list.find((i) => i.id === id);
        if (!x) throw new HttpError(404, `${what} not found`);
        return x;
      };

      /** @type {[string, RegExp, (m: string[], body: any, req: any, res: any) => any][]} */
      const routes = [
        ['GET', /^\/me$/, () => ({ user: 'admin' })],
        ['POST', /^\/logout$/, (_m, _b, req, res) => {
          db.sessions.delete(sessionOf(req));
          res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict`);
          return null;
        }],

        ['GET', /^\/clients$/, () => db.clients],
        ['POST', /^\/clients$/, (_m, b) => {
          const c = { ...blankClient(), ...pickClientFields(b), untrusted: false };
          validateClient(c);
          return [201, S.addClient(c)];
        }],
        ['GET', /^\/clients\/([^/]+)$/, ([, id]) => findOr404(db.clients, id, 'client')],
        ['PUT', /^\/clients\/([^/]+)$/, ([, id], b) => {
          const c = findOr404(db.clients, id, 'client');
          const next = { ...c, ...pickClientFields(b), untrusted: false };
          validateClient(next);
          const enabledChanged = next.enabled !== c.enabled;
          Object.assign(c, next, { id });
          if (enabledChanged) S.setEnabled(c, next.enabled);
          return c;
        }],
        ['DELETE', /^\/clients\/([^/]+)$/, ([, id]) => {
          findOr404(db.clients, id, 'client');
          db.clients = db.clients.filter((c) => c.id !== id);
          S.removeClientRefs(id);
          return null;
        }],
        ['POST', /^\/clients\/([^/]+)\/toggle$/, ([, id]) => {
          const c = findOr404(db.clients, id, 'client');
          S.setEnabled(c, !c.enabled);
          return c;
        }],
        ['POST', /^\/clients\/([^/]+)\/check$/, ([, id]) => {
          S.checkNow(findOr404(db.clients, id, 'client'));
          return [202, { ok: true }];
        }],
        ['GET', /^\/clients\/([^/]+)\/link$/, ([, id]) => ({ link: buildLink(findOr404(db.clients, id, 'client')) })],

        ['GET', /^\/groups$/, () => db.groups],
        ['POST', /^\/groups$/, (_m, b) => {
          const g = { name: b.name, strategy: b.strategy, members: b.members || [], stickyIncludeDest: b.stickyIncludeDest };
          validateGroup(g, db);
          const group = { id: S.newId('g'), ...g, current: g.members[0] || '', traffic: { up: 0, down: 0, upRate: 0, downRate: 0, conns: 0 } };
          db.groups.push(group);
          return [201, group];
        }],
        ['GET', /^\/groups\/([^/]+)$/, ([, id]) => findOr404(db.groups, id, 'group')],
        ['PUT', /^\/groups\/([^/]+)$/, ([, id], b) => {
          const g = findOr404(db.groups, id, 'group');
          const next = { name: b.name, strategy: b.strategy, members: b.members, stickyIncludeDest: b.stickyIncludeDest };
          validateGroup(next, db);
          Object.assign(g, next);
          if (!g.members.includes(g.current)) g.current = g.members[0] || '';
          return g;
        }],
        ['DELETE', /^\/groups\/([^/]+)$/, ([, id]) => {
          findOr404(db.groups, id, 'group');
          if (db.rules.some((r) => r.target.kind === 'group' && r.target.id === id)) throw new HttpError(409, 'group is used by a rule');
          db.groups = db.groups.filter((g) => g.id !== id);
          return null;
        }],

        ['GET', /^\/rules$/, () => db.rules],
        ['PUT', /^\/rules$/, (_m, b) => {
          if (!Array.isArray(b)) throw bad('body must be an array of rules');
          const rules = b.map((r, i) => {
            const n = `rule ${i + 1}`;
            if (!RULE_TYPES.includes(r.type)) throw bad(`${n}: invalid type`);
            const values = (r.values || []).map((v) => String(v).trim()).filter(Boolean);
            if (r.type !== 'default' && !values.length) throw bad(`${n}: needs at least one value`);
            const kind = r.target?.kind;
            if (!TARGETS.includes(kind)) throw bad(`${n}: invalid target`);
            const id = kind === 'client' || kind === 'group' ? r.target.id : '';
            if (kind === 'client') findOr404(db.clients, id, `${n}: client`);
            if (kind === 'group') findOr404(db.groups, id, `${n}: group`);
            return { id: r.id || S.newId('r'), type: r.type, values: r.type === 'default' ? [] : values, target: { kind, id } };
          });
          db.rules = rules;
          return rules;
        }],

        ['POST', /^\/import$/, (_m, b) => {
          const added = [], errors = [];
          let skipped = 0;
          splitLinks(String(b.text || '')).forEach((text, i) => {
            if (!text || text.startsWith('#')) return;
            try {
              const c = { ...parseLink(text), untrusted: true };
              if (db.clients.some((x) => x.address === c.address && x.port === c.port && x.uuid === c.uuid)) {
                skipped++;
                return;
              }
              validateClient(c);
              added.push(S.addClient(c));
            } catch (e) {
              errors.push({ line: i + 1, text: text.length > 80 ? text.slice(0, 77) + '...' : text, error: e.message });
            }
          });
          return { added, errors, skipped };
        }],

        ['GET', /^\/subscriptions$/, () => db.subscriptions],
        ['POST', /^\/subscriptions$/, (_m, b) => {
          let u;
          try {
            u = new URL(b.url);
          } catch {
            throw bad('url is invalid');
          }
          if (!/^https?:$/.test(u.protocol)) throw bad('url must be http or https');
          const s = { id: S.newId('s'), name: String(b.name || '').trim() || u.hostname, url: b.url, lastUpdate: '', count: 0, lastError: '', note: '' };
          db.subscriptions.push(s);
          S.refreshSubscription(s);
          return [201, s];
        }],
        ['DELETE', /^\/subscriptions\/([^/]+)$/, ([, id]) => {
          findOr404(db.subscriptions, id, 'subscription');
          db.subscriptions = db.subscriptions.filter((s) => s.id !== id);
          for (const c of db.clients.filter((x) => x.subscriptionId === id)) S.removeClientRefs(c.id);
          db.clients = db.clients.filter((c) => c.subscriptionId !== id);
          return null;
        }],
        ['POST', /^\/subscriptions\/([^/]+)\/refresh$/, async ([, id]) => {
          const s = findOr404(db.subscriptions, id, 'subscription');
          await new Promise((r) => setTimeout(r, 700));
          S.refreshSubscription(s);
          return s;
        }],

        ['GET', /^\/settings$/, () => publicSettings()],
        ['PUT', /^\/settings$/, (_m, b) => {
          const p = b.ports || {};
          for (const k of ['transparent', 'socks', 'http', 'dns', 'ui']) {
            const v = Number(p[k]);
            const min = k === 'transparent' || k === 'ui' ? 1 : 0; // 0 disables socks/http/dns
            if (!Number.isInteger(v) || v < min || v > 65535) throw bad(`ports.${k} must be ${min}-65535`);
            p[k] = v;
          }
          const usedPorts = Object.values(p).filter((v) => v !== 0);
          if (new Set(usedPorts).size !== usedPorts.length) throw bad('ports must differ');
          const iv = Number(b.healthInterval);
          if (!Number.isInteger(iv) || iv < 5 || iv > 3600) throw bad('healthInterval must be 5-3600 seconds');
          if (!['block', 'direct'].includes(b.killSwitch)) throw bad('killSwitch must be block or direct');
          if (b.healthUrl) { // "" selects the default
            let u;
            try {
              u = new URL(b.healthUrl);
            } catch {
              throw bad('healthUrl must be an http or https URL');
            }
            if (!['http:', 'https:'].includes(u.protocol)) throw bad('healthUrl must be an http or https URL');
          }
          const m = String(b.dnsUpstream || '').match(/^(\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]):(\d{1,5})$/);
          if (!m || Number(m[2]) < 1 || Number(m[2]) > 65535) throw bad('dnsUpstream must be ip:port');
          const r = b.routeros || {};
          if (r.certSha256 && !/^[0-9a-fA-F]{64}$/.test(String(r.certSha256).replace(/:/g, ''))) throw bad('routeros.certSha256 must be 64 hex characters');
          const prev = db.settings.routeros;
          db.settings = {
            ports: p, healthUrl: b.healthUrl, healthInterval: iv, killSwitch: b.killSwitch, dnsUpstream: b.dnsUpstream,
            allowPrivateServers: !!b.allowPrivateServers,
            routeros: { enabled: !!r.enabled, url: r.url || '', user: r.user || '', addressList: r.addressList || '',
              certSha256: r.certSha256 || '', password: r.password ? r.password : prev.password },
          };
          return publicSettings();
        }],

        ['GET', /^\/stats$/, (_m, _b, req) => {
          const q = new URL(req.url, 'http://x').searchParams;
          const target = q.get('target') || 'total';
          const range = q.get('range') || '1h';
          if (!['1m', '1h', '24h'].includes(range)) throw bad('range must be 1m, 1h or 24h');
          if (target !== 'total' && !/^(client|group):.+$/.test(target)) throw bad('invalid target');
          return S.stats(target, range);
        }],
        ['GET', /^\/connections$/, () => db.connections.map(S.publicConnection)],
      ];

      const sessionOf = (req) => (req.headers.cookie || '').match(new RegExp(`${COOKIE}=([^;]+)`))?.[1];

      server.middlewares.use('/api', async (req, res) => {
        const path = req.url.split('?')[0];
        try {
          if (req.method === 'POST' && path === '/login') {
            const b = await readBody(req);
            await new Promise((r) => setTimeout(r, 250));
            if (b.password !== 'admin') throw new HttpError(401, 'wrong password');
            const sid = randomBytes(16).toString('hex');
            db.sessions.add(sid);
            res.setHeader('Set-Cookie', `${COOKIE}=${sid}; Path=/; HttpOnly; SameSite=Strict`);
            return send(res, 204);
          }
          if (!db.sessions.has(sessionOf(req))) throw new HttpError(401, 'unauthorized');
          // Same CSRF guard as the Go server: writes must declare a JSON body, even empty ones.
          if (req.method !== 'GET' && !String(req.headers['content-type'] || '').startsWith('application/json')) {
            throw new HttpError(415, 'Content-Type must be application/json');
          }

          if (req.method === 'GET' && path === '/events') return events(req, res);

          for (const [method, re, fn] of routes) {
            const m = path.match(re);
            if (!m) continue;
            if (method !== req.method) continue;
            const body = ['POST', 'PUT'].includes(req.method) ? await readBody(req) : undefined;
            await new Promise((r) => setTimeout(r, 60 + Math.random() * 120)); // feel like a network
            const out = await fn(m, body, req, res);
            if (Array.isArray(out) && typeof out[0] === 'number' && out.length === 2) return send(res, out[0], out[1]);
            return out === null ? send(res, 204) : send(res, 200, out);
          }
          throw new HttpError(routes.some(([, re]) => re.test(path)) ? 405 : 404, 'not found');
        } catch (e) {
          if (!(e instanceof HttpError)) console.error('[mock]', e);
          send(res, e.status || 500, { error: e.message });
        }
      });

      function events(req, res) {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          Connection: 'keep-alive',
        });
        res.write('retry: 3000\n\n');
        const off = S.onEvent((type, data) => res.write(`event: ${type}\ndata: ${JSON.stringify(data)}\n\n`));
        req.on('close', off);
      }
    },
  };
}
