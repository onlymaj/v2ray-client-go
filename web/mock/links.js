// Rough vless:// and vmess:// share-link parsing and building for the mock.

export const blankClient = () => ({
  name: '',
  enabled: true,
  protocol: 'vless',
  address: '',
  port: 443,
  uuid: '',
  flow: '',
  security: 'none',
  network: 'tcp',
  tls: 'none',
  sni: '',
  fingerprint: 'chrome',
  alpn: [],
  allowInsecure: false,
  publicKey: '',
  shortId: '',
  spiderX: '',
  path: '',
  host: '',
  serviceName: '',
  multiMode: false,
  authority: '',
});

const b64decode = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');

function parseVless(line) {
  const u = new URL(line);
  if (!u.username || !u.hostname) throw new Error('missing uuid or host');
  const q = u.searchParams;
  const sec = q.get('security') || 'none';
  const network = q.get('type') || 'tcp';
  if (!['tcp', 'ws', 'grpc'].includes(network)) throw new Error(`unsupported transport "${network}"`);
  if (!['none', 'tls', 'reality'].includes(sec)) throw new Error(`unsupported security "${sec}"`);
  return {
    ...blankClient(),
    name: decodeURIComponent(u.hash.slice(1)) || u.hostname,
    protocol: 'vless',
    address: u.hostname.replace(/^\[|\]$/g, ''),
    port: Number(u.port) || 443,
    uuid: decodeURIComponent(u.username),
    flow: q.get('flow') || '',
    security: q.get('encryption') || 'none',
    network,
    tls: sec,
    sni: q.get('sni') || '',
    fingerprint: q.get('fp') || 'chrome',
    alpn: (q.get('alpn') || '').split(',').filter(Boolean),
    allowInsecure: false, // never taken from a link (see API.md)
    publicKey: q.get('pbk') || '',
    shortId: q.get('sid') || '',
    spiderX: q.get('spx') || '',
    path: q.get('path') || '',
    host: q.get('host') || '',
    serviceName: q.get('serviceName') || '',
    multiMode: q.get('mode') === 'multi',
    authority: q.get('authority') || '',
  };
}

function parseVmess(line) {
  let j;
  try {
    j = JSON.parse(b64decode(line.slice('vmess://'.length)));
  } catch {
    throw new Error('invalid base64 JSON');
  }
  if (!j.add || !j.id) throw new Error('missing add or id');
  const network = j.net || 'tcp';
  if (!['tcp', 'ws', 'grpc'].includes(network)) throw new Error(`unsupported transport "${network}"`);
  return {
    ...blankClient(),
    name: j.ps || j.add,
    protocol: 'vmess',
    address: j.add,
    port: Number(j.port) || 443,
    uuid: j.id,
    security: j.scy || 'auto',
    network,
    tls: j.tls === 'tls' ? 'tls' : 'none',
    sni: j.sni || '',
    fingerprint: j.fp || 'chrome',
    alpn: (j.alpn || '').split(',').filter(Boolean),
    path: network === 'ws' ? j.path || '' : '',
    host: j.host || '',
    serviceName: network === 'grpc' ? j.path || '' : '',
  };
}

export function parseLink(line) {
  if (line.startsWith('vless://')) return parseVless(line);
  if (line.startsWith('vmess://')) return parseVmess(line);
  throw new Error('unsupported scheme');
}

/** Splits pasted text into lines, decoding a base64 subscription body if that is what was pasted. */
export function splitLinks(text) {
  let t = text.trim();
  if (t && !t.includes('://') && /^[A-Za-z0-9+/=_\-\s]+$/.test(t)) {
    try {
      const d = b64decode(t.replace(/\s/g, ''));
      if (d.includes('://')) t = d;
    } catch {}
  }
  return t.split(/\r?\n/).map((s) => s.trim());
}

export function buildLink(c) {
  if (c.protocol === 'vmess') {
    const j = {
      v: '2', ps: c.name, add: c.address, port: String(c.port), id: c.uuid, aid: '0', scy: c.security,
      net: c.network, type: 'none', host: c.host, path: c.network === 'grpc' ? c.serviceName : c.path,
      tls: c.tls === 'tls' ? 'tls' : '', sni: c.sni, alpn: c.alpn.join(','), fp: c.fingerprint,
    };
    return 'vmess://' + Buffer.from(JSON.stringify(j)).toString('base64');
  }
  const q = new URLSearchParams({ encryption: 'none', security: c.tls, type: c.network });
  const set = (k, v) => v && q.set(k, v);
  set('flow', c.flow);
  if (c.tls !== 'none') {
    set('sni', c.sni);
    set('fp', c.fingerprint);
  }
  if (c.tls === 'tls') {
    set('alpn', c.alpn.join(','));
  }
  if (c.tls === 'reality') {
    set('pbk', c.publicKey);
    set('sid', c.shortId);
    set('spx', c.spiderX);
  }
  if (c.network === 'ws') {
    set('path', c.path);
    set('host', c.host);
  }
  if (c.network === 'grpc') {
    set('serviceName', c.serviceName);
    set('authority', c.authority);
    if (c.multiMode) q.set('mode', 'multi');
  }
  const host = c.address.includes(':') ? `[${c.address}]` : c.address;
  return `vless://${c.uuid}@${host}:${c.port}?${q}#${encodeURIComponent(c.name)}`;
}
