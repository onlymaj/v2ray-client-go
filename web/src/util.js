export const navigate = (path) => (location.hash = '#' + path);

const units = ['B', 'KB', 'MB', 'GB', 'TB'];
export function fmtBytes(n) {
  if (n == null || isNaN(n)) return '-';
  let i = 0;
  while (n >= 1000 && i < units.length - 1) {
    n /= 1000;
    i++;
  }
  return (i && n < 10 ? n.toFixed(1) : Math.round(n)) + ' ' + units[i];
}
export const fmtRate = (n) => fmtBytes(n) + '/s';
export const fmtMs = (n) => (n == null ? '-' : Math.round(n) + ' ms');

export function fmtDuration(sec) {
  sec = Math.max(0, Math.floor(sec));
  if (sec < 60) return sec + 's';
  if (sec < 3600) return Math.floor(sec / 60) + 'm ' + (sec % 60) + 's';
  if (sec < 86400) return Math.floor(sec / 3600) + 'h ' + Math.floor((sec % 3600) / 60) + 'm';
  return Math.floor(sec / 86400) + 'd ' + Math.floor((sec % 86400) / 3600) + 'h';
}
export const since = (iso) => (iso ? (Date.now() - Date.parse(iso)) / 1000 : null);
export const fmtAgo = (iso) => (iso ? fmtDuration(since(iso)) + ' ago' : 'never');

/** RFC 4122 v4 UUID; crypto.randomUUID is missing on plain-http LAN origins. */
export function uuid() {
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Copies text; falls back to execCommand because the Clipboard API needs a secure context. */
export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try {
      ok = document.execCommand('copy');
    } catch {}
    ta.remove();
    return ok;
  }
}

export const cls = (...a) => a.filter(Boolean).join(' ');
