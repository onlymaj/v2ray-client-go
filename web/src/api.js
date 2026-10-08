// Thin fetch wrapper for /api. Errors carry the server's {error} message.

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

let onUnauthorized = () => {};
/** @param {() => void} fn called when any request (other than login) gets a 401 */
export const setUnauthorizedHandler = (fn) => (onUnauthorized = fn);

/**
 * @param {string} path path below /api, e.g. "/clients"
 * @param {{method?: string, body?: any}} [opts]
 */
export async function api(path, { method = 'GET', body } = {}) {
  const init = { method, credentials: 'same-origin', headers: {} };
  // The server requires this header on every POST/PUT/DELETE, even bodyless
  // ones (a simple CSRF guard: cross-site forms cannot set it).
  if (method !== 'GET') init.headers['Content-Type'] = 'application/json';
  if (body !== undefined) init.body = JSON.stringify(body);
  let res;
  try {
    res = await fetch('/api' + path, init);
  } catch {
    throw new ApiError(0, 'Network error, is the router reachable?');
  }
  if (res.status === 401 && path !== '/login' && path !== '/me') onUnauthorized();
  if (!res.ok) {
    let msg = res.statusText || 'Request failed';
    try {
      msg = (await res.json()).error || msg;
    } catch {}
    throw new ApiError(res.status, msg);
  }
  if (res.status === 204) return null;
  return (res.headers.get('content-type') || '').includes('json') ? res.json() : res.text();
}
