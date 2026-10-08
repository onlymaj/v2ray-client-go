// Single shared EventSource on /api/events plus a 60 s rolling buffer of
// total throughput for the dashboard chart.
import { useEffect, useReducer } from 'preact/hooks';
import { api } from './api.js';

const listeners = new Set();
let es = null;

export const live = {
  connected: false,
  total: { upRate: 0, downRate: 0 },
  /** @type {Record<string, {upRate: number, downRate: number, conns: number}>} */
  clients: {},
  hist: { t: [], up: [], down: [] },
};

const emit = (type, data) => listeners.forEach((fn) => fn(type, data));

export function startLive() {
  if (es) return;
  api('/stats?target=total&range=1m')
    .then((s) => {
      if (live.hist.t.length) return;
      live.hist = { t: s.t, up: s.up, down: s.down };
      emit('traffic', null);
    })
    .catch(() => {});
  es = new EventSource('/api/events');
  es.onopen = () => {
    live.connected = true;
    emit('conn', true);
  };
  es.onerror = () => {
    live.connected = false;
    emit('conn', false);
  };
  es.addEventListener('traffic', (e) => {
    const d = JSON.parse(e.data);
    live.total = d.total;
    live.clients = d.clients;
    const h = live.hist;
    if (h.t.length && h.t[h.t.length - 1] >= d.t) return emit('traffic', d);
    h.t.push(d.t);
    h.up.push(d.total.upRate);
    h.down.push(d.total.downRate);
    while (h.t.length > 60) {
      h.t.shift();
      h.up.shift();
      h.down.shift();
    }
    emit('traffic', d);
  });
  for (const type of ['ping', 'status', 'group']) {
    es.addEventListener(type, (e) => emit(type, JSON.parse(e.data)));
  }
}

export function stopLive() {
  es?.close();
  es = null;
  live.connected = false;
  live.hist = { t: [], up: [], down: [] };
}

/**
 * Subscribes to live events for the lifetime of the component.
 * @param {(type: string, data: any) => void} fn
 */
export function useLiveEvents(fn) {
  useEffect(() => {
    listeners.add(fn);
    return () => listeners.delete(fn);
  }, [fn]);
}

/** Re-renders the component on every event of the given types. */
export function useLiveTick(...types) {
  const [, bump] = useReducer((n) => n + 1, 0);
  useEffect(() => {
    const fn = (type) => types.includes(type) && bump();
    listeners.add(fn);
    bump(); // catch up on events emitted between render and subscribe
    return () => listeners.delete(fn);
  }, []);
}
