// Theme preference: data-theme on <html>, remembered in
// localStorage. public/theme.js applies it before first paint.
const KEY = 'v2ray-theme';
const listeners = new Set();

export const getTheme = () => (document.documentElement.dataset.theme === 'light' ? 'light' : 'dark');

export function setTheme(t) {
  document.documentElement.dataset.theme = t;
  try {
    localStorage.setItem(KEY, t);
  } catch {}
  listeners.forEach((fn) => fn(t));
}

/** @param {(t: 'light'|'dark') => void} fn */
export const onTheme = (fn) => (listeners.add(fn), () => listeners.delete(fn));
