import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';
import tailwindcss from '@tailwindcss/vite';
import { gzipAssets } from './scripts/gzip-plugin.js';
import { mockApi } from './mock/plugin.js';

// react/react-dom resolve to preact/compat (preset-vite aliases them, and
// package.json maps the packages to @preact/compat) so Radix/shadcn work.
// The mock API is a dev-server-only plugin (apply: 'serve'), so none of it
// reaches the production bundle.
export default defineConfig({
  plugins: [preact(), tailwindcss(), mockApi(), gzipAssets()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: { host: true, port: 5173, strictPort: true },
  build: {
    target: 'es2020',
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    reportCompressedSize: false,
  },
});
