// Single-file, SRI-pinnable browser bundle of the v4 prover.
// Output: static/zkp/build/mm-zkp-v4.js (committed; CI rebuilds and diffs).
import { defineConfig } from 'vite';
import { readFileSync } from 'node:fs';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

const BYTES_SUFFIX = '?mmbytes';

/** `import x from './f?mmbytes'` -> Uint8Array of the file, inlined as base64. */
function inlineBytes() {
  return {
    name: 'mm-inline-bytes',
    enforce: 'pre',
    async resolveId(source, importer) {
      if (!source.endsWith(BYTES_SUFFIX)) return null;
      const r = await this.resolve(source.slice(0, -BYTES_SUFFIX.length), importer, { skipSelf: true });
      return r && `\0mmbytes:${r.id}`;
    },
    load(id) {
      if (!id.startsWith('\0mmbytes:')) return null;
      const b64 = readFileSync(id.slice('\0mmbytes:'.length)).toString('base64');
      return `const s = atob(${JSON.stringify(b64)}); const u = new Uint8Array(s.length);\n`
        + 'for (let i = 0; i < s.length; i += 1) u[i] = s.charCodeAt(i);\nexport default u;\n';
    },
  };
}

/** bb.js fetch()es its inlined data: URL wasm; CSP connect-src refuses data:. Decode in page. */
function bbNoDataFetch() {
  return {
    name: 'mm-bb-no-data-fetch',
    transform(code, id) {
      const path = id.replace(/\\/g, '/');
      if (path.endsWith('/dest/browser/barretenberg_wasm/helpers/browser/index.js')) {
        // Single-threaded, non-shared wasm even when the page is cross-origin
        // isolated (COOP/COEP make SharedArrayBuffer available): no thread
        // workers, and the non-threads wasm is the only one bundled.
        const probe = "return typeof SharedArrayBuffer !== 'undefined' && globalScope.crossOriginIsolated;";
        if (!code.includes(probe)) throw new Error('bb.js getSharedMemoryAvailable changed; update mm-bb-no-data-fetch');
        return code.replace(probe, 'return false;');
      }
      if (!path.includes('/barretenberg_wasm/fetch_code/browser/index.js')) return null;
      const needle = 'const res = await fetch(url);';
      if (!code.includes(needle)) throw new Error('bb.js fetch_code changed; update mm-bb-no-data-fetch');
      const threads = "(await import('./barretenberg-threads.js')).default";
      if (!code.includes(threads)) throw new Error('bb.js fetch_code changed; update mm-bb-no-data-fetch');
      return code.replace(threads, "(() => { throw new Error('threaded bb wasm is not bundled'); })()").replace(needle, "const res = url.startsWith('data:') ? new Response(Uint8Array.from(atob(url.slice(url.indexOf(',') + 1)), (c) => c.charCodeAt(0))) : await fetch(url);");
    },
  };
}

export default defineConfig({
  plugins: [inlineBytes(), bbNoDataFetch(), nodePolyfills({
    globals: { Buffer: true, global: true, process: true },
    protocolImports: true,
  })],
  optimizeDeps: { exclude: ['@aztec/bb.js'] },
  resolve: { alias: { pino: 'pino/browser.js' } },
  build: {
    target: 'es2022',
    lib: { entry: 'manual_expense_v4_browser.js', formats: ['es'], fileName: () => 'mm-zkp-v4.js' },
    rollupOptions: { output: { inlineDynamicImports: true } },
    assetsInlineLimit: Number.MAX_SAFE_INTEGER,
    outDir: 'build',
    emptyOutDir: true,
    minify: true,
    sourcemap: false,
  },
});
