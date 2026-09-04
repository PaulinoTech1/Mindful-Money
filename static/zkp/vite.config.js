import { defineConfig } from 'vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

export default defineConfig({
  plugins: [nodePolyfills({
    globals: { Buffer: true, global: true, process: true },
    protocolImports: true,
  })],
  optimizeDeps: { exclude: ['@aztec/bb.js'] },
  resolve: { alias: { pino: 'pino/browser.js' } },
  build: {
    target: 'es2022',
    // Keep Noir/ACVM WASM as same-origin files. Inlining these modules as
    // data: URLs makes a strict connect-src 'self' CSP reject initialization.
    assetsInlineLimit: 0,
    // Library mode forces small binary assets (including Noir's WASM) into
    // data: URLs. Use a regular Rollup entry so Vite emits the WASM as a
    // same-origin file that the strict CSP can load with connect-src 'self'.
    rollupOptions: {
      input: 'manual_expense_client.js',
      preserveEntrySignatures: 'strict',
      output: {
        format: 'es',
        preserveModules: false,
        // Keep a versioned filename so a live browser cannot hold the old
        // bundle open while this build is being refreshed on Windows.
        entryFileNames: 'manual_expense_prover_v2.js',
        chunkFileNames: 'chunks/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
    outDir: 'dist',
    emptyOutDir: false,
  },
});
