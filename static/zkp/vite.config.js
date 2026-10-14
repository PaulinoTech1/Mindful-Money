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
    lib: {
      entry: {
        manual_expense_prover: 'manual_expense_client.js',
        manual_expense_v4_prover: 'manual_expense_v4_client.js',
      },
      formats: ['es'],
    },
    outDir: 'dist',
    emptyOutDir: true,
  },
});
