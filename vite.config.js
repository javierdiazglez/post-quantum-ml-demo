import { defineConfig } from 'vite';

export default defineConfig({
  root: 'web',
  server: {
    port: 5173,
    open: true
  },
  build: {
    outDir: '../dist-web',
    emptyOutDir: true,
    target: 'esnext'
  }
});
