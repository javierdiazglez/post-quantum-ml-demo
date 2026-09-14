import { defineConfig } from 'vite';
import { fileURLToPath } from 'url';

const rootDir = fileURLToPath(new URL('.', import.meta.url));

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
