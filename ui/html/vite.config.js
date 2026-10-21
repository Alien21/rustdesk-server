import { defineConfig } from 'vite';

export default defineConfig({
    build: {
        outDir: '../../artifacts/ui/dist',
        emptyOutDir: true
    },
    server: {
        port: '5177',
        strictPort: true
    }
});