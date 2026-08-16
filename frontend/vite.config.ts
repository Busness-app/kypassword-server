import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5878,
    proxy: {
      "/api": {
        target: "http://localhost:5877",
        changeOrigin: true,
      },
      "/auth": {
        target: "http://localhost:5877",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
