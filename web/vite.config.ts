import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    // In development the Go API runs separately on :8080; in production the
    // Go binary serves the built frontend itself, so no proxy is involved.
    proxy: {
      "/api": "http://localhost:8080",
    },
  },
});
