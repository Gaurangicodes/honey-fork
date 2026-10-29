import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 12000,
    // The runtime serves the dev server through a proxied hostname, so the
    // preview origin must be allowed explicitly or Vite answers with 403.
    allowedHosts: [".prod-runtime.all-hands.dev"],
    // The dashboard talks to the FastAPI backend on its own port. Proxying
    // keeps the browser on one origin, so no CORS configuration is needed and
    // the backend never has to be exposed directly.
    proxy: {
      "/api": {
        target: process.env.AGENTCRASH_API ?? "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
});
