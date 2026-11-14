import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { VitePWA } from "vite-plugin-pwa";

// The control-plane origin. In dev the proxy below forwards Connect calls to the
// Go server, so the app can stay same-origin. ARES_PROXY_TARGET moves only the
// proxy (scripts/dev.sh sets it); VITE_ARES_URL also makes the browser call the
// server directly, which needs CORS, so it is for split deployments.
const ARES_ORIGIN =
  process.env.ARES_PROXY_TARGET ?? process.env.VITE_ARES_URL ?? "http://127.0.0.1:8080";

export default defineConfig({
  root: ".",
  plugins: [
    react(),
    tailwindcss(),
    VitePWA({
      registerType: "autoUpdate",
      includeAssets: ["icon.svg"],
      manifest: {
        name: "Ares",
        short_name: "Ares",
        description: "Authorized security testing — control plane",
        theme_color: "#f5f7fa",
        background_color: "#f5f7fa",
        display: "standalone",
        start_url: "/",
        icons: [
          { src: "icon.svg", sizes: "any", type: "image/svg+xml", purpose: "any maskable" },
        ],
      },
      workbox: {
        globPatterns: ["**/*.{js,css,html,svg,woff2}"],
        // The control-plane API is never cached: operators must see live state.
        navigateFallbackDenylist: [/^\/ares\.v1\./],
      },
      devOptions: { enabled: false },
    }),
  ],
  server: {
    port: 5173,
    proxy: {
      "/ares.v1.ControlPlane": {
        target: ARES_ORIGIN,
        changeOrigin: true,
      },
    },
  },
  build: {
    target: "es2022",
    sourcemap: true,
  },
});
