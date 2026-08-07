import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The fixture bundle. Same plugins, same target and same inlining rule as the
// shipped build, so the bundle under measurement differs from the installed one
// by exactly one module: the Tauri IPC bridge.
export default defineConfig({
  root: fileURLToPath(new URL(".", import.meta.url)),
  base: "./",
  plugins: [react()],
  clearScreen: false,
  resolve: {
    alias: {
      "@tauri-apps/api/core": fileURLToPath(new URL("./tauri-core.ts", import.meta.url)),
    },
  },
  build: {
    target: "es2022",
    sourcemap: false,
    assetsInlineLimit: 0,
    emptyOutDir: true,
    outDir: fileURLToPath(new URL("../../dist-reflow", import.meta.url)),
  },
});
