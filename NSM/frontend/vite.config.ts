import path from "node:path"
// vitest/config's defineConfig extends Vite's own with the `test` field
// below (type-only distinction — this is still the identical Vite config
// Vite itself loads; the extra typing is what lets `test` type-check as
// well as `plugins`/`resolve`/`server` already did).
import { defineConfig } from "vitest/config"
import react from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite"

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    strictPort: true,
  },
  // Vitest config lives here rather than a separate vitest.config.ts so it
  // shares the exact same "@" alias resolution as the real app build —
  // two separate configs that could silently drift apart on that alias is
  // exactly the kind of thing that makes a passing test suite lie about
  // what actually resolves in production.
  test: {
    environment: "jsdom",
    // No global test API injection — every test file explicitly imports
    // describe/it/expect/vi from "vitest", matching this app's existing
    // "nothing is ambient, everything is imported" style (no globals
    // anywhere else in src/ either).
    globals: false,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
})
