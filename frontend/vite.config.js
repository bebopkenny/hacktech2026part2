import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    // proxy API calls to backend in dev so CORS isn't an issue
    proxy: {
      "/scan": "http://localhost:8000",
      "/findings": "http://localhost:8000",
      "/webhook": "http://localhost:8000",
    },
  },
});
