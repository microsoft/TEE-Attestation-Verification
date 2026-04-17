// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { defineConfig } from "@playwright/test";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
// Repo root is three levels up from demos/web-verify-kernel/tests/.
const repoRoot = resolve(here, "..", "..", "..");

export default defineConfig({
  testDir: ".",
  fullyParallel: false,
  reporter: [["list"]],
  // Start a static file server rooted at the repo so the demo's
  // `../../pkg/...` import resolves, and so test fixtures under
  // `tests/test_data/` are reachable via HTTP.
  webServer: {
    command: `python3 -m http.server 8123 --directory "${repoRoot}"`,
    url: "http://127.0.0.1:8123/demos/web-verify-kernel/",
    reuseExistingServer: !process.env.CI,
    stdout: "ignore",
    stderr: "pipe",
  },
  use: {
    baseURL: "http://127.0.0.1:8123",
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
