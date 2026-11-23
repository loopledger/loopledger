import { configDefaults, defineConfig } from "vitest/config";

// `terraform init` checks the kit repository out under infra/envs/*/.terraform, test files included.
// ui/ is the vendored golden-path package (WO-UI-VENDOR-LOOPLEDGER): its own node:test
// suite runs in the ci.yml `ui` job, never under the workspace vitest run.
export default defineConfig({
  test: { exclude: [...configDefaults.exclude, "**/.terraform/**", "ui/**"], passWithNoTests: true },
});
