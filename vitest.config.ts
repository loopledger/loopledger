import { configDefaults, defineConfig } from "vitest/config";

// `terraform init` checks the kit repository out under infra/envs/*/.terraform, test files included.
export default defineConfig({ test: { exclude: [...configDefaults.exclude, "**/.terraform/**"], passWithNoTests: true } });
