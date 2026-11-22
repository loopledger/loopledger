// Env-gated staging provisioning for the factory's read view (provision/bi-product-events.sql). The migrator calls it
// after the migrations on every boot. Inert unless LOOPLEDGER_PROVISION_BI names the deployment's environment, and
// that environment may only be staging: the view and its roles never reach a production database.
import { readFileSync } from "node:fs";
import type { Sql } from "postgres";

export const PROVISION_BI = "LOOPLEDGER_PROVISION_BI";
const ALLOWED = new Set(["staging"]);
const file = new URL("../provision/bi-product-events.sql", import.meta.url);

/** The provisioning SQL for one environment label; throws on any label outside the allowed set. */
export function biProvisionSql(env: string): string {
  if (!ALLOWED.has(env)) throw new Error(`${PROVISION_BI} must be one of ${[...ALLOWED].join(", ")}, got "${env}"`);
  return readFileSync(file, "utf8").replaceAll("__ENV__", env);
}

/** Applies the view and roles when the gate is set; returns whether it ran. */
export async function provisionBi(sql: Sql, env: Record<string, string | undefined> = process.env): Promise<boolean> {
  const gate = env[PROVISION_BI];
  if (!gate) return false;
  await sql.unsafe(biProvisionSql(gate));
  return true;
}
