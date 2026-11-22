// The staging runtime login (provision/runtime-role.sql) and the boot gate over the server's DATABASE_URL. Inert unless
// LOOPLEDGER_RUNTIME_ROLE names the deployment's environment, and that environment may only be staging: production never
// gets the role and its server is never gated.
import { readFileSync } from "node:fs";
import type { Sql } from "postgres";

export const RUNTIME_ROLE = "LOOPLEDGER_RUNTIME_ROLE";
export const RUNTIME_LOGIN = "loopledger_app_login";
/** Groups whose members read or write every table; the runtime login is in none. */
export const ELEVATED_GROUPS = ["neon_superuser", "pg_read_all_data", "pg_write_all_data"];
const ALLOWED = new Set(["staging"]);
const file = new URL("../provision/runtime-role.sql", import.meta.url);

/** Whether the gate is set; throws on any label outside the allowed set. */
export function runtimeRoleGated(env: Record<string, string | undefined> = process.env): boolean {
  const gate = env[RUNTIME_ROLE];
  if (!gate) return false;
  if (!ALLOWED.has(gate)) throw new Error(`${RUNTIME_ROLE} must be one of ${[...ALLOWED].join(", ")}, got "${gate}"`);
  return true;
}

export function runtimeRoleSql(): string {
  return readFileSync(file, "utf8");
}

/** Creates or verifies the login and converges its grants when the gate is set, over the owner's connection; returns whether it ran. */
export async function provisionRuntimeRole(owner: Sql, env: Record<string, string | undefined> = process.env): Promise<boolean> {
  if (!runtimeRoleGated(env)) return false;
  await owner.unsafe(runtimeRoleSql());
  return true;
}

/** What the boot gate reads about the connection's role. */
export type RuntimeIdentity = {
  name: string;
  session_name: string;
  rolsuper: boolean;
  rolcreaterole: boolean;
  rolcreatedb: boolean;
  rolbypassrls: boolean;
  rolreplication: boolean;
  owns_database: boolean;
  owns_relation: boolean;
  owns_schema: boolean;
  elevated: string[];
};

/** Why an identity is not the restricted runtime login; empty when it is. */
export function runtimeReasons(who: RuntimeIdentity): string[] {
  return [
    who.name !== RUNTIME_LOGIN && `not ${RUNTIME_LOGIN}`,
    who.session_name !== RUNTIME_LOGIN && `session user ${who.session_name}, not ${RUNTIME_LOGIN}`,
    who.rolsuper && "superuser",
    who.rolcreaterole && "createrole",
    who.rolcreatedb && "createdb",
    who.rolbypassrls && "bypassrls",
    who.rolreplication && "replication",
    who.owns_database && "database owner",
    who.owns_relation && "relation owner",
    who.owns_schema && "schema owner",
    ...who.elevated.map((group) => `member of ${group}`),
  ].filter((reason): reason is string => typeof reason === "string");
}

/** Why the connection is not the restricted runtime login; empty when it is. */
export async function restrictedRuntimeReasons(sql: Sql): Promise<string[]> {
  // ::text and text[]: postgres.js hands a name or name[] back unparsed.
  const [who] = await sql<RuntimeIdentity[]>`
    SELECT current_user::text AS name, session_user::text AS session_name,
           r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolbypassrls, r.rolreplication,
           pg_has_role(current_user, d.datdba, 'MEMBER') AS owns_database,
           EXISTS (SELECT FROM pg_class c WHERE pg_has_role(current_user, c.relowner, 'MEMBER')) AS owns_relation,
           EXISTS (SELECT FROM pg_namespace n WHERE pg_has_role(current_user, n.nspowner, 'MEMBER')) AS owns_schema,
           ARRAY(SELECT g.rolname::text FROM pg_roles g
                  WHERE g.rolname = ANY(${ELEVATED_GROUPS}::text[]) AND pg_has_role(current_user, g.oid, 'MEMBER')
                  ORDER BY 1)::text[] AS elevated
      FROM pg_roles r, pg_database d
     WHERE r.rolname = current_user AND d.datname = current_database()`;
  if (!who) throw new Error("current_user has no pg_roles row");
  return runtimeReasons(who);
}

/** The staging boot gate: throws unless the connection is the restricted runtime login. */
export async function assertRestrictedRuntime(sql: Sql): Promise<void> {
  const reasons = await restrictedRuntimeReasons(sql);
  if (reasons.length > 0) {
    throw new Error(`DATABASE_URL is not the restricted runtime login (${reasons.join(", ")}); refusing to start`);
  }
}
