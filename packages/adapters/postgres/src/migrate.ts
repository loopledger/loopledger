// Applies the adapter's migrations, in file order, each exactly once (REQ-PG-002). Run with
// `pnpm db:migrate` against the branch's DATABASE_URL; the service's CI and Railway deploy run it
// before anything reads or appends. Applied files are recorded in schema_migration, so re-running is
// a no-op. MIGRATION_DATABASE_URL, when set, is the owner connection it uses instead (staging, where
// DATABASE_URL is the restricted runtime login, REQ-PG-007).
import { readdirSync, readFileSync } from "node:fs";
import postgres from "postgres";
import { PROVISION_BI, provisionBi } from "./provision-bi";
import { RUNTIME_LOGIN, RUNTIME_ROLE, provisionRuntimeRole, runtimeRoleGated } from "./runtime-role";

// The migrations this migrator applies live in this adapter's migrations/ directory, plus the
// service directory conform's feedback_form rule reads: the feedback_submission migration sits under
// apps/server/infra/migrations/ (the apps/server service root, REQ-SERVER-012), applied here with
// everything else (REQ-PG-002). Files are sorted by NAME across all directories — the numbered
// convention orders correctly no matter which directory a file sits in.
const migrationsDirs = [
  new URL("../migrations/", import.meta.url),
  new URL("../../../../apps/server/infra/migrations/", import.meta.url),
];

const migrationFiles = (): { file: string; url: URL }[] => {
  const seen = new Map<string, URL>();
  const files: { file: string; url: URL }[] = [];
  for (const dir of migrationsDirs) {
    for (const file of readdirSync(dir).filter((f) => f.endsWith(".sql"))) {
      const dupe = seen.get(file);
      if (dupe !== undefined) throw new Error(`migration ${file} exists in both ${dupe.pathname} and ${dir.pathname}`);
      seen.set(file, dir);
      files.push({ file, url: new URL(file, dir) });
    }
  }
  files.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
  return files;
};

// Any constant unique to this migrator. Transaction-scoped, so it also holds through a
// transaction-mode pooler; each file re-checks schema_migration under the lock, so concurrent
// runners (replicas, a pre-deploy step plus the container start) apply each file once.
export const MIGRATION_LOCK_KEY = 4_727_001;

export async function migrate(sql: postgres.Sql): Promise<string[]> {
  const files = migrationFiles();
  const applied: string[] = [];
  for (const { file, url } of files) {
    const ran = await sql.begin(async (tx) => {
      await tx`select pg_advisory_xact_lock(${MIGRATION_LOCK_KEY})`;
      await tx`create table if not exists schema_migration (id text primary key, applied_at timestamptz not null default now())`;
      const [done] = await tx`select 1 from schema_migration where id = ${file}`;
      if (done) return false;
      await tx.unsafe(readFileSync(url, "utf8"));
      await tx`insert into schema_migration (id) values (${file})`;
      return true;
    });
    if (ran) applied.push(file);
  }
  return applied;
}

if (process.argv[1]?.endsWith("migrate.ts")) {
  const url = process.env.MIGRATION_DATABASE_URL || process.env.DATABASE_URL;
  if (!url) {
    console.error("db:migrate: DATABASE_URL is not set; refusing to guess a database");
    process.exit(1);
  }
  if (runtimeRoleGated() && !process.env.MIGRATION_DATABASE_URL) {
    console.error(`db:migrate: ${RUNTIME_ROLE} is set but MIGRATION_DATABASE_URL is not; the runtime login is provisioned as the owner`);
    process.exit(1);
  }
  const sql = postgres(url, { max: 1 });
  try {
    const applied = await migrate(sql);
    if (applied.length === 0) console.log("db:migrate: migrations are up to date");
    for (const file of applied) console.log(`db:migrate: applied ${file}`);
    if (await provisionBi(sql)) console.log(`db:migrate: provisioned the BI view for ${process.env[PROVISION_BI]}`);
    if (await provisionRuntimeRole(sql)) console.log(`db:migrate: provisioned ${RUNTIME_LOGIN} for ${process.env[RUNTIME_ROLE]}`);
  } finally {
    await sql.end();
  }
}
