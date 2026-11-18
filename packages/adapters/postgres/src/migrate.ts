// Applies the adapter's migrations, in file order, each exactly once (REQ-PG-002). Run with
// `pnpm db:migrate` against the branch's DATABASE_URL; the service's CI and Railway deploy run it
// before anything reads or appends. Applied files are recorded in schema_migration, so re-running is
// a no-op.
import { readdirSync, readFileSync } from "node:fs";
import postgres from "postgres";

const migrationsDir = new URL("../migrations/", import.meta.url);

export async function migrate(sql: postgres.Sql): Promise<string[]> {
  await sql`create table if not exists schema_migration (id text primary key, applied_at timestamptz not null default now())`;
  const done = new Set((await sql`select id from schema_migration`).map((r) => r.id as string));
  const files = readdirSync(migrationsDir)
    .filter((f) => f.endsWith(".sql"))
    .sort();
  const applied: string[] = [];
  for (const file of files) {
    if (done.has(file)) continue;
    const statements = readFileSync(new URL(file, migrationsDir), "utf8");
    await sql.begin(async (tx) => {
      await tx.unsafe(statements);
      await tx`insert into schema_migration (id) values (${file})`;
    });
    applied.push(file);
  }
  return applied;
}

if (process.argv[1]?.endsWith("migrate.ts")) {
  const url = process.env.DATABASE_URL;
  if (!url) {
    console.error("db:migrate: DATABASE_URL is not set; refusing to guess a database");
    process.exit(1);
  }
  const sql = postgres(url, { max: 1 });
  const applied = await migrate(sql);
  if (applied.length === 0) console.log("db:migrate: migrations are up to date");
  for (const file of applied) console.log(`db:migrate: applied ${file}`);
  await sql.end();
}
