// The Postgres adapters' behaviour tests, the same cases the memory and IndexedDB adapters run, against a
// real database. They need a live Postgres: set DATABASE_URL (CI sets it to the PR's Neon branch, e.g.
// `pr-2-ci`). Without it the suite skips, and says why out loud — never silently (REQ-PG-005).
import { generateKeyPairSync } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import postgres from "postgres";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { Ledger, signEvent } from "../../../ledger/src/index";
import type { EventRow, KeyRecord, Passport } from "../../../ports/src/index";
import { MIGRATION_LOCK_KEY, migrate } from "../src/migrate";
import { PgEventStore, PgEvidenceStore, PgKeyRegistry, PgPassportStore, json } from "../src/index";
import { biProvisionSql, provisionBi } from "../src/provision-bi";

const url = process.env.DATABASE_URL;
if (!url) console.log("postgres adapter tests skipped: set DATABASE_URL to run them against a real database (CI points them at the PR's Neon branch)");

const database = url ? describe : describe.skip;
const sql = url ? postgres(url, { max: 1 }) : (undefined as unknown as postgres.Sql);

const SND = "pty_01JDPC0000000000000000SND1";
const RCV = "pty_01JDPC0000000000000000RCV1";
const TENANT = "pilot-northside";
const ULID = "0123456789ABCDEFGHJKMNPQRS";
const evt = (n: number) => `evt_${ULID.slice(0, 24)}${String(n).padStart(2, "0")}`;
const AST = `ast_${ULID}`;

const event = (n: number, extra: Partial<EventRow> = {}): EventRow => ({
  event_id: evt(n),
  tenant_id: TENANT,
  event_type: "custody_transferred",
  asset_ids: [AST],
  occurred_at: "2026-11-13T08:00:00Z",
  recorded_at: "2026-11-13T08:00:05Z",
  payload: { from_party_id: SND, to_party_id: RCV, mode: "signed" },
  ...extra,
});

const key = (keyId: string, partyId = SND): KeyRecord => ({
  key_id: keyId,
  party_id: partyId,
  alg: "EdDSA",
  mode: "test",
  public_key: "MCowBQYDK2VwAyEAGb9FAWthY8l70jSJQNJ0b2R4qMYgHP0n9k6CJL9PTmU=",
  valid_from: "2026-11-13T00:00:00.000Z",
});

const passport = (assetId: string, tenantId = TENANT): Passport => ({
  "@context": ["https://loopledger.org/schema/v0.1/context.jsonld"],
  "@type": "Passport",
  asset_id: assetId,
  passport_id: "LL-NORTHSIDE-000001",
  tenant_id: tenantId,
  kind: "unit",
  revision: { basis: "unknown" },
  owner: { party_id: SND, record_access: "full" },
  origin: { site_id: "site-northside-01", source_event: "evt_01JDPC0000000000000000B0RN" },
});

beforeAll(async () => {
  if (!url) return;
  await migrate(sql);
});

// The log only grows; a fresh table per test keeps the cases independent. `party` is migration-seeded
// and never truncated. TRUNCATE is a maintenance privilege the owner has; the application role does not.
beforeEach(async () => {
  if (!url) return;
  await sql`truncate event, signature, evidence, key, passport restart identity cascade`;
});

afterAll(async () => {
  if (!url) return;
  await sql.end();
});

database("REQ-PG-001 the Postgres stores implement the ledger's ports", () => {
  it("appends events and reads them back in append order, with their signatures", async () => {
    const events = new PgEventStore(sql, "pilot");
    expect(events.mode).toBe("pilot");
    const [first, second] = [event(2), event(1)];
    await events.append(first);
    await events.append(second);
    await events.appendSignature(first.event_id, { ...keyRow(1), sig_id: "sig_01JDPC0000000000000000SGN1" });
    expect((await events.readAll()).map((e) => e.event_id)).toEqual([first.event_id, second.event_id]);
    expect(await events.read(first.event_id)).toEqual(first);
    expect(await events.read("evt_00000000000000000000000000")).toBeUndefined();
    expect(await events.signatures(first.event_id)).toHaveLength(1);
    expect(await events.signatures(second.event_id)).toEqual([]);
  });

  it("refuses a second append of an event_id and a repeat or unknown-event signature", async () => {
    const events = new PgEventStore(sql, "pilot");
    const e = event(1);
    await events.append(e);
    await expect(events.append(e)).rejects.toThrow("is already in the log");
    await expect(events.appendSignature("evt_00000000000000000000000000", keyRow(1))).rejects.toThrow("is not in the log");
    await events.appendSignature(e.event_id, keyRow(1));
    await expect(events.appendSignature(e.event_id, keyRow(1))).rejects.toThrow("is already stored");
  });

  it("stores evidence by hash, dedupes it, and reads the bytes back", async () => {
    const evidence = new PgEvidenceStore(sql, "pilot");
    expect(evidence.mode).toBe("pilot");
    const bytes = new TextEncoder().encode("scale ticket");
    const hash = await evidence.put(bytes);
    expect(hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(await evidence.put(bytes)).toBe(hash);
    expect(Uint8Array.from((await evidence.get(hash)) as Uint8Array)).toEqual(bytes);
    expect(await evidence.get("sha256:" + "0".repeat(64))).toBeUndefined();
  });

  it("registers keys, resolves copies, and refuses a repeat key_id", async () => {
    const registry = new PgKeyRegistry(sql);
    await registry.register(key("did:key:z6MkPgSender"));
    const got = await registry.resolve("did:key:z6MkPgSender");
    expect(got?.alg).toBe("EdDSA");
    if (got) got.party_id = "tampered";
    expect((await registry.resolve("did:key:z6MkPgSender"))?.party_id).toBe(SND);
    await expect(registry.register(key("did:key:z6MkPgSender"))).rejects.toThrow("already registered");
    await registry.register({ ...key("did:key:z6MkPgReceiver"), party_id: RCV });
    expect((await registry.resolve("did:key:z6MkPgReceiver"))?.party_id).toBe(RCV);
    expect(await registry.resolve("did:key:z6MkPgNope")).toBeUndefined();
  });

  it("stores a passport, refuses a second one for an asset, and lists by tenant in stored order", async () => {
    const passports = new PgPassportStore(sql, "pilot");
    expect(passports.mode).toBe("pilot");
    await passports.put(passport(`${AST}1`, "tenant-1"));
    await passports.put(passport(`${AST}2`, "tenant-2"));
    await passports.put(passport(`${AST}3`, "tenant-1"));
    const got = await passports.get(`${AST}1`);
    expect(got?.passport_id).toBe("LL-NORTHSIDE-000001");
    if (got) got.tenant_id = "tampered";
    expect((await passports.get(`${AST}1`))?.tenant_id).toBe("tenant-1");
    await expect(passports.put(passport(`${AST}1`))).rejects.toThrow("already has a passport");
    expect((await passports.list("tenant-1")).map((p) => p.asset_id)).toEqual([`${AST}1`, `${AST}3`]);
    expect(await passports.list("tenant-3")).toEqual([]);
    expect(await passports.get("ast_00000000000000000000000000")).toBeUndefined();
  });
});

database("REQ-PG-002 the migrations are files applied once by pnpm db:migrate", () => {
  it("records each applied file and applies nothing on a second run", async () => {
    const applied = await migrate(sql);
    expect(applied).toEqual([]);
    const rows = await sql`select id from schema_migration order by id`;
    expect(rows.map((r) => r.id)).toContain("0001_init.sql");
  });

  it("waits while another runner holds the migration lock", async () => {
    const other = postgres(url as string, { max: 1 });
    let settled = false;
    let run: Promise<string[]> | undefined;
    await other.begin(async (tx) => {
      await tx`select pg_advisory_xact_lock(${MIGRATION_LOCK_KEY})`;
      run = migrate(sql).finally(() => {
        settled = true;
      });
      await new Promise((resolve) => setTimeout(resolve, 500));
      expect(settled).toBe(false);
    });
    expect(await run).toEqual([]);
    await other.end();
  });
});

database("REQ-PG-003 the migration seeds the two locked pilot parties", () => {
  it("seeds Northside Fit-out and Lakeside Recovery under the pilot tenant", async () => {
    const rows = await sql`select party_id, tenant_id, name from party order by seq`;
    expect(rows).toEqual([
      { party_id: SND, tenant_id: TENANT, name: "Northside Fit-out" },
      { party_id: RCV, tenant_id: TENANT, name: "Lakeside Recovery" },
    ]);
  });
});

database("REQ-PG-004 the application role has no UPDATE or DELETE grant (SPEC-data-model §5)", () => {
  it("denies update and delete on every table, in the catalog and in fact", async () => {
    const tables = ["event", "signature", "evidence", "key", "passport", "party"];
    for (const table of tables) {
      expect(await privilege(table, "UPDATE")).toBe(false);
      expect(await privilege(table, "DELETE")).toBe(false);
      expect(await privilege(table, "TRUNCATE")).toBe(false);
      expect(await privilege(table, "INSERT")).toBe(true);
      expect(await privilege(table, "SELECT")).toBe(true);
    }
  });

  it("refuses an UPDATE and a DELETE executed as the application role, and allows an append", async () => {
    const events = new PgEventStore(sql, "pilot");
    await events.append(event(1));
    // A dedicated one-connection DIRECT client (not Neon's pooler: transaction-mode pooling would let
    // `set role` leak onto other clients' sessions) so the session reliably runs as loopledger_app.
    const app = postgres((url as string).replace("-pooler", ""), { max: 1 });
    try {
      await app.unsafe("set role loopledger_app");
      await app`insert into event (event_id, tenant_id, event_type, row)
             values (${event(2).event_id}, ${TENANT}, ${"custody_transferred"}, ${json(app, event(2))})`;
      await expect(app`update event set event_type = 'weighed'`).rejects.toThrow(/permission denied/);
      await expect(app`delete from event`).rejects.toThrow(/permission denied/);
    } finally {
      await app.end();
    }
    // The app role's own append went through; the owner's append of event 1 is untouched.
    expect((await events.readAll()).map((e) => e.event_id)).toEqual([event(1).event_id, event(2).event_id]);
  });
});

database("REQ-PG-005 the behaviour tests run against a real Neon branch, or skip with a printed reason", () => {
  it("drives a two-party custody handoff through the real ledger over the Postgres stores", async () => {
    const events = new PgEventStore(sql, "pilot");
    const evidence = new PgEvidenceStore(sql, "pilot");
    const registry = new PgKeyRegistry(sql);
    const sender = generateKeyPairSync("ed25519");
    const receiver = generateKeyPairSync("ed25519");
    const spki = (key: typeof sender.publicKey) => key.export({ type: "spki", format: "der" }).toString("base64");
    // The registered public keys are the ones the signatures are made with — the ledger verifies for real.
    await registry.register({ ...key("did:key:z6MkPgSenderKey"), public_key: spki(sender.publicKey) });
    await registry.register({ ...key("did:key:z6MkPgReceiverKey"), party_id: RCV, public_key: spki(receiver.publicKey) });
    const ledger = new Ledger(events, evidence, registry, "pilot");
    const handoff = event(1);
    const signed = signEvent(handoff, sender.privateKey, {
      sig_id: "sig_01JDPC0000000000000000SGN1",
      key_id: "did:key:z6MkPgSenderKey",
      party_id: SND,
      role_at_signing: "sender",
      signed_at: "2026-11-13T08:01:00Z",
    });
    expect(await ledger.append({ ...handoff, signatures: [signed] })).toEqual({ event_id: handoff.event_id, held: true });
    const read = await ledger.read(TENANT, handoff.event_id);
    expect(read.held).toBe(true);
    expect(read.signatures).toHaveLength(1);
    const countersigned = signEvent(handoff, receiver.privateKey, {
      sig_id: "sig_01JDPC0000000000000000SGN2",
      key_id: "did:key:z6MkPgReceiverKey",
      party_id: RCV,
      role_at_signing: "receiver",
      signed_at: "2026-11-13T08:02:00Z",
    });
    expect(await ledger.countersign(handoff.event_id, countersigned)).toEqual({ event_id: handoff.event_id, held: false });
    expect((await ledger.read(TENANT, handoff.event_id)).signatures).toHaveLength(2);
    expect(await ledger.pending(TENANT)).toEqual([]);
  });
});

describe("REQ-PG-006 the BI view is provisioned on staging only, never by a migration", () => {
  it("refuses any environment but staging and does nothing without the gate", async () => {
    expect(() => biProvisionSql("production")).toThrow(/must be one of staging, got "production"/);
    expect(() => biProvisionSql("staging'; drop table event; --")).toThrow(/must be one of staging/);
    expect(biProvisionSql("staging")).toContain("'staging'::text");
    expect(await provisionBi(undefined as unknown as postgres.Sql, {})).toBe(false);
  });

  it("keeps the view and its roles out of every migration file", () => {
    const dir = new URL("../migrations/", import.meta.url);
    for (const f of readdirSync(dir).filter((n) => n.endsWith(".sql"))) {
      expect(readFileSync(new URL(f, dir), "utf8")).not.toMatch(/bi_product_events|loopledger_bi|bi_pseudonym_key/);
    }
  });
});

database("REQ-PG-006 the factory reads daily-countable events through bi_product_events only", () => {
  const OTHER = "pilot-lakeside";
  beforeAll(async () => {
    expect(await provisionBi(sql, { LOOPLEDGER_PROVISION_BI: "staging" })).toBe(true);
  });
  // A direct (non-pooler) client, as for loopledger_app, so `set role` holds for the session.
  const asBi = async <T>(fn: (bi: postgres.Sql) => Promise<T>): Promise<T> => {
    const bi = postgres((url as string).replace("-pooler", ""), { max: 1 });
    try {
      await bi.unsafe("set role loopledger_bi");
      return await fn(bi);
    } finally {
      await bi.end();
    }
  };

  it("exposes each event with a keyed tenant subject, ledger time and no payload", async () => {
    const events = new PgEventStore(sql, "pilot");
    await events.append(event(1));
    await events.append(event(2, { event_type: "weighed", recorded_at: "2026-11-14T09:00:00Z" }));
    await events.append(event(3, { tenant_id: OTHER }));
    const rows = await asBi((bi) => bi`select kind, occurred_at, dedupe_key, subject, test_account, settings_on, env, payload
                                         from bi_product_events order by dedupe_key`);
    expect(rows.map((r) => [r.kind, r.dedupe_key, (r.occurred_at as Date).toISOString()])).toEqual([
      ["custody_transferred", evt(1), "2026-11-13T08:00:05.000Z"],
      ["weighed", evt(2), "2026-11-14T09:00:00.000Z"],
      ["custody_transferred", evt(3), "2026-11-13T08:00:05.000Z"],
    ]);
    for (const r of rows) {
      expect(r.subject).toMatch(/^[0-9a-f]{64}$/);
      expect(r).toMatchObject({ test_account: true, settings_on: [], env: "staging", payload: {} });
    }
    expect(rows[0]!.subject).toBe(rows[1]!.subject);
    expect(rows[0]!.subject).not.toBe(rows[2]!.subject);
    const [plain] = await sql`select encode(sha256(convert_to(${TENANT}, 'UTF8')), 'hex') as h`;
    expect(rows[0]!.subject).not.toBe(plain!.h);

    await provisionBi(sql, { LOOPLEDGER_PROVISION_BI: "staging" });
    const again = await asBi((bi) => bi`select subject from bi_product_events where dedupe_key = ${evt(1)}`);
    expect(again[0]!.subject).toBe(rows[0]!.subject);
  });

  it("gives a row whose recorded_at is not an ISO timestamp no occurred_at, instead of breaking the view", async () => {
    for (const [n, recorded] of [[4, "now"], [5, "2026-13-40T00:00:00Z"], [6, "13 Nov 2026"]] as const) {
      const row = { ...event(n), recorded_at: recorded };
      await sql`insert into event (event_id, tenant_id, event_type, row)
                values (${row.event_id}, ${TENANT}, ${row.event_type}, ${json(sql, row)})`;
    }
    await new PgEventStore(sql, "pilot").append(event(7));
    const rows = await asBi((bi) => bi`select dedupe_key, occurred_at from bi_product_events order by dedupe_key`);
    expect(rows.map((r) => [r.dedupe_key, r.occurred_at === null])).toEqual([
      [evt(4), true], [evt(5), true], [evt(6), true], [evt(7), false],
    ]);
  });

  it("refuses the BI role every table, the key included", async () => {
    for (const table of ["event", "signature", "evidence", "key", "passport", "party", "bi_pseudonym_key"]) {
      await expect(asBi((bi) => bi.unsafe(`select 1 from ${table} limit 1`))).rejects.toThrow(/permission denied/);
    }
    await expect(sql`select 1 from bi_pseudonym_key`.then(() => "owner reads")).resolves.toBe("owner reads");
    expect(await sql`select has_table_privilege('loopledger_app', 'bi_pseudonym_key', 'SELECT') as allowed`)
      .toEqual([{ allowed: false }]);
  }, 30_000);

  it("grants the BI role SELECT on the view and nothing else, and its login only membership", async () => {
    const grants = await sql`select c.relname, a.privilege_type
                               from pg_class c cross join lateral aclexplode(c.relacl) a
                              where a.grantee in ('loopledger_bi'::regrole, 'loopledger_bi_login'::regrole)
                              order by 1, 2`;
    expect(grants.map((g) => [g.relname, g.privilege_type])).toEqual([["bi_product_events", "SELECT"]]);
    const roles = await sql`select rolname, rolcanlogin, rolsuper, rolcreaterole, rolbypassrls,
                                   pg_has_role(rolname, 'loopledger_bi', 'MEMBER') as member
                              from pg_roles where rolname in ('loopledger_bi', 'loopledger_bi_login') order by 1`;
    expect(roles).toEqual([
      { rolname: "loopledger_bi", rolcanlogin: false, rolsuper: false, rolcreaterole: false, rolbypassrls: false, member: true },
      { rolname: "loopledger_bi_login", rolcanlogin: true, rolsuper: false, rolcreaterole: false, rolbypassrls: false, member: true },
    ]);
  });
});

/** The plain signature row the store-level cases append (its JWS is not verified at the store level). */
function keyRow(n: number) {
  return {
    sig_id: `sig_01JDPC0000000000000000SGN${n}`,
    party_id: SND,
    key_id: "did:key:z6MkPgSender",
    alg: "EdDSA",
    signed_hash: "sha256:" + "0".repeat(64),
    signed_at: "2026-11-13T08:01:00Z",
    role_at_signing: "sender",
    signature: "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa1BnU2VuZGVyIn0..c2ln",
  };
}

async function privilege(table: string, action: string): Promise<boolean> {
  const rows = await sql`select has_table_privilege('loopledger_app', ${table}, ${action}) as allowed`;
  return rows[0]!.allowed as boolean;
}
