// Postgres adapters for the ledger ports: the hosted pilot's stores (LL-001, issue #78).
// They implement the same contracts as the memory adapters (packages/adapters/memory); the log only
// grows here too — nothing in this file updates or deletes a stored object (REQ-PG-004 enforces it in
// the database, not only in code).
import { createHash } from "node:crypto";
import type { JSONValue, Parameter, Sql } from "postgres";
import type {
  EventRow,
  EventStore,
  EvidenceStore,
  KeyRecord,
  KeyRegistry,
  KeyResolver,
  LedgerMode,
  Passport,
  PassportStore,
  SignatureRow,
} from "@loopledger/ports";

/** Postgres's unique-violation code: a duplicate `event_id`, `sig_id`, `key_id`, `asset_id` or `hash`. */
const isUnique = (e: unknown): boolean =>
  typeof e === "object" && e !== null && "code" in e && (e as { code?: unknown }).code === "23505";

/** The parsed jsonb row of a one-row read, or undefined when nothing matched. jsonb is dynamic on the way out. */
const one = <T>(rows: unknown): T | undefined => (rows as { row?: unknown }[])[0]?.row as T | undefined;

/** The port objects are JSON documents by contract (the schemas define them); postgres.js wants JSONValue. */
export const json = (sql: { json(value: JSONValue): Parameter }, value: unknown) => sql.json(value as JSONValue);

export class PgEventStore implements EventStore {
  constructor(
    private readonly sql: Sql,
    readonly mode: LedgerMode,
  ) {}

  async append(event: EventRow): Promise<void> {
    try {
      await this.sql`insert into event (event_id, tenant_id, event_type, row)
                    values (${event.event_id}, ${event.tenant_id}, ${event.event_type}, ${json(this.sql, event)})`;
    } catch (e) {
      if (isUnique(e)) throw new Error(`event ${event.event_id} is already in the log`);
      throw e;
    }
  }

  async appendSignature(eventId: string, row: SignatureRow): Promise<void> {
    await this.sql.begin(async (tx) => {
      const [event] = await tx`select 1 from event where event_id = ${eventId}`;
      if (!event) throw new Error(`event ${eventId} is not in the log`);
      const stored = await tx`insert into signature (sig_id, event_id, row)
                             values (${row.sig_id}, ${eventId}, ${json(tx, row)})
                             on conflict (sig_id) do nothing returning 1`;
      if (stored.length === 0) throw new Error(`signature ${row.sig_id} is already stored`);
    });
  }

  async read(eventId: string): Promise<EventRow | undefined> {
    const rows = await this.sql`select row from event where event_id = ${eventId}`;
    return one<EventRow>(rows);
  }

  async readAll(): Promise<EventRow[]> {
    const rows = await this.sql`select row from event order by seq`;
    return rows.map((r) => r.row as EventRow);
  }

  async signatures(eventId: string): Promise<SignatureRow[]> {
    const rows = await this.sql`select row from signature where event_id = ${eventId} order by seq`;
    return rows.map((r) => r.row as SignatureRow);
  }
}

export class PgEvidenceStore implements EvidenceStore {
  constructor(
    private readonly sql: Sql,
    readonly mode: LedgerMode,
  ) {}

  async put(bytes: Uint8Array): Promise<string> {
    const hash = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
    await this.sql`insert into evidence (hash, bytes) values (${hash}, ${bytes}) on conflict (hash) do nothing`;
    return hash;
  }

  async get(hash: string): Promise<Uint8Array | undefined> {
    const rows = await this.sql`select bytes from evidence where hash = ${hash}`;
    const bytes = rows[0]?.bytes;
    return bytes === undefined ? undefined : Uint8Array.from(bytes as Uint8Array);
  }
}

export class PgKeyRegistry implements KeyRegistry, KeyResolver {
  constructor(private readonly sql: Sql) {}

  async register(record: KeyRecord): Promise<void> {
    try {
      await this.sql`insert into key (key_id, party_id, record)
                    values (${record.key_id}, ${record.party_id}, ${json(this.sql, record)})`;
    } catch (e) {
      if (isUnique(e)) throw new Error(`key ${record.key_id} is already registered`);
      throw e;
    }
  }

  async resolve(keyId: string): Promise<KeyRecord | undefined> {
    const rows = await this.sql`select record as row from key where key_id = ${keyId}`;
    return one<KeyRecord>(rows);
  }
}

export class PgPassportStore implements PassportStore {
  constructor(
    private readonly sql: Sql,
    readonly mode: LedgerMode,
  ) {}

  async put(passport: Passport): Promise<void> {
    try {
      await this.sql`insert into passport (asset_id, tenant_id, doc)
                    values (${passport.asset_id}, ${passport.tenant_id}, ${json(this.sql, passport)})`;
    } catch (e) {
      if (isUnique(e)) throw new Error(`asset ${passport.asset_id} already has a passport`);
      throw e;
    }
  }

  async get(assetId: string): Promise<Passport | undefined> {
    const rows = await this.sql`select doc as row from passport where asset_id = ${assetId}`;
    return one<Passport>(rows);
  }

  async list(tenantId: string): Promise<Passport[]> {
    const rows = await this.sql`select doc as row from passport where tenant_id = ${tenantId} order by seq`;
    return rows.map((r) => r.row as Passport);
  }
}
