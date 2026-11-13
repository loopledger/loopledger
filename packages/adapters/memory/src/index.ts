// In-memory adapters for the ledger ports. They back tests and the drill (LL-001).
import { createHash } from "node:crypto";
import type { EventRow, EventStore, EvidenceStore, KeyRecord, KeyRegistry, KeyResolver, LedgerMode, Passport, PassportStore, SignatureRow } from "@loopledger/ports";

export class MemoryEventStore implements EventStore {
  private readonly events = new Map<string, EventRow>();
  private readonly sigs = new Map<string, SignatureRow[]>();
  private readonly sigIds = new Set<string>();

  constructor(readonly mode: LedgerMode = "evidence") {}

  /** Drops the whole log. Only a pilot store can be discarded, and there is no per-event delete (REQ-LEDGER-010). */
  discard(): void {
    if (this.mode !== "pilot") throw new Error("only a pilot store can be discarded");
    this.events.clear();
    this.sigs.clear();
    this.sigIds.clear();
  }

  async append(event: EventRow): Promise<void> {
    if (this.events.has(event.event_id)) throw new Error(`event ${event.event_id} is already in the log`);
    this.events.set(event.event_id, structuredClone(event));
    this.sigs.set(event.event_id, []);
  }

  async appendSignature(eventId: string, row: SignatureRow): Promise<void> {
    const list = this.sigs.get(eventId);
    if (!list) throw new Error(`event ${eventId} is not in the log`);
    if (this.sigIds.has(row.sig_id)) throw new Error(`signature ${row.sig_id} is already stored`);
    this.sigIds.add(row.sig_id);
    list.push(structuredClone(row));
  }

  async read(eventId: string): Promise<EventRow | undefined> {
    const event = this.events.get(eventId);
    return event && structuredClone(event);
  }

  async readAll(): Promise<EventRow[]> {
    return [...this.events.values()].map((e) => structuredClone(e));
  }

  async signatures(eventId: string): Promise<SignatureRow[]> {
    return structuredClone(this.sigs.get(eventId) ?? []);
  }
}

export class MemoryEvidenceStore implements EvidenceStore {
  private readonly blobs = new Map<string, Uint8Array>();

  constructor(readonly mode: LedgerMode = "evidence") {}

  /** Drops every blob; pilot photos are test data too (REQ-LEDGER-010). */
  discard(): void {
    if (this.mode !== "pilot") throw new Error("only a pilot store can be discarded");
    this.blobs.clear();
  }

  async put(bytes: Uint8Array): Promise<string> {
    const hash = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
    if (!this.blobs.has(hash)) this.blobs.set(hash, Uint8Array.from(bytes));
    return hash;
  }

  async get(hash: string): Promise<Uint8Array | undefined> {
    const bytes = this.blobs.get(hash);
    return bytes && Uint8Array.from(bytes);
  }
}

export class MemoryKeyResolver implements KeyResolver {
  private readonly keys = new Map<string, KeyRecord>();

  register(record: KeyRecord): void {
    if (this.keys.has(record.key_id)) throw new Error(`key ${record.key_id} is already registered`);
    this.keys.set(record.key_id, { ...record });
  }

  async resolve(keyId: string): Promise<KeyRecord | undefined> {
    const record = this.keys.get(keyId);
    return record && { ...record };
  }
}

export class MemoryPassportStore implements PassportStore {
  private readonly passports = new Map<string, Passport>();

  constructor(readonly mode: LedgerMode = "evidence") {}

  /** Drops every passport; pilot passports are test data too (REQ-LEDGER-010). */
  discard(): void {
    if (this.mode !== "pilot") throw new Error("only a pilot store can be discarded");
    this.passports.clear();
  }

  async put(passport: Passport): Promise<void> {
    if (this.passports.has(passport.asset_id)) throw new Error(`asset ${passport.asset_id} already has a passport`);
    this.passports.set(passport.asset_id, structuredClone(passport));
  }

  async get(assetId: string): Promise<Passport | undefined> {
    const passport = this.passports.get(assetId);
    return passport && structuredClone(passport);
  }

  async list(tenantId: string): Promise<Passport[]> {
    return [...this.passports.values()].filter((p) => p.tenant_id === tenantId).map((p) => structuredClone(p));
  }
}

export class MemoryKeyRegistry extends MemoryKeyResolver implements KeyRegistry {
  async register(record: KeyRecord): Promise<void> {
    // The resolver's register already refuses a repeat key_id; the async wrapper is the port's shape.
    super.register(record);
  }
}
