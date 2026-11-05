// The ledger: an append-only event log with two-party signatures and evidence stored by hash (issue #7).
// Events are never updated. A countersignature is a new signature row, and `held` is derived from the rows.
import { EVENT_TYPES, requiredSigners } from "@loopledger/spec";
import type { EventType } from "@loopledger/spec";
import type { EventRow, EventStore, EvidenceStore, KeyResolver, SignatureRow } from "@loopledger/ports";
import { VERIFIERS, eventHash, eventRow, sha256, signingInput } from "./crypto";
import type { Verifier } from "./crypto";

export { canonical, eventHash, merkleRoot, sha256, signingInput } from "./crypto";

export type EventInput = EventRow & { signatures?: SignatureRow[] };

export interface Appended {
  event_id: string;
  held: boolean;
}

const EVENT_ID = /^evt_[0-9A-HJKMNP-TV-Z]{26}$/;
const ASSET_ID = /^ast_[0-9A-HJKMNP-TV-Z]{26}$/;
const time = (value: unknown): number => (typeof value === "string" ? Date.parse(value) : NaN);

const refuse = (message: string): never => {
  throw new Error(message);
};

export class Ledger {
  private readonly verifiers: Readonly<Record<string, Verifier>>;

  constructor(
    private readonly events: EventStore,
    private readonly evidence: EvidenceStore,
    private readonly keys: KeyResolver,
    verifiers: Readonly<Record<string, Verifier>> = VERIFIERS,
  ) {
    this.verifiers = verifiers;
  }

  /**
   * Appends the event with the signatures it arrives with. With too few signatures it is stored held (absent from
   * `projection`, listed by `pending`) until `countersign` completes it.
   */
  async append(input: EventInput): Promise<Appended> {
    const event = eventRow(input);
    this.envelope(event);
    if (await this.events.read(event.event_id)) refuse(`event ${event.event_id} is already in the log`);
    if (event.correction_of !== undefined) {
      const target = await this.events.read(event.correction_of);
      if (!target) refuse(`correction_of ${event.correction_of} is not in the log`);
      else if (target.tenant_id !== event.tenant_id) refuse("correction_of names an event of another tenant");
    }
    for (const ref of event.evidence ?? []) await this.readEvidence(ref.content_hash);

    const signatures = input.signatures ?? [];
    const accepted: SignatureRow[] = [];
    for (const row of signatures) {
      await this.check(event, accepted, row);
      accepted.push(row);
    }
    await this.events.append(event);
    for (const row of accepted) await this.events.appendSignature(event.event_id, row);
    return { event_id: event.event_id, held: !this.complete(event, accepted) };
  }

  /** Adds a signature to a held event. The event row is not touched. */
  async countersign(eventId: string, row: SignatureRow): Promise<Appended> {
    const event = await this.events.read(eventId);
    if (!event) return refuse(`event ${eventId} is not in the log`);
    const existing = await this.events.signatures(eventId);
    if (this.complete(event, existing)) return refuse(`event ${eventId} is not held`);
    await this.check(event, existing, row);
    await this.events.appendSignature(eventId, row);
    return { event_id: eventId, held: !this.complete(event, [...existing, row]) };
  }

  /** `tenant_id` is checked here, on read only; access control is a later issue. */
  async read(tenantId: string, eventId: string): Promise<EventRow & { held: boolean; signatures: SignatureRow[] }> {
    const event = await this.events.read(eventId);
    if (!event) return refuse(`event ${eventId} is not in the log`);
    if (event.tenant_id !== tenantId) return refuse(`event ${eventId} belongs to another tenant`);
    const signatures = await this.events.signatures(eventId);
    return { ...event, signatures, held: !this.complete(event, signatures) };
  }

  /** The tenant's final events. Held events are left out, and so is an event a final correction supersedes. */
  async projection(tenantId: string): Promise<EventRow[]> {
    const final = await this.tenantEvents(tenantId, false);
    const superseded = new Set(final.flatMap((e) => (e.correction_of === undefined ? [] : [e.correction_of])));
    return final.filter((e) => !superseded.has(e.event_id));
  }

  /** The tenant's held events, awaiting a countersignature. */
  pending(tenantId: string): Promise<EventRow[]> {
    return this.tenantEvents(tenantId, true);
  }

  /** The whole log in order, held events included: the input to `merkleRoot`. */
  log(): Promise<EventRow[]> {
    return this.events.readAll();
  }

  putEvidence(bytes: Uint8Array): Promise<string> {
    return this.evidence.put(bytes);
  }

  /** Returns the stored bytes after recomputing their hash; throws when it differs from the hash asked for. */
  async readEvidence(hash: string): Promise<Uint8Array> {
    const bytes = await this.evidence.get(hash);
    if (!bytes) return refuse(`evidence ${hash} is not stored`);
    if (sha256(bytes) !== hash) return refuse(`evidence ${hash} does not match its hash`);
    return bytes;
  }

  private async tenantEvents(tenantId: string, held: boolean): Promise<EventRow[]> {
    const out: EventRow[] = [];
    for (const event of await this.events.readAll()) {
      if (event.tenant_id !== tenantId) continue;
      if (!this.complete(event, await this.events.signatures(event.event_id)) === held) out.push(event);
    }
    return out;
  }

  private envelope(event: EventRow): void {
    if (typeof event.event_id !== "string" || !EVENT_ID.test(event.event_id)) refuse("event_id is not an evt_ ULID");
    if (typeof event.tenant_id !== "string" || event.tenant_id === "") refuse("tenant_id is required");
    if (!(EVENT_TYPES as readonly string[]).includes(event.event_type)) refuse(`unknown event type ${String(event.event_type)}`);
    if (!Array.isArray(event.asset_ids) || event.asset_ids.length === 0 || !event.asset_ids.every((a) => typeof a === "string" && ASSET_ID.test(a))) {
      refuse("asset_ids needs at least one ast_ ULID");
    }
    if (Number.isNaN(time(event.occurred_at))) refuse("occurred_at is not a timestamp");
    if (Number.isNaN(time(event.recorded_at))) refuse("recorded_at is not a timestamp");
    if (event.payload === null || typeof event.payload !== "object" || Array.isArray(event.payload)) refuse("payload must be an object");
    if (event.correction_of !== undefined && !EVENT_ID.test(String(event.correction_of))) refuse("correction_of is not an evt_ ULID");
  }

  /** Refuses a signature that does not bind to this event, its key's party and its own fields, or repeats a party. */
  private async check(event: EventRow, existing: readonly SignatureRow[], row: SignatureRow): Promise<void> {
    if (existing.some((s) => s.party_id === row.party_id)) refuse(`party ${row.party_id} already signed event ${event.event_id}`);
    if (existing.some((s) => s.sig_id === row.sig_id)) refuse(`signature ${row.sig_id} is already on event ${event.event_id}`);
    if (row.signed_hash !== eventHash(event)) refuse("signed_hash does not match the event");
    const verifier = Object.hasOwn(this.verifiers, row.alg) ? this.verifiers[row.alg] : undefined;
    if (!verifier) refuse(`unknown alg ${String(row.alg)}`);
    const key = await this.keys.resolve(row.key_id);
    if (!key) refuse(`unknown key ${row.key_id}`);
    else {
      if (key.party_id !== row.party_id) refuse(`key ${row.key_id} does not belong to party ${row.party_id}`);
      if (key.alg !== row.alg) refuse(`key ${row.key_id} is not an ${row.alg} key`);
      const at = time(row.signed_at);
      if (Number.isNaN(at) || at < time(key.valid_from) || (key.valid_until !== undefined && at > time(key.valid_until))) {
        refuse(`signed_at is outside the validity window of key ${row.key_id}`);
      }
      let ok = false;
      try {
        ok = verifier!(key.public_key, signingInput(row), row.signature);
      } catch {
        ok = false;
      }
      if (!ok) refuse(`signature ${row.sig_id} does not verify`);
    }
  }

  /** Whether the signatures meet the event type's rule in `packages/spec`. Conditional signers are not enforced (REQ-EVENT-002). */
  private complete(event: EventRow, signatures: readonly SignatureRow[]): boolean {
    const rule = requiredSigners(event.event_type as EventType);
    const roles = new Set(signatures.map((s) => s.role_at_signing));
    if (signatures.length < rule.min) return false;
    if (rule.mode === "all") return rule.roles.every((r) => roles.has(r));
    return rule.roles.length === 0 || rule.roles.some((r) => roles.has(r));
  }
}
