// The ledger: an append-only event log with two-party signatures and evidence stored by hash (issue #7).
// Events are never updated. A countersignature is a new signature row, and `held` is derived from the rows.
import { EVENT_TYPES, dispositionClassificationErrors, dispositionFamilyErrors, dispositionSeparationErrors, requiredSigners, signerBindingErrors } from "@loopledger/spec";
import type { EventType } from "@loopledger/spec";
import type { EventRow, EventStore, EvidenceStore, KeyResolver, LedgerMode, SignatureRow } from "@loopledger/ports";
import { VERIFIERS, detachedSignature, eventHash, eventRow, jwsSigningInput, sha256 } from "./crypto";
import type { Verifier } from "./crypto";

export { VERIFIERS, WEBCRYPTO_VERIFIERS, canonical, detachedSignature, eventHash, jwsHeader, jwsSigningInput, merkleRoot, sha256, signEvent, signCredential, signEventWebCrypto, signingPayload, verifyCredential } from "./crypto";
export type { DidDocument } from "./crypto";

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
    /** Fixed at creation (REQ-LEDGER-008). Both stores must carry the same mode. */
    readonly mode: LedgerMode = "evidence",
    verifiers: Readonly<Record<string, Verifier>> = VERIFIERS,
  ) {
    if (events.mode !== mode || evidence.mode !== mode) refuse(`the stores are not ${mode} stores`);
    this.verifiers = verifiers;
  }

  /**
   * Appends an event, with its signatures, from another ledger. Nothing leaves a pilot ledger for an evidence ledger:
   * the check is on the ledgers' modes, not on the event (REQ-LEDGER-009).
   */
  async importFrom(source: Ledger, tenantId: string, eventId: string): Promise<Appended> {
    if (source.mode === "pilot" && this.mode === "evidence") refuse("events of a pilot ledger can't enter an evidence ledger");
    const { held: _held, signatures, ...event } = await source.read(tenantId, eventId);
    return this.append({ ...event, signatures });
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
    if (event.event_type === "disposition_final") await this.disposition(event);

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

  /**
   * Refuses a `disposition_final` whose `family` is not the route of its heaviest line, whose known-scheme
   * classification contradicts a line's `route`, or that sends a fraction to redeploy, resale, donation or recycling
   * that no `processed` event on the asset (or the one that birthed it) separated.
   */
  private async disposition(event: EventRow): Promise<void> {
    const processed = (await this.events.readAll())
      .filter((e) => e.event_type === "processed" && e.tenant_id === event.tenant_id)
      .filter((e) => {
        const children = Array.isArray(e.payload["child_asset_ids"]) ? e.payload["child_asset_ids"] : [];
        return event.asset_ids.some((a) => e.asset_ids.includes(a) || children.includes(a));
      })
      .map((e) => e.payload);
    const errors = [
      ...dispositionFamilyErrors(event.payload),
      ...dispositionClassificationErrors(event.payload),
      ...dispositionSeparationErrors(event.payload, processed),
    ];
    if (errors.length > 0) refuse(errors.join("; "));
  }

  /** Refuses a signature that does not bind to this event, its key's party and its own fields, or repeats a party. */
  private async check(event: EventRow, existing: readonly SignatureRow[], row: SignatureRow): Promise<void> {
    if (existing.some((s) => s.party_id === row.party_id)) refuse(`party ${row.party_id} already signed event ${event.event_id}`);
    if (existing.some((s) => s.sig_id === row.sig_id)) refuse(`signature ${row.sig_id} is already on event ${event.event_id}`);
    if (row.signed_hash !== eventHash(event)) refuse("signed_hash does not match the event");
    const verifier = Object.hasOwn(this.verifiers, row.alg) ? this.verifiers[row.alg] : undefined;
    if (!verifier) refuse(`unknown alg ${String(row.alg)}`);
    let value: Uint8Array = new Uint8Array(0);
    try {
      value = detachedSignature(row);
    } catch (error) {
      refuse((error as Error).message);
    }
    const key = await this.keys.resolve(row.key_id);
    if (!key) refuse(`unknown key ${row.key_id}`);
    else {
      if (key.party_id !== row.party_id) refuse(`key ${row.key_id} does not belong to party ${row.party_id}`);
      if (key.alg !== row.alg) refuse(`key ${row.key_id} is not an ${row.alg} key`);
      if (this.mode === "pilot" && key.mode !== "test") refuse(`key ${row.key_id} is not a test key: a pilot ledger takes test keys only`);
      if (this.mode === "evidence" && key.mode !== "production") refuse(`key ${row.key_id} is a test key: an evidence ledger refuses it`);
      const at = time(row.signed_at);
      if (Number.isNaN(at) || at < time(key.valid_from) || (key.valid_until !== undefined && at > time(key.valid_until))) {
        refuse(`signed_at is outside the validity window of key ${row.key_id}`);
      }
      let ok = false;
      try {
        ok = await verifier!(key.public_key, jwsSigningInput(event, row), value);
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
    if (signerBindingErrors(event.event_type as EventType, event.payload, signatures).length > 0) return false;
    if (rule.mode === "all") return rule.roles.every((r) => roles.has(r));
    return rule.roles.length === 0 || rule.roles.some((r) => roles.has(r));
  }
}
