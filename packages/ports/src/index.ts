// Interfaces the ledger depends on (LL-001). Adapters implement them; no database or cloud SDK appears here.
// There is no update and no delete on any port: the log only grows.

export interface Signature {
  sig_id: string;
  party_id: string;
  key_id: string;
  alg: string;
  signed_hash: string;
  signed_at: string;
  role_at_signing: string;
}

/** A signature row as stored. `signature` is the base64 signature value; the spec's signature object has no field for it. */
export interface SignatureRow extends Signature {
  signature: string;
}

export interface EvidenceRef {
  evidence_id: string;
  kind: string;
  content_hash: string;
  storage_ref: string;
  captured_by?: string;
  redactions?: string[];
}

/** The immutable event row: the envelope and payload, with no signatures and no held flag (both are derived). */
export interface EventRow {
  event_id: string;
  tenant_id: string;
  event_type: string;
  asset_ids: string[];
  occurred_at: string;
  recorded_at: string;
  payload: Record<string, unknown>;
  evidence?: EvidenceRef[];
  correction_of?: string;
  [field: string]: unknown;
}

export interface EventStore {
  /** Throws when the `event_id` is already in the log. */
  append(event: EventRow): Promise<void>;
  /** Throws when the event is unknown or the `sig_id` is already stored. */
  appendSignature(eventId: string, row: SignatureRow): Promise<void>;
  read(eventId: string): Promise<EventRow | undefined>;
  /** Every event, in the order it was appended. */
  readAll(): Promise<EventRow[]>;
  signatures(eventId: string): Promise<SignatureRow[]>;
}

export interface EvidenceStore {
  /** Stores the bytes and returns their hash, `sha256:<hex>`. */
  put(bytes: Uint8Array): Promise<string>;
  get(hash: string): Promise<Uint8Array | undefined>;
}

export interface KeyRecord {
  key_id: string;
  /** The party this key belongs to. A signature made with it counts only for this party. */
  party_id: string;
  alg: string;
  /** Base64 of the SPKI DER public key. */
  public_key: string;
  valid_from: string;
  valid_until?: string;
}

export interface KeyResolver {
  resolve(keyId: string): Promise<KeyRecord | undefined>;
}
