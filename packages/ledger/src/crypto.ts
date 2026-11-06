// Canonical form (RFC 8785 JCS), hashing, the detached JWS signing input, per-`alg` verification and the Merkle root
// (SPEC-data-model.md §3, §7; packages/spec/README.md "Signatures").
import { createHash, createPublicKey, sign, verify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import type { EventRow, Signature } from "@loopledger/ports";

export const sha256 = (data: string | Uint8Array): string => `sha256:${createHash("sha256").update(data).digest("hex")}`;

/**
 * RFC 8785 JSON Canonicalization Scheme: members sorted by UTF-16 code units, no whitespace, strings and numbers
 * serialised as ECMAScript does. Undefined members are left out, as `JSON.stringify` does; a non-finite number has no
 * JSON form and throws.
 */
export const canonical = (value: unknown): string => {
  if (typeof value === "number" && !Number.isFinite(value)) throw new Error("a non-finite number has no JCS form");
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).filter((k) => record[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(record[k])}`).join(",")}}`;
};

const b64u = (data: string | Uint8Array): string => Buffer.from(data).toString("base64url");
const B64U = /^[A-Za-z0-9_-]+$/;

/** The event as a row: whatever the caller sent, without the derived `held` flag and the signatures. */
export const eventRow = (event: EventRow & { held?: unknown; signatures?: unknown }): EventRow => {
  const { held: _held, signatures: _signatures, ...row } = event;
  return row as EventRow;
};

const evidenceHashes = (event: EventRow): string[] => (event.evidence ?? []).map((e) => e.content_hash).sort();

/** The convenience digest every signature of the event carries: SHA-256 of the JCS of the event and its evidence hashes. */
export const eventHash = (event: EventRow): string => sha256(canonical({ event: eventRow(event), evidence_hashes: evidenceHashes(event) }));

type Fields = Pick<Signature, "party_id" | "role_at_signing" | "signed_at">;

/** The JWS payload. `party_id`, `role_at_signing` and `signed_at` are inside, so a relayed row can't change them. */
export const signingPayload = (event: EventRow, fields: Fields): string =>
  canonical({
    event: eventRow(event),
    evidence_hashes: evidenceHashes(event),
    party_id: fields.party_id,
    role_at_signing: fields.role_at_signing,
    signed_at: fields.signed_at,
  });

/** The protected header, BASE64URL of the JCS of `{alg, kid}`. */
export const jwsHeader = (alg: string, keyId: string): string => b64u(canonical({ alg, kid: keyId }));

/** The bytes a signer signs: `BASE64URL(header) . BASE64URL(payload)` (RFC 7515 §5.1). */
export const jwsSigningInput = (event: EventRow, sig: Fields & Pick<Signature, "alg" | "key_id">): Buffer =>
  Buffer.from(`${jwsHeader(sig.alg, sig.key_id)}.${b64u(signingPayload(event, sig))}`);

/**
 * The signature bytes of a detached JWS (`header..signature`, RFC 7515 App. F). Throws when the JWS has a payload part,
 * is malformed, or its header is not exactly the JCS of `{alg, kid}` for the row's `alg` and `key_id`.
 */
export const detachedSignature = (sig: Pick<Signature, "alg" | "key_id" | "signature">): Buffer => {
  const parts = typeof sig.signature === "string" ? sig.signature.split(".") : [];
  if (parts.length !== 3 || parts[1] !== "" || !B64U.test(parts[0]!) || !B64U.test(parts[2]!)) {
    throw new Error("signature is not a detached JWS (header..signature)");
  }
  if (parts[0] !== jwsHeader(sig.alg, sig.key_id)) throw new Error("JWS header does not match alg and key_id");
  return Buffer.from(parts[2]!, "base64url");
};

/** Signs the event as a detached JWS with an Ed25519 private key and returns the signature row. */
export const signEvent = (
  event: EventRow,
  privateKey: KeyObject,
  fields: Fields & Pick<Signature, "sig_id" | "key_id"> & { alg?: string },
): Signature => {
  const alg = fields.alg ?? "EdDSA";
  const body = {
    sig_id: fields.sig_id,
    party_id: fields.party_id,
    key_id: fields.key_id,
    alg,
    signed_hash: eventHash(event),
    signed_at: fields.signed_at,
    role_at_signing: fields.role_at_signing,
  };
  const value = sign(null, jwsSigningInput(event, body), privateKey).toString("base64url");
  return { ...body, signature: `${jwsHeader(alg, fields.key_id)}..${value}` };
};

/** Verifies the signature bytes over `message` with a base64 SPKI DER public key. */
export type Verifier = (publicKey: string, message: Uint8Array, signature: Uint8Array) => boolean;

const eddsa: Verifier = (publicKey, message, signature) => {
  const key = createPublicKey({ key: Buffer.from(publicKey, "base64"), format: "der", type: "spki" });
  return verify(null, message, key, signature);
};

/** Verification dispatches on the JOSE `alg`. `EdDSA` (Ed25519 curve, RFC 8037) is the only suite in v1 (no PQC). */
export const VERIFIERS: Readonly<Record<string, Verifier>> = { EdDSA: eddsa };

const leaf = (event: EventRow): Buffer => createHash("sha256").update(Buffer.concat([Buffer.from([0]), Buffer.from(canonical(eventRow(event)))])).digest();
const node = (left: Buffer, right: Buffer): Buffer => createHash("sha256").update(Buffer.concat([Buffer.from([1]), left, right])).digest();

const tree = (leaves: Buffer[]): Buffer => {
  if (leaves.length === 1) return leaves[0]!;
  let split = 1;
  while (split * 2 < leaves.length) split *= 2;
  return node(tree(leaves.slice(0, split)), tree(leaves.slice(split)));
};

/** Merkle root over the events in log order (RFC 6962 shape). Pure: the same events give the same root. */
export const merkleRoot = (events: readonly EventRow[]): string =>
  events.length === 0 ? sha256("") : `sha256:${tree(events.map(leaf)).toString("hex")}`;
