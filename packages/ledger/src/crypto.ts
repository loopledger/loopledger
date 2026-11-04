// Canonical form, hashing, per-`alg` signature verification and the Merkle root (SPEC-data-model.md §3, §7).
import { createHash, createPublicKey, verify } from "node:crypto";
import type { EventRow, Signature } from "@loopledger/ports";

export const sha256 = (data: string | Uint8Array): string => `sha256:${createHash("sha256").update(data).digest("hex")}`;

/** JSON with sorted keys and no whitespace, so equal values always serialise to the same bytes. */
export const canonical = (value: unknown): string => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).filter((k) => record[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(record[k])}`).join(",")}}`;
};

/** The event as a row: whatever the caller sent, without the derived `held` flag and the signatures. */
export const eventRow = (event: EventRow & { held?: unknown; signatures?: unknown }): EventRow => {
  const { held: _held, signatures: _signatures, ...row } = event;
  return row as EventRow;
};

/** What every signature of the event commits to: the canonical event form plus its evidence hashes. */
export const eventHash = (event: EventRow): string =>
  sha256(canonical({ event: eventRow(event), evidence_hashes: (event.evidence ?? []).map((e) => e.content_hash).sort() }));

/** The bytes a signer signs. `party_id`, `role_at_signing` and `signed_at` are inside, so a relayed row can't change them. */
export const signingInput = (sig: Pick<Signature, "signed_hash" | "party_id" | "role_at_signing" | "signed_at">): Buffer =>
  Buffer.from(
    canonical({ signed_hash: sig.signed_hash, party_id: sig.party_id, role_at_signing: sig.role_at_signing, signed_at: sig.signed_at }),
  );

/** Verifies a base64 signature over `message` with a base64 SPKI DER public key. */
export type Verifier = (publicKey: string, message: Uint8Array, signature: string) => boolean;

const ed25519: Verifier = (publicKey, message, signature) => {
  const key = createPublicKey({ key: Buffer.from(publicKey, "base64"), format: "der", type: "spki" });
  return verify(null, message, key, Buffer.from(signature, "base64"));
};

/** Verification dispatches on `alg`. Ed25519 is the only suite in v1 (no PQC); "EdDSA" is the name the spec examples use. */
export const VERIFIERS: Readonly<Record<string, Verifier>> = { Ed25519: ed25519, EdDSA: ed25519 };

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
