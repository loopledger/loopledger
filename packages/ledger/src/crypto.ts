// Canonical form (RFC 8785 JCS), hashing, the detached JWS signing input, per-`alg` verification and the Merkle root
// (SPEC-data-model.md §3, §7; packages/spec/README.md "Signatures").
// Hashing is `@noble/hashes` and bytes are `Uint8Array`, so Node and the browser share one path with no `Buffer`.
// `node:crypto` is only for the Node signer and verifier; a namespace import is read when they run, never at load.
import * as nodeCrypto from "node:crypto";
import type { KeyObject } from "node:crypto";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";
import type { EventRow, Signature } from "@loopledger/ports";

const utf8 = (data: string | Uint8Array): Uint8Array => (typeof data === "string" ? new TextEncoder().encode(data) : data);
const digest = (data: Uint8Array): Uint8Array => nobleSha256(data);

export const sha256 = (data: string | Uint8Array): string => `sha256:${bytesToHex(digest(utf8(data)))}`;

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

const toBase64 = (bytes: Uint8Array): string => btoa(Array.from(bytes, (b) => String.fromCharCode(b)).join(""));
const fromBase64 = (text: string): Uint8Array => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
const b64u = (data: string | Uint8Array): string => toBase64(utf8(data)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
const fromB64u = (text: string): Uint8Array => fromBase64(text.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(text.length / 4) * 4, "="));
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
export const jwsSigningInput = (event: EventRow, sig: Fields & Pick<Signature, "alg" | "key_id">): Uint8Array =>
  utf8(`${jwsHeader(sig.alg, sig.key_id)}.${b64u(signingPayload(event, sig))}`);

/**
 * The signature bytes of a detached JWS (`header..signature`, RFC 7515 App. F). Throws when the JWS has a payload part,
 * is malformed, or its header is not exactly the JCS of `{alg, kid}` for the row's `alg` and `key_id`.
 */
export const detachedSignature = (sig: Pick<Signature, "alg" | "key_id" | "signature">): Uint8Array => {
  const parts = typeof sig.signature === "string" ? sig.signature.split(".") : [];
  if (parts.length !== 3 || parts[1] !== "" || !B64U.test(parts[0]!) || !B64U.test(parts[2]!)) {
    throw new Error("signature is not a detached JWS (header..signature)");
  }
  if (parts[0] !== jwsHeader(sig.alg, sig.key_id)) throw new Error("JWS header does not match alg and key_id");
  return fromB64u(parts[2]!);
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
  const value = b64u(nodeCrypto.sign(null, jwsSigningInput(event, body), privateKey));
  return { ...body, signature: `${jwsHeader(alg, fields.key_id)}..${value}` };
};

/** Signs the event as `signEvent` does, with a WebCrypto Ed25519 private key. The signed bytes are the same. */
export const signEventWebCrypto = async (
  event: EventRow,
  privateKey: CryptoKey,
  fields: Fields & Pick<Signature, "sig_id" | "key_id"> & { alg?: string },
): Promise<Signature> => {
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
  const value = b64u(new Uint8Array(await globalThis.crypto.subtle.sign("Ed25519", privateKey, jwsSigningInput(event, body) as BufferSource)));
  return { ...body, signature: `${jwsHeader(alg, fields.key_id)}..${value}` };
};

/**
 * Secures a credential (`buildCredential` in `packages/spec`) as VC-JOSE-COSE: a compact JWS whose protected header is
 * the JCS of `{alg: EdDSA, cty: "vc", kid, typ: "vc+jwt"}`, whose payload is the JCS of the credential, and whose `kid`
 * is a verification method of the issuer's did:web (`<issuer>#<fragment>`). This is the issuer's signature; the
 * signatures inside the subject are the event signers' and are untouched.
 */
export const signCredential = (credential: { issuer: string }, privateKey: KeyObject, kid: string): string => {
  if (!kid.startsWith(`${credential.issuer}#`)) throw new Error("kid is not a verification method of the issuer");
  const input = `${b64u(canonical({ alg: "EdDSA", cty: "vc", kid, typ: "vc+jwt" }))}.${b64u(canonical(credential))}`;
  return `${input}.${b64u(nodeCrypto.sign(null, utf8(input), privateKey))}`;
};

/** Verifies the signature bytes over `message` with a base64 SPKI DER public key. */
export type Verifier = (publicKey: string, message: Uint8Array, signature: Uint8Array) => boolean | Promise<boolean>;

/** The part of a did:web document `verifyCredential` reads: its `id` and its verification methods. */
export interface DidDocument {
  id: string;
  verificationMethod?: readonly { id: string; type?: string; publicKeyJwk?: { kty?: string; crv?: string; x?: string } }[];
}

const ED25519_SPKI_PREFIX = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);

const parseJson = (part: string, what: string): Record<string, unknown> => {
  try {
    const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromB64u(part)));
    if (value !== null && typeof value === "object" && !Array.isArray(value)) return value as Record<string, unknown>;
  } catch {
    // falls through to the refusal
  }
  throw new Error(`credential JWS ${what} is not a JSON object`);
};

/**
 * Verifies a credential secured by `signCredential` against the issuer's did:web document, offline. Throws unless the
 * protected header is `{alg: EdDSA, typ: vc+jwt, cty: vc}`, the payload is the JCS of a credential whose `issuer` is the
 * document's `id`, `kid` is `<issuer>#…` and names a verification method of the document (an Ed25519 `publicKeyJwk`),
 * and the signature over `header.payload` verifies. Returns the decoded credential. Dates and revocation are not checked.
 */
export const verifyCredential = (jws: string, didDocument: DidDocument): Record<string, unknown> => {
  const parts = typeof jws === "string" ? jws.split(".") : [];
  if (parts.length !== 3 || !parts.every((p) => B64U.test(p))) throw new Error("credential is not a compact JWS");
  const [h, p, s] = parts as [string, string, string];
  const header = parseJson(h, "header");
  if (header.alg !== "EdDSA") throw new Error("credential JWS alg is not EdDSA");
  if (header.typ !== "vc+jwt") throw new Error("credential JWS typ is not vc+jwt");
  if (header.cty !== "vc") throw new Error("credential JWS cty is not vc");
  const credential = parseJson(p, "payload");
  if (p !== b64u(canonical(credential))) throw new Error("credential JWS payload is not the JCS of the credential");
  const { issuer } = credential;
  if (typeof issuer !== "string" || issuer !== didDocument.id) throw new Error("credential issuer is not the did:web document's id");
  const kid = header.kid;
  if (typeof kid !== "string" || !kid.startsWith(`${issuer}#`)) throw new Error("kid is not a verification method of the issuer");
  const method = didDocument.verificationMethod?.find((m) => m.id === kid);
  if (!method) throw new Error("kid is not a verification method in the did:web document");
  const jwk = method.publicKeyJwk;
  if (jwk?.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string" || !B64U.test(jwk.x)) {
    throw new Error("verification method is not an Ed25519 publicKeyJwk");
  }
  const raw = fromB64u(jwk.x);
  if (raw.length !== 32) throw new Error("verification method key is not 32 bytes");
  const spki = toBase64(concatBytes(ED25519_SPKI_PREFIX, raw));
  if (VERIFIERS.EdDSA!(spki, utf8(`${h}.${p}`), fromB64u(s)) !== true) throw new Error("credential JWS signature does not verify");
  return credential;
};

const eddsa: Verifier = (publicKey, message, signature) => {
  const key = nodeCrypto.createPublicKey({ key: Buffer.from(publicKey, "base64"), format: "der", type: "spki" });
  return nodeCrypto.verify(null, message, key, signature);
};

/** Verification dispatches on the JOSE `alg`. `EdDSA` (Ed25519 curve, RFC 8037) is the only suite in v1 (no PQC). */
export const VERIFIERS: Readonly<Record<string, Verifier>> = { EdDSA: eddsa };

const eddsaWebCrypto: Verifier = async (publicKey, message, signature) => {
  const key = await globalThis.crypto.subtle.importKey("spki", fromBase64(publicKey) as BufferSource, "Ed25519", false, ["verify"]);
  return globalThis.crypto.subtle.verify("Ed25519", key, new Uint8Array(signature), new Uint8Array(message));
};

/** The same table through WebCrypto, for the browser: identical signing input and identical results. */
export const WEBCRYPTO_VERIFIERS: Readonly<Record<string, Verifier>> = { EdDSA: eddsaWebCrypto };

const leaf = (event: EventRow): Uint8Array => digest(concatBytes(Uint8Array.of(0), utf8(canonical(eventRow(event)))));
const node = (left: Uint8Array, right: Uint8Array): Uint8Array => digest(concatBytes(Uint8Array.of(1), left, right));

const tree = (leaves: Uint8Array[]): Uint8Array => {
  if (leaves.length === 1) return leaves[0]!;
  let split = 1;
  while (split * 2 < leaves.length) split *= 2;
  return node(tree(leaves.slice(0, split)), tree(leaves.slice(split)));
};

/** Merkle root over the events in log order (RFC 6962 shape). Pure: the same events give the same root. */
export const merkleRoot = (events: readonly EventRow[]): string =>
  events.length === 0 ? sha256("") : `sha256:${bytesToHex(tree(events.map(leaf)))}`;
