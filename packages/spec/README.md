# @loopledger/spec

Passport and event schema v0.1: JSON Schema (draft 2020-12) plus a JSON-LD context, example passports, and a validation suite (`pnpm test`).

| Path | Contents | License (LL-002) |
|---|---|---|
| `schema/`, `examples/` | schemas, context, examples | Community Specification License 1.0 |
| `src/`, `test/` | the signer table and the suite | Apache-2.0 |

- `schema/passport.schema.json` is the identity record, with the party, carrier, revision, lifecycle and data-grant shapes under `$defs`.
- `schema/event.schema.json` is the envelope, a typed payload per event type, and the invariants.
- `src/signers.ts` exports `REQUIRED_SIGNERS`, the one table of signers per event type. #7 imports it; a test fails if the schema's counts differ.
- Alignment: UNTP DPP 0.7.0 (named in `schema/context.jsonld`; 1.0 was not confirmed released). Carrier and identifier follow ISO/IEC 15459 and EN 18219–18222.
- Joint-type, material and cause fields are term IRIs checked for shape only. #18 adds the membership check.

## Signatures

A signature object (`$defs/signature` in `schema/event.schema.json`, used by events and data grants) carries `sig_id`, `party_id`, `key_id`, `alg`, `signed_hash`, `signed_at`, `role_at_signing` and `signature`. `signature` is a detached JWS (RFC 7515 App. F) with `alg` `EdDSA` (Ed25519, RFC 8037) and is the authoritative value. An independent implementation signs and verifies as follows.

1. **Subject.** For an event, the event as a JSON object without `signatures` and `held`, so `@context`, `@type`, `evidence` and every other member are included. For a data grant, the grant without `signatures`, with an empty list of evidence hashes.
2. **Canonical form.** JCS, RFC 8785: members sorted by UTF-16 code unit, no whitespace, strings and numbers as ECMAScript serialises them. JCS is the only canonical form: the signing payload, `signed_hash` and the Merkle leaf (the JCS of the event without `signatures` and `held`, hashed as `SHA-256(0x00 || bytes)`) all use it.
3. **Payload.** The JCS of the object `{"event": <subject>, "evidence_hashes": <sorted content_hash values of the event's evidence, [] when none>, "party_id", "role_at_signing", "signed_at"}`, the last three taken from the signature object. A relayed signature row can't change the party, role or time.
4. **Protected header.** The JCS of `{"alg": <alg>, "kid": <key_id>}`, so `{"alg":"EdDSA","kid":"did:key:z6Mk…"}`. `alg` and `kid` must equal the signature object's `alg` and `key_id`; the header carries nothing else.
5. **Signing input.** `BASE64URL(header) . BASE64URL(payload)` as ASCII, base64url without padding (RFC 7515 §5.1). The signature is Ed25519 (RFC 8032) over those bytes.
6. **Value.** `signature` is `BASE64URL(header)` + `..` + `BASE64URL(signature bytes)`: the compact JWS with the payload part left empty (the detached form).
7. **Convenience digest.** `signed_hash` is `sha256:<hex>` of the JCS of `{"event": <subject>, "evidence_hashes": [...]}`. It is not the signed value: a verifier recomputes the payload and checks the JWS.
8. **Key.** In the examples `key_id` is a `did:key` (multibase `z`, base58btc of the multicodec `0xed01` and the 32-byte Ed25519 public key). The example keys are derived from each `party_id` by `scripts/sign-examples.ts`, which re-signs the examples.

The legacy string `Ed25519` is not an `alg`. The VC-JOSE-COSE envelope that wraps an event or a passport is the next section.

## VC-JOSE-COSE envelope

An event, and the passport, export as a W3C VCDM 2.0 credential secured with VC-JOSE-COSE, read at UNTP 0.7.0 (the release that goes with the DPP 0.7.0 alignment target; only the shape of the profile is taken from it). `src/vc.ts` builds and checks the credential; `packages/ledger` signs it.

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2", "https://loopledger.org/schema/v0.1/context.jsonld"],
  "type": ["VerifiableCredential", "Event"],
  "issuer": "did:web:example.org",
  "validFrom": "2026-11-08T10:00:00Z",
  "credentialSubject": { "…": "the event, verbatim" }
}
```

1. **Shape.** `@context` is the VC v2 context then ours, in that order; ours redefines no protected term (REQ-SPEC-001). `type` is `["VerifiableCredential", "Event"]` or `["VerifiableCredential", "Passport"]`. `validFrom` is the export time, an RFC 3339 date-time.
2. **Subject.** `credentialSubject` is the event or the passport exactly as stored, including its own `@context`, `@type` and `signatures`. The detached JWS signatures above are not touched and verify against the subject as they do against the bare event (REQ-EVENT-012, REQ-EVENT-013).
3. **Securing.** A new issuer JWS secures the whole credential, media type `application/vc+jwt`: a compact JWS whose protected header is `{"alg":"EdDSA","cty":"vc","kid":<verification method>,"typ":"vc+jwt"}` and whose payload is the credential, both as JCS (RFC 8785), base64url without padding. The signature is Ed25519 over `BASE64URL(header) . BASE64URL(payload)`. This is the issuer's signature, distinct from the event signers' signatures inside the subject, which sign a different payload.
4. **Issuer.** `issuer` is the `did:web` of the tenant exporting the credential, never an event signer, so an event with two signers still has one issuer. Which `did:web` a tenant uses is the deployment's configuration. The examples use `did:web:example.org`, which has no hosted `did.json` and no real key.
5. **Resolution.** `did:web:host[:path…]` resolves to `https://host/[path/…]did.json`, and `did:web:host` with no path to `https://host/.well-known/did.json`; `%3A` in the host is a port. The issuer JWS `kid` is a DID URL `<issuer>#<fragment>` naming a verification method in that document; a verifier fetches the document, finds the method and uses its Ed25519 public key (`publicKeyJwk`, `crv` `Ed25519`).
6. **Relation to `did:key`.** The event signers' `key_id` stays a `did:key` (item 8 above). The issuer key is a different key under a `did:web`: a signer's key never secures a credential, and the issuer key never signs an event.

The real `did:web` domain and who holds its key are decided after the fiscal host (#9) and before any real signed event.

## EPCIS 2.0 export mapping

The exporter is out of scope; this is the mapping it follows (`docs/kickoff/SPEC-data-model.md` §6).

| Ours | EPCIS 2.0 |
|---|---|
| `observed`, `weighed`, `telemetry` | ObjectEvent (`bizStep: inspecting`…) |
| `custody_transferred` | ObjectEvent, `bizStep: shipping/receiving`, `action: OBSERVE`, source/destination party lists |
| lot assets (`kind: lot`) | QuantityElement |
| `processed` | TransformationEvent; `separate` maps assembly to component passports |
| `maintained` | ObjectEvent, `bizStep: repairing` |
| `record_transferred` | ObjectEvent with `owning_party` source/destination |
| `disposition_final` | ObjectEvent with CBV `disposition` (`recycled`, `disposed`…); reuse families in our namespace. One entry per line: its `route` picks the value (`recycle` recycled, `disposal` disposed, `recovery` its own value); a regional code in `classification` is not read |
| `route_*`, `gate_passed`, `exception_*`, `rule_version_applied` | extension fields in our JSON-LD context |
| `signatures`, `evidence` | detached JOSE signatures and a hash list in the extension block |
| `occurred_at`, `recorded_at` | `eventTime`, `recordTime` |
