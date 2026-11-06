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

The legacy string `Ed25519` is not an `alg`. A VC-JOSE-COSE (UNTP) envelope that wraps this signature is a follow-up.

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
| `disposition_final` | ObjectEvent with CBV `disposition` (`recycled`, `disposed`…); reuse families in our namespace |
| `route_*`, `gate_passed`, `exception_*`, `rule_version_applied` | extension fields in our JSON-LD context |
| `signatures`, `evidence` | detached JOSE signatures and a hash list in the extension block |
| `occurred_at`, `recorded_at` | `eventTime`, `recordTime` |
