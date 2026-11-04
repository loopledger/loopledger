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
