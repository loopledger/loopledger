# LoopLedger

**An open specification for material passports and recovery evidence in the built environment.**

When a commercial interior is renovated or decommissioned, most of its fixtures, furniture, equipment and panels are landfilled. They aren't worthless. The problem is that no system knows what they are, what condition they're in, where they could go next, or who is accountable for getting them there. LoopLedger is that system.

- **Material passports:** every asset gets an append-only record of its identity, design revision, components and composition, condition, custody and loop position. A physical carrier keeps the passport on the asset, and the record follows it to each new owner.
- **Two-party custody:** each handoff is signed by both sender and receiver, with evidence. Diversion figures are computed from weighed, signed events, never from self-reported totals.
- **Recovery routing:** before demolition, each asset is routed down a fixed ladder (redeploy, remanufacture, resale, donate, recycle, disposal last) by explicit, versioned rules.
- **Design feedback:** recovery outcomes are measured per design revision and per joint, and written back to the manufacturers and design tools that own the design.

## Status

Phase 0, under review. The passport and event schemas (v0.1, JSON-LD) and the joint-type, material and cause vocabularies are published here. Gate G0 is an external review of the schema by EPCIS/UNTP, BIM/design-data and EPD/LCA practitioners.

**Reviewing?** Start with [packages/spec/REVIEW.md](packages/spec/REVIEW.md).

## Packages

| Path | What it is |
|---|---|
| [packages/spec](packages/spec) | Passport and event schemas, examples, validation suite |
| [packages/vocab](packages/vocab) | Joint type, material and cause vocabularies, mapped to bSDD classes where they exist |
| [packages/ledger](packages/ledger) | Append-only ledger: two-party signature verification, evidence hashing |
| [packages/ports](packages/ports) | Interfaces for the event, evidence and key stores the ledger runs on |
| [packages/corpus](packages/corpus) | Jurisdiction rules corpus, seeded with Chicago |
| [packages/drill](packages/drill) | Design-feedback drill: one item in two revisions (G4 bonded, G5 screwed) run through recovery on synthetic events |

## Standards

The core records LoopLedger's own terms: event types, disposition routes, joint types, materials and causes. Standards sit around it as adapters and classifications, so the core does not depend on any one region's codes. The adapters cover EPCIS 2.0 and CBV 2.0 / UNTP interchange, EU DPP (ESPR) export, IFC and bSDD mappings for design data, and ISO/IEC 15459 identifiers carried as GS1 Digital Link. Regional waste codes, such as the EU Waste Framework Directive R/D codes, ride on a disposition line as classifications beside its route. EN 15804 EPDs and ISO 20887 (design for disassembly) are the references for carbon and design.

## Contributing and license

Findings and questions go in [issues](https://github.com/loopledger/loopledger/issues). See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).

Licensed per path ([LICENSE](LICENSE)): the spec and vocabularies under the Community Specification License 1.0, the corpus data under CDLA-Permissive-2.0, everything else under Apache-2.0.
