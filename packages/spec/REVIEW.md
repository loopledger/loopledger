# Reviewing schema v0.1

LoopLedger records what happens to building fit-out components after use: how they come apart, what they are worth, and where they go. The records are signed, append-only events against a passport, so that a manufacturer can see which design revision performed better at end of life, and why. This folder holds schema v0.1. We are asking reviewers from four areas to read it before we freeze it: two from the EPCIS/UNTP ecosystem, one from BIM/design data, and one from EPD/LCA practice.

A review takes one to two hours.

## Reading order

1. [`README.md`](README.md): what each file is, the UNTP DPP alignment, and the EPCIS 2.0 export mapping.
2. [`schema/passport.schema.json`](schema/passport.schema.json): the identity record, covering party, carrier, catalog revision, components and joint graph, composition, and data grants.
3. [`schema/event.schema.json`](schema/event.schema.json): the event envelope with signatures and evidence, and a typed payload per event type. The required signers per event type are in [`src/signers.ts`](src/signers.ts).
4. [`examples/`](examples/): a 2-seat booth module in two revisions (G4 bonded, G5 screwed), one of its seats as a component passport, and the G4 module's event history.
5. [`../vocab/`](../vocab/): the joint-type, material and cause vocabularies, with their bSDD references.

## What we want to know

- Can the schema answer "which design revision performed better at end of life, and why", at the level of the joint and within a life band?
- Is every field the feedback loop needs captured when the event happens, or could some only be derived later from data we won't have?
- Does composition reconcile with weighed fractions, using a mass basis and the same material vocabulary?
- Can an owner who never joins the network resolve a passport and append to it?
- Do the vocabularies map to existing classifications rather than inventing parallel ones?
- Is the core vocabulary (routes, joint types, materials, causes) sufficient, with the standards as mappings and classifications beside it rather than inside it?

For a reviewer from a particular area, these questions matter most:

- **EPCIS/UNTP:** are the event types, the custody and record transfers, and the export mapping faithful to EPCIS 2.0 and the UNTP DPP?
- **BIM/design data:** are the catalog revision, the joint graph and the bSDD references (IFC 4.3 for joint types, NAAKT 2.5 for materials) the right hooks into design data?
- **EPD/LCA:** do composition, weighed fractions and final disposition carry what an EPD or a Module D claim would need?

## Sending findings

Open an issue on this repository, one per finding, or reply to the email that brought you here. A finding that names the field and the case it fails is the most useful kind.
