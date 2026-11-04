import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { describe, expect, it } from "vitest";
import { EVENT_TYPES, REQUIRED_SIGNERS, requiredSigners } from "../src/index";
import type { EventType } from "../src/index";

type Json = any;

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path: string): Json => JSON.parse(readFileSync(join(root, path), "utf8"));
const passportSchema = read("schema/passport.schema.json");
const eventSchema = read("schema/event.schema.json");

const ajv = new Ajv2020({ allErrors: true, strictTypes: false });
addFormats(ajv);
ajv.addSchema(passportSchema);
ajv.addSchema(eventSchema);
const passportCheck = ajv.compile(passportSchema);
const eventCheck = ajv.compile(eventSchema);

const passportOk = (doc: Json) => passportCheck(doc) as boolean;
const eventOk = (doc: Json) => eventCheck(doc) as boolean;
const grantCheck = ajv.compile({ $ref: `${passportSchema.$id}#/$defs/data_grant` });

const booth = read("examples/booth-2s-g4.passport.json");
const seat = read("examples/booth-2s-g4-seat.passport.json");
const events: Json[] = read("examples/booth-2s-g4.events.json");
const event = (type: string, nth = 0): Json => structuredClone(events.filter((e) => e.type === type)[nth]);
const copy = (doc: Json): Json => structuredClone(doc);

const signatureErrors = (doc: Json): boolean => {
  eventCheck(doc);
  return (eventCheck.errors ?? []).some((e) => e.instancePath.startsWith("/signatures"));
};

/** The event type each signer entry of the schema binds, with its minimum and the roles it names. */
const schemaSigners = (): Map<string, { min: number; roles: string[] }> => {
  const roles = (node: Json): string[] => {
    if (Array.isArray(node)) return node.flatMap(roles);
    if (node === null || typeof node !== "object") return [];
    const own = node.properties?.role_at_signing;
    const here = own ? (own.enum ?? [own.const]) : [];
    return [...here, ...Object.values(node).flatMap(roles)];
  };
  const found = new Map<string, { min: number; roles: string[] }>();
  for (const entry of eventSchema.allOf) {
    const signatures = entry.then?.properties?.signatures;
    if (!signatures) continue;
    const type = entry.if.properties.type;
    for (const t of type.enum ?? [type.const]) found.set(t, { min: signatures.minItems, roles: roles(signatures).sort() });
  }
  return found;
};

describe("REQ-SPEC-001 the schema and its JSON-LD context are published under packages/spec", () => {
  it("publishes a context, a passport schema and an event schema, all draft 2020-12", () => {
    const names = readdirSync(join(root, "schema")).sort();
    expect(names).toEqual(["context.jsonld", "event.schema.json", "passport.schema.json"]);
    expect(passportSchema.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
    expect(eventSchema.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
    expect(ajv.validateSchema(passportSchema)).toBe(true);
    expect(ajv.validateSchema(eventSchema)).toBe(true);
  });

  it("names the alignment target in the context and resolves the context IRI the documents use", () => {
    const context = read("schema/context.jsonld")["@context"];
    expect(context["untp-dpp"]).toContain("/0.7.0/");
    expect(passportSchema.properties["@context"].contains.const).toBe("https://loopledger.org/schema/v0.1/context.jsonld");
    expect(booth["@context"]).toContain("https://loopledger.org/schema/v0.1/context.jsonld");
  });

  it("rejects a passport that does not point at the context", () => {
    const doc = copy(booth);
    doc["@context"] = ["https://example.com/other.jsonld"];
    expect(passportOk(doc)).toBe(false);
  });
});

describe("REQ-SPEC-002 example passports cover an assembly, a carrier and a record transfer", () => {
  it("validates every example", () => {
    expect(passportOk(booth)).toBe(true);
    expect(passportOk(seat)).toBe(true);
    for (const e of events) expect(eventOk(e), JSON.stringify(eventCheck.errors)).toBe(true);
  });

  it("includes an assembly with components and joints, a carrier, and a record_transferred event", () => {
    expect(booth.components.length).toBeGreaterThan(1);
    expect(booth.joints.length).toBeGreaterThan(1);
    expect(booth.carrier.digital_link).toMatch(/\/01\/\d{14}\/21\//);
    expect(events.map((e) => e.type)).toContain("record_transferred");
    expect(events.map((e) => e.type)).toContain("carrier_attached");
  });

  it("keeps joints between components the assembly lists, and a separated component's lineage pointing at its parent", () => {
    const ids = new Set(booth.components.map((c: Json) => c.component_id));
    for (const j of booth.joints) for (const end of j.between) expect(ids.has(end)).toBe(true);
    expect(seat.lineage.parent_asset).toBe(booth.asset_id);
  });
});

describe("REQ-SPEC-003 the validation suite rejects passports and events that break the invariants", () => {
  it("runs under pnpm test and rejects a broken passport and a broken event", () => {
    const badPassport = copy(booth);
    delete badPassport.passport_id;
    const badEvent = event("weighed");
    delete badEvent.payload.certification_id;
    expect(passportOk(badPassport)).toBe(false);
    expect(eventOk(badEvent)).toBe(false);
  });
});

describe("REQ-PASSPORT-001 identity fields", () => {
  it.each(["asset_id", "passport_id", "tenant_id", "kind", "revision", "owner", "origin"])("rejects a passport without %s", (field) => {
    const doc = copy(booth);
    delete doc[field];
    expect(passportOk(doc)).toBe(false);
  });

  it("needs a catalog ref or a free class, and a quantity for a lot", () => {
    const free = copy(seat);
    delete free.class_name;
    expect(passportOk(free)).toBe(false);
    const lot = copy(seat);
    lot.kind = "lot";
    expect(passportOk(lot)).toBe(false);
    lot.quantity = { value: 22, uom: "each" };
    expect(passportOk(lot)).toBe(true);
  });

  it("rejects a malformed passport alias, asset id, grade and controlled flag without a policy", () => {
    for (const [field, value] of [["passport_id", "booth-1"], ["asset_id", "ast_123"], ["condition_grade", "D"], ["controlled", { value: true }]] as const) {
      const doc = copy(booth);
      doc[field] = value;
      expect(passportOk(doc), field).toBe(false);
    }
    const controlled = copy(booth);
    controlled.controlled = { value: true, policy_id: "pol-trademark" };
    expect(passportOk(controlled)).toBe(true);
  });
});

describe("REQ-PASSPORT-002 revision basis is declared, observed or unknown", () => {
  it("accepts each basis in its own shape", () => {
    for (const revision of [{ basis: "declared", label: "G4" }, { basis: "observed", label: "G5" }, { basis: "unknown" }]) {
      const doc = copy(booth);
      doc.revision = revision;
      expect(passportOk(doc), JSON.stringify(revision)).toBe(true);
    }
  });

  it("rejects another basis, an unknown revision with a label, and a known one without", () => {
    for (const revision of [{ basis: "guessed", label: "G4" }, { basis: "unknown", label: "G4" }, { basis: "declared" }]) {
      const doc = copy(booth);
      doc.revision = revision;
      expect(passportOk(doc), JSON.stringify(revision)).toBe(false);
    }
  });
});

describe("REQ-PASSPORT-008 catalog item recovery method and design reference", () => {
  const g5 = read("examples/booth-2s-g5.passport.json");

  it("validates the G4 and G5 examples, G5 superseding G4 with screwed upholstery joints", () => {
    expect(passportOk(booth)).toBe(true);
    expect(passportOk(g5)).toBe(true);
    expect(g5.catalog_ref.supersedes).toBe(booth.revision.label);
    expect(g5.joints.filter((j: Json) => j.type.endsWith("/screwed"))).toHaveLength(2);
  });

  it("rejects a recovery method without a declared labor figure or with an unknown method", () => {
    const open = copy(g5);
    delete open.recovery_method[0].declared_labor_min;
    expect(passportOk(open)).toBe(false);
    const unknown = copy(g5);
    unknown.recovery_method[0].method = "shred";
    expect(passportOk(unknown)).toBe(false);
  });

  it("rejects a design reference with an unknown scheme or no value", () => {
    const scheme = copy(g5);
    scheme.design_ref[0].scheme = "napkin";
    expect(passportOk(scheme)).toBe(false);
    const empty = copy(g5);
    empty.design_ref[0].value = "";
    expect(passportOk(empty)).toBe(false);
  });
});

describe("REQ-PASSPORT-003 assembly, joint and composition shape", () => {
  it("rejects a joint that is not between exactly two components, or has no reversibility", () => {
    const three = copy(booth);
    three.joints[0].between = ["frame", "seat", "back"];
    expect(passportOk(three)).toBe(false);
    const open = copy(booth);
    delete open.joints[0].reversible;
    expect(passportOk(open)).toBe(false);
  });

  it("rejects a component without mass or a composition line over 100 percent", () => {
    const light = copy(booth);
    delete light.components[0].mass_kg;
    expect(passportOk(light)).toBe(false);
    const heavy = copy(booth);
    heavy.composition[0].mass_pct = 140;
    expect(passportOk(heavy)).toBe(false);
  });

  it("carries substance lines with a CAS number, and rejects one without", () => {
    expect(booth.composition.some((c: Json) => c.substances)).toBe(true);
    const doc = copy(booth);
    doc.composition[2].substances[0].cas = "not-a-cas";
    expect(passportOk(doc)).toBe(false);
  });
});

describe("REQ-PASSPORT-004 carrier with an ISO/IEC 15459 identifier as a GS1 Digital Link", () => {
  it("accepts the example carrier and rejects a digital link that is not GTIN plus serial", () => {
    expect(passportOk(booth)).toBe(true);
    const doc = copy(booth);
    doc.carrier.digital_link = "https://id.example.com/passports/BTH2S000101";
    expect(passportOk(doc)).toBe(false);
  });

  it("rejects an identifier that is not a GTIN-14 plus serial, and an unknown carrier kind", () => {
    const id = copy(booth);
    id.carrier.identifier = "BTH2S000101";
    expect(passportOk(id)).toBe(false);
    const kind = copy(booth);
    kind.carrier.kind = "barcode";
    expect(passportOk(kind)).toBe(false);
  });
});

describe("REQ-PASSPORT-005 status and lifecycle are separate fields", () => {
  it("has no value in common between status and loop_route", () => {
    const status: string[] = passportSchema.$defs.status.enum;
    const routes: string[] = passportSchema.$defs.lifecycle.properties.loop_route.enum;
    expect(status.filter((s) => routes.includes(s))).toEqual([]);
    expect(Object.keys(passportSchema.properties)).toEqual(expect.arrayContaining(["status", "lifecycle"]));
  });

  it("rejects a route in status, a status in loop_route, and a status that is not a plain value", () => {
    const route = copy(booth);
    route.status = "reuse";
    expect(passportOk(route)).toBe(false);
    const status = copy(booth);
    status.lifecycle.loop_route = "scheduled";
    expect(passportOk(status)).toBe(false);
    const merged = copy(booth);
    merged.status = { status: "removed", loop_route: "reuse" };
    expect(passportOk(merged)).toBe(false);
    const disposal = copy(booth);
    disposal.lifecycle.loop_route = "disposal";
    expect(passportOk(disposal)).toBe(false);
  });

  it("accepts every status with a lifecycle beside it", () => {
    for (const status of passportSchema.$defs.status.enum) {
      const doc = copy(booth);
      doc.status = status;
      expect(passportOk(doc), status).toBe(true);
    }
  });
});

describe("REQ-PASSPORT-006 manufacturer, designer and owner roles and the data grant", () => {
  it("accepts a grant signed by tenant and grantee", () => {
    expect(grantCheck(booth.data_grants[0])).toBe(true);
  });

  it("rejects a grant missing the grantee signature, with an unknown field, or without an expiry", () => {
    const unsigned = copy(booth.data_grants[0]);
    unsigned.signatures = [unsigned.signatures[0]];
    expect(grantCheck(unsigned)).toBe(false);
    const field = copy(booth.data_grants[0]);
    field.fields = ["salaries"];
    expect(grantCheck(field)).toBe(false);
    const open = copy(booth.data_grants[0]);
    delete open.expires;
    expect(grantCheck(open)).toBe(false);
  });

  it("rejects an owner without record access, or a manufacturer that is not a party id", () => {
    const owner = copy(booth);
    delete owner.owner.record_access;
    expect(passportOk(owner)).toBe(false);
    const maker = copy(booth);
    maker.manufacturer = { party_id: "Booth Makers" };
    expect(passportOk(maker)).toBe(false);
  });
});

describe("REQ-PASSPORT-007 vocabulary fields are scheme-qualified IRIs, checked for shape only", () => {
  it("rejects a bare string, a term from another scheme, or a non-IRI in joint type, material and cause", () => {
    const joint = copy(booth);
    joint.joints[0].type = "bolted";
    expect(passportOk(joint)).toBe(false);
    const crossed = copy(booth);
    crossed.joints[0].type = "https://loopledger.org/vocab/material/steel";
    expect(passportOk(crossed)).toBe(false);
    const material = copy(booth);
    material.components[0].material = "steel";
    expect(passportOk(material)).toBe(false);
    const cause = event("removed");
    cause.payload.cause.term = "bonded_joint";
    expect(eventOk(cause)).toBe(false);
  });

  it("does not check membership: any well-formed term in the right scheme passes (#18 adds that)", () => {
    const doc = copy(booth);
    doc.joints[0].type = "https://loopledger.org/vocab/joint_type/v0.1/not_yet_published";
    expect(passportOk(doc)).toBe(true);
  });
});

describe("REQ-EVENT-001 envelope and a typed payload for every event type", () => {
  it("lists every taxonomy event type in the envelope enum", () => {
    expect([...eventSchema.properties.type.enum].sort()).toEqual([...EVENT_TYPES].sort());
  });

  it("has a payload definition for each type and rejects a payload of the wrong shape", () => {
    for (const type of EVENT_TYPES) {
      const key = type.startsWith("exception_") ? "payload_exception" : `payload_${type}`;
      expect(eventSchema.$defs[key], type).toBeDefined();
    }
    const doc = event("weighed");
    doc.payload = { mass_kg: 218 };
    expect(eventOk(doc)).toBe(false);
  });

  it("rejects an envelope missing a required field, with an unknown type, or with a naive timestamp", () => {
    for (const field of ["event_id", "tenant_id", "type", "occurred_at", "recorded_at", "asset_ids", "payload", "signatures", "held"]) {
      const doc = event("weighed");
      delete doc[field];
      expect(eventOk(doc), field).toBe(false);
    }
    const unknown = event("weighed");
    unknown.type = "teleported";
    expect(eventOk(unknown)).toBe(false);
    const naive = event("weighed");
    naive.occurred_at = "yesterday";
    expect(eventOk(naive)).toBe(false);
  });
});

describe("REQ-EVENT-002 the signer-count table is exported as typed data and matches the schema", () => {
  it("covers every event type", () => {
    expect(Object.keys(REQUIRED_SIGNERS).sort()).toEqual([...EVENT_TYPES].sort());
    expect(requiredSigners("custody_transferred")).toEqual(REQUIRED_SIGNERS.custody_transferred);
  });

  it("matches the counts and roles in event.schema.json", () => {
    const schema = schemaSigners();
    expect([...schema.keys()].sort()).toEqual([...EVENT_TYPES].sort());
    for (const type of EVENT_TYPES) {
      const rule = REQUIRED_SIGNERS[type];
      expect(schema.get(type), type).toEqual({ min: rule.min, roles: [...rule.roles].sort() });
    }
  });

  it("holds that two signers are required exactly for the two-party events", () => {
    const twoParty = EVENT_TYPES.filter((t) => REQUIRED_SIGNERS[t].min === 2).sort();
    expect(twoParty).toEqual(["custody_transferred", "disposition_final", "record_transferred", "removed", "route_confirmed"]);
    for (const type of twoParty) expect(REQUIRED_SIGNERS[type].roles).toHaveLength(2);
  });
});

const sign = (role: string, n: number): Json => ({
  sig_id: `sig_${n}`,
  party_id: `pty_01JC8K2M4N6P8R0T2V4X6Z8P${String(10 + n)}`,
  key_id: "did:key:z6MkTestKey",
  alg: "EdDSA",
  signed_hash: `sha256:${"a".repeat(64)}`,
  signed_at: "2026-09-20T15:01:00Z",
  role_at_signing: role,
});
const bare = (type: EventType, signatures: Json[], held = false): Json => ({
  "@context": ["https://loopledger.org/schema/v0.1/context.jsonld"],
  "@type": "Event",
  event_id: "evt_01JC8K2M4N6P8R0T2V4X6Z8B90",
  tenant_id: "acme-hospitality",
  asset_ids: ["ast_01JC8K2M4N6P8R0T2V4X6Z8A01"],
  type,
  occurred_at: "2026-09-20T15:00:00Z",
  recorded_at: "2026-09-20T15:00:01Z",
  payload: {},
  held,
  signatures,
});

describe("REQ-EVENT-003 two-party events need two signers", () => {
  const twoParty = EVENT_TYPES.filter((t) => REQUIRED_SIGNERS[t].min === 2);

  it.each(twoParty)("accepts %s with both parties and rejects it with one", (type) => {
    const roles = REQUIRED_SIGNERS[type].roles;
    expect(signatureErrors(bare(type, roles.map((r, i) => sign(r, i))))).toBe(false);
    expect(signatureErrors(bare(type, [sign(roles[0]!, 0)]))).toBe(true);
    expect(signatureErrors(bare(type, [sign(roles[0]!, 0), sign(roles[0]!, 1)]))).toBe(true);
  });

  it("rejects a removed example signed by the crew alone", () => {
    const doc = event("removed");
    doc.signatures = [doc.signatures[0]];
    expect(eventOk(doc)).toBe(false);
  });

  it("requires one signer from the named role for one-party events", () => {
    for (const type of EVENT_TYPES.filter((t) => REQUIRED_SIGNERS[t].min === 1 && REQUIRED_SIGNERS[t].roles.length > 0)) {
      const rule = REQUIRED_SIGNERS[type];
      expect(signatureErrors(bare(type, [sign(rule.roles[0]!, 0)])), type).toBe(false);
      expect(signatureErrors(bare(type, [sign("bystander", 0)])), type).toBe(true);
      expect(signatureErrors(bare(type, [])), type).toBe(true);
    }
  });
});

describe("REQ-EVENT-004 a one-sided custody claim is held", () => {
  it("accepts a custody_transferred with the sender only when held, and rejects it when not held", () => {
    const sender = [sign("sender", 0)];
    expect(signatureErrors(bare("custody_transferred", sender, true))).toBe(false);
    expect(signatureErrors(bare("custody_transferred", sender, false))).toBe(true);
  });

  it("accepts the complete example not held, and requires the held flag on every event", () => {
    expect(eventOk(event("custody_transferred"))).toBe(true);
    const doc = event("custody_transferred");
    delete doc.held;
    expect(eventOk(doc)).toBe(false);
  });
});

describe("REQ-EVENT-005 disposal needs a linked exception and a cause", () => {
  const disposal = (): Json => {
    const doc = event("disposition_final");
    doc.payload = {
      family: "disposal",
      exception_event_id: "evt_01JC8K2M4N6P8R0T2V4X6Z8B91",
      cause: { term: "https://loopledger.org/vocab/cause/no_receiver", design_addressable: false },
    };
    return doc;
  };

  it("accepts a disposal with both, and a recycle with neither", () => {
    expect(eventOk(disposal())).toBe(true);
    expect(eventOk(event("disposition_final"))).toBe(true);
  });

  it("rejects a disposal without the linked exception, and one without a cause", () => {
    const noException = disposal();
    delete noException.payload.exception_event_id;
    expect(eventOk(noException)).toBe(false);
    const noCause = disposal();
    delete noCause.payload.cause;
    expect(eventOk(noCause)).toBe(false);
  });

  it("requires a cause on a disposal_request exception", () => {
    const request = bare("exception_opened", [sign("operator", 0)]);
    request.payload = { exception_id: "exc-1", kind: "disposal_request", owner_party_id: "pty_01JC8K2M4N6P8R0T2V4X6Z8P01" };
    expect(eventOk(request)).toBe(false);
    request.payload.cause = { term: "https://loopledger.org/vocab/cause/no_receiver", design_addressable: false };
    expect(eventOk(request)).toBe(true);
  });
});

describe("REQ-EVENT-006 a design-addressable cause needs photo evidence", () => {
  it("accepts the example, which carries a photo beside a design-addressable cause", () => {
    const doc = event("removed");
    expect(doc.payload.cause.design_addressable).toBe(true);
    expect(eventOk(doc)).toBe(true);
  });

  it("rejects the same event with no evidence, or evidence that is not a photo", () => {
    const none = event("removed");
    delete none.evidence;
    expect(eventOk(none)).toBe(false);
    const ticket = event("removed");
    ticket.evidence[0].kind = "scale_ticket";
    expect(eventOk(ticket)).toBe(false);
  });

  it("does not ask for a photo when the cause is not design-addressable", () => {
    const doc = event("removed");
    delete doc.evidence;
    doc.payload.cause = { term: "https://loopledger.org/vocab/cause/removal_damage", design_addressable: false };
    expect(eventOk(doc)).toBe(true);
  });
});

describe("REQ-EVENT-007 alg is mandatory on signatures", () => {
  it("rejects an event whose signature has no alg, or an empty one", () => {
    const missing = event("weighed");
    delete missing.signatures[0].alg;
    expect(eventOk(missing)).toBe(false);
    const empty = event("weighed");
    empty.signatures[0].alg = "";
    expect(eventOk(empty)).toBe(false);
  });

  it("accepts any named algorithm, so a second suite is an addition", () => {
    const doc = event("weighed");
    doc.signatures[0].alg = "ML-DSA-65";
    expect(eventOk(doc)).toBe(true);
  });

  it("rejects a data-grant signature without alg", () => {
    const grant = copy(booth.data_grants[0]);
    delete grant.signatures[0].alg;
    expect(grantCheck(grant)).toBe(false);
  });
});

describe("REQ-EVENT-008 labor is never keyed to an individual", () => {
  it("accepts per-asset labor with a crew size", () => {
    expect(eventOk(event("removed"))).toBe(true);
    expect(eventOk(event("processed"))).toBe(true);
    expect(eventOk(event("maintained"))).toBe(true);
  });

  it("rejects a worker id on removed, processed and maintained", () => {
    for (const type of ["removed", "processed", "maintained"]) {
      const doc = event(type);
      doc.payload.worker_id = "pty_01JC8K2M4N6P8R0T2V4X6Z8P02";
      expect(eventOk(doc), type).toBe(false);
    }
  });

  it("rejects labor given per person, and a joint outcome with a person on it", () => {
    const perPerson = event("processed");
    perPerson.payload.labor_min = { pty_01JC8K2M4N6P8R0T2V4X6Z8P02: 30, pty_01JC8K2M4N6P8R0T2V4X6Z8P03: 25 };
    expect(eventOk(perPerson)).toBe(false);
    const joint = event("removed");
    joint.payload.joints_opened[0].worked_by = "pty_01JC8K2M4N6P8R0T2V4X6Z8P02";
    expect(eventOk(joint)).toBe(false);
  });
});

describe("REQ-EVENT-009 labor, joint outcomes and weighed fractions on removed and processed", () => {
  it("rejects a joint outcome outside clean, damaged and destroyed", () => {
    for (const type of ["removed", "processed"]) {
      const doc = event(type);
      doc.payload.joints_opened[0].outcome = "broken";
      expect(eventOk(doc), type).toBe(false);
    }
  });

  it("rejects a fraction that is not tied to a weighed event", () => {
    const doc = event("processed");
    delete doc.payload.fractions[0].weighed_event;
    expect(eventOk(doc)).toBe(false);
  });

  it("requires removal method and crew size, and processed before and after evidence references", () => {
    const removed = event("removed");
    delete removed.payload.crew_size;
    expect(eventOk(removed)).toBe(false);
    const processed = event("processed");
    processed.payload.after_refs = [];
    expect(eventOk(processed)).toBe(false);
  });

  it("requires a separate operation to name the component assets it births", () => {
    const doc = event("processed");
    delete doc.payload.child_asset_ids;
    expect(eventOk(doc)).toBe(false);
    const born = event("asset_born");
    born.payload.source = "separation";
    expect(eventOk(born)).toBe(false);
    born.payload.parent_asset = "ast_01JC8K2M4N6P8R0T2V4X6Z8A01";
    expect(eventOk(born)).toBe(true);
  });
});

describe("REQ-EVENT-010 carrier_attached, maintained and record_transferred payloads", () => {
  it("rejects carrier_attached without a GS1 Digital Link carrier", () => {
    const doc = event("carrier_attached");
    doc.payload.carrier.digital_link = "https://id.example.com/BTH2S000101";
    expect(eventOk(doc)).toBe(false);
  });

  it("rejects record_transferred without the receiving owner or with an unknown access level", () => {
    const to = event("record_transferred");
    delete to.payload.to_owner_party_id;
    expect(eventOk(to)).toBe(false);
    const access = event("record_transferred");
    access.payload.access = "admin";
    expect(eventOk(access)).toBe(false);
  });

  it("rejects maintained with an unknown operation", () => {
    const doc = event("maintained");
    doc.payload.operation = "polished";
    expect(eventOk(doc)).toBe(false);
  });
});
