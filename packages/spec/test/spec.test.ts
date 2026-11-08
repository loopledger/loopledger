import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import jsonld from "jsonld";
import { describe, expect, it } from "vitest";
import { BIO_BASED_MATERIALS, EVENT_TYPES, REQUIRED_SIGNERS, UNTP_VC_PROFILE_VERSION, VC_CONTEXT_V2, VC_MEDIA_TYPE, buildCredential, catalogErrors, credentialErrors, didWebUrl, dispositionClassificationErrors, dispositionFamilyErrors, dispositionSeparationErrors, isBioBased, requiredSigners,signerBindingErrors, validateEvent, validateEventSet } from "../src/index";
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
const event = (type: string, nth = 0): Json => structuredClone(events.filter((e) => e.event_type === type)[nth]);
const copy = (doc: Json): Json => structuredClone(doc);

// An independent check of the detached JWS, written from packages/spec/README.md (Signatures) alone: it shares no code
// with the ledger.
const jcs = (v: Json): string => {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(jcs).join(",")}]`;
  const keys = Object.keys(v).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(v[k])}`).join(",")}}`;
};
const header = (s: Json): Json => JSON.parse(Buffer.from(s.signature.split(".")[0], "base64url").toString());
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/** The 32-byte Ed25519 public key of a `did:key:z6Mk…` identifier (multibase base58btc, multicodec 0xed01). */
const didKeyPublic = (kid: string): Buffer => {
  let n = 0n;
  for (const c of kid.slice("did:key:z".length)) n = n * 58n + BigInt(B58.indexOf(c));
  const bytes = Buffer.from(n.toString(16).padStart(68, "0"), "hex");
  expect([...bytes.subarray(0, 2)]).toEqual([0xed, 0x01]);
  return bytes.subarray(2);
};
const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");
/** The signed event or grant: the document without `signatures` and `held`. */
const subject = (doc: Json): Json => {
  const { signatures: _s, held: _h, ...rest } = doc;
  return rest;
};
const jwsVerifies = (doc: Json, s: Json): boolean => {
  const [h, payload, value] = s.signature.split(".");
  const body = jcs({
    event: subject(doc),
    evidence_hashes: (doc.evidence ?? []).map((e: Json) => e.content_hash).sort(),
    party_id: s.party_id,
    role_at_signing: s.role_at_signing,
    signed_at: s.signed_at,
  });
  const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519, didKeyPublic(s.key_id)]), format: "der", type: "spki" });
  return payload === "" && h === Buffer.from(jcs({ alg: s.alg, kid: s.key_id })).toString("base64url") && verify(null, Buffer.from(`${h}.${Buffer.from(body).toString("base64url")}`), key, Buffer.from(value, "base64url"));
};

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
    const type = entry.if.properties.event_type;
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
    expect(events.map((e) => e.event_type)).toContain("record_transferred");
    expect(events.map((e) => e.event_type)).toContain("carrier_attached");
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
    const badSet = copy(events);
    badSet.find((e: Json) => e.event_type === "processed" && e.payload.fractions).payload.fractions[0].mass_kg = 1;
    expect(validateEventSet(badSet)).not.toEqual([]);
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
    const { supersedes, ...own } = booth.catalog_ref;
    expect(g5.catalog_ref.supersedes).toEqual({ manufacturer: own.manufacturer, model_reference: own.model_reference, version: own.version });
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

describe("REQ-PASSPORT-009 a catalog revision is keyed by manufacturer, model reference and version", () => {
  const g5 = read("examples/booth-2s-g5.passport.json");
  const born = (): Json => event("asset_born");
  const ref = (doc: Json): Json => doc.catalog_ref;

  it("validates the G3, G4 and G5 lineage as versions 1, 2 and 3 of one model reference, with no check errors", () => {
    expect([ref(g5).supersedes.version, ref(booth).version, ref(g5).version]).toEqual([2, 2, 3]);
    expect(ref(booth).supersedes.version).toBe(1);
    expect(ref(booth).model_reference).toBe(ref(g5).model_reference);
    expect(ref(booth).manufacturer.party_id).toBe(booth.manufacturer.party_id);
    expect(catalogErrors(booth)).toEqual([]);
    expect(catalogErrors(g5)).toEqual([]);
    expect(catalogErrors(born())).toEqual([]);
    expect(eventOk(born())).toBe(true);
  });

  it("requires a manufacturer party_id and a model_reference, and drops catalog_id", () => {
    for (const field of ["manufacturer", "model_reference", "version"]) {
      const doc = copy(booth);
      delete doc.catalog_ref[field];
      expect(passportOk(doc), field).toBe(false);
      const e = born();
      delete e.payload.catalog_ref[field];
      expect(eventOk(e), field).toBe(false);
    }
    const doc = copy(booth);
    doc.catalog_ref.catalog_id = "BTH-2S";
    expect(passportOk(doc)).toBe(false);
    const named = copy(booth);
    named.catalog_ref.manufacturer = { party_id: "Booth Makers" };
    expect(passportOk(named)).toBe(false);
    const withName = copy(booth);
    withName.catalog_ref.manufacturer.name = "Booth Makers Ltd.";
    expect(passportOk(withName)).toBe(false);
  });

  it("takes article_number and gtin as optional, and rejects a malformed gtin or an empty article number", () => {
    const bare = copy(g5);
    delete bare.catalog_ref.article_number;
    expect(passportOk(bare)).toBe(true);
    for (const [field, value] of [["gtin", "BTH-2S"], ["gtin", "123"], ["article_number", ""], ["version", 0]] as const) {
      const doc = copy(booth);
      doc.catalog_ref[field] = value;
      expect(passportOk(doc), `${field} ${value}`).toBe(false);
    }
  });

  it("rejects a supersedes that is a label and not a typed ref", () => {
    const doc = copy(g5);
    doc.catalog_ref.supersedes = "G4";
    expect(passportOk(doc)).toBe(false);
    const half = copy(g5);
    delete half.catalog_ref.supersedes.model_reference;
    expect(passportOk(half)).toBe(false);
  });

  it("rejects a version that goes backwards or stands still along supersedes, in a passport and an event", () => {
    for (const version of [3, 4]) {
      const doc = copy(g5);
      doc.catalog_ref.supersedes.version = version;
      expect(catalogErrors(doc), String(version)).toEqual(["catalog_ref: supersedes must name a lower version"]);
    }
    const e = born();
    e.payload.catalog_ref.supersedes = { ...e.payload.catalog_ref, version: 3 };
    expect(catalogErrors(e)).toEqual(["payload.catalog_ref: supersedes must name a lower version"]);
  });

  it("rejects a supersedes of another manufacturer or another model reference, in a component too", () => {
    const maker = copy(g5);
    maker.catalog_ref.supersedes.manufacturer.party_id = "pty_01JC8K2M4N6P8R0T2V4X6Z8P99";
    expect(passportOk(maker)).toBe(true);
    expect(catalogErrors(maker)).toEqual(["catalog_ref: supersedes names another manufacturer"]);
    const model = copy(g5);
    model.catalog_ref.supersedes.model_reference = "BTH-3S";
    expect(catalogErrors(model)).toEqual(["catalog_ref: supersedes names another model_reference"]);
    const part = copy(g5);
    part.components[0].catalog_ref = copy(g5.catalog_ref);
    part.components[0].catalog_ref.supersedes.version = 3;
    expect(passportOk(part)).toBe(true);
    expect(catalogErrors(part)).toEqual(["components[0].catalog_ref: supersedes must name a lower version"]);
  });

  it("keeps two manufacturers' revisions with the same model reference and label distinct by their keys", () => {
    const other = copy(booth);
    other.catalog_ref.manufacturer.party_id = "pty_01JC8K2M4N6P8R0T2V4X6Z8P99";
    other.catalog_ref.supersedes.manufacturer.party_id = "pty_01JC8K2M4N6P8R0T2V4X6Z8P99";
    expect(passportOk(other)).toBe(true);
    expect(catalogErrors(other)).toEqual([]);
    expect(other.revision.label).toBe(booth.revision.label);
    expect(other.catalog_ref.manufacturer).not.toEqual(booth.catalog_ref.manufacturer);
  });

  it("documents the Pset_ManufacturerTypeInformation mapping in the schema", () => {
    const comment: string = passportSchema.$defs.catalog_revision_ref.$comment;
    for (const name of ["Manufacturer", "ModelReference", "ArticleNumber", "GlobalTradeItemNumber"]) expect(comment).toContain(name);
    expect(passportSchema.$defs.catalog_revision_ref.properties).not.toHaveProperty("catalog_id");
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
    doc.joints[0].type = "https://loopledger.org/vocab/joint_type/not_yet_published";
    expect(passportOk(doc)).toBe(true);
  });
});

const CONTEXT_URLS = {
  epcis: "https://ref.gs1.org/standards/epcis/epcis-context.jsonld",
  vc: "https://www.w3.org/ns/credentials/v2",
  ll: "https://loopledger.org/schema/v0.1/context.jsonld",
};
const CONTEXT_FILES: Record<string, string> = {
  [CONTEXT_URLS.epcis]: "test/fixtures/contexts/epcis-context.jsonld",
  [CONTEXT_URLS.vc]: "test/fixtures/contexts/credentials-v2.jsonld",
  [CONTEXT_URLS.ll]: "schema/context.jsonld",
};
/** Serves the vendored contexts and the local one; any other URL fails, so nothing reaches the network. */
const documentLoader = async (url: string) => {
  const file = CONTEXT_FILES[url];
  if (file === undefined) throw new Error(`context ${url} is not vendored`);
  return { contextUrl: undefined, documentUrl: url, document: read(file) };
};
const expand = (doc: Json, contexts: string[]): Promise<Json[]> =>
  jsonld.expand({ ...doc, "@context": contexts }, { documentLoader }) as Promise<Json[]>;
const ALONGSIDE = [CONTEXT_URLS.epcis, CONTEXT_URLS.vc, CONTEXT_URLS.ll];
const LL = "https://loopledger.org/ns/v0.1#";
const ids = (nodes: Json[] | undefined): string[] => (nodes ?? []).map((n) => n["@id"]);

describe("REQ-SPEC-004 the context expands alongside the EPCIS 2.0 and VC v2 contexts", () => {
  it("expands a passport after both contexts without a protected-term error, and joint type, material and external refs are IRIs", async () => {
    const doc = copy(booth);
    doc.components[0].external_refs = ["https://identifier.buildingsmart.org/uri/buildingsmart/ifc/4.3/class/IfcBeam"];
    const [node] = await expand(doc, ALONGSIDE);
    const joints: Json[] = node[`${LL}joints`];
    expect(joints.map((j) => ids(j[`${LL}joint_type`])[0])).toEqual(booth.joints.map((j: Json) => j.type));
    expect(joints.every((j) => j["@type"] === undefined && j[`${LL}event_type`] === undefined)).toBe(true);
    const components: Json[] = node[`${LL}components`];
    expect(components.map((c) => ids(c[`${LL}material`])[0])).toEqual(booth.components.map((c: Json) => c.material));
    expect(ids(components[0][`${LL}external_refs`])).toEqual(doc.components[0].external_refs);
    expect(ids(node[`${LL}carrier`]?.[0]?.[`${LL}digital_link`])).toEqual([booth.carrier.digital_link]);
  });

  it("expands an event after both contexts, with the event type as plain text under event_type", async () => {
    const [node] = await expand(event("removed"), ALONGSIDE);
    expect(node["@type"]).toEqual([`${LL}Event`]);
    expect(node[`${LL}event_type`]).toEqual([{ "@value": "removed" }]);
  });

  it("expands the same way with the context alone", async () => {
    const [node] = await expand(copy(booth), [CONTEXT_URLS.ll]);
    expect(ids(node[`${LL}joints`][0][`${LL}joint_type`])).toEqual([booth.joints[0].type]);
  });

  it("loads the local context from a loader that refuses every URL it does not vendor", async () => {
    await expect(documentLoader("https://example.com/other.jsonld")).rejects.toThrow("not vendored");
  });
});

describe("REQ-SPEC-005 one IRI form per vocabulary term, the unversioned term IRI", () => {
  it("rejects the versioned form in joint type, material and cause", () => {
    const joint = copy(booth);
    joint.joints[0].type = "https://loopledger.org/vocab/joint_type/v0.1/bolted";
    expect(passportOk(joint)).toBe(false);
    const material = copy(booth);
    material.components[0].material = "https://loopledger.org/vocab/material/v0.1/foam";
    expect(passportOk(material)).toBe(false);
    const cause = event("removed");
    cause.payload.cause.term = "https://loopledger.org/vocab/cause/v0.1/bonded_joint";
    expect(eventOk(cause)).toBe(false);
  });

  it("accepts the unversioned form", () => {
    const material = copy(booth);
    material.components[0].material = "https://loopledger.org/vocab/material/foam";
    expect(passportOk(material)).toBe(true);
  });
});

describe("REQ-EVENT-001 envelope and a typed payload for every event type", () => {
  it("lists every taxonomy event type in the envelope enum", () => {
    expect([...eventSchema.properties.event_type.enum].sort()).toEqual([...EVENT_TYPES].sort());
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
    for (const field of ["event_id", "tenant_id", "event_type", "occurred_at", "recorded_at", "asset_ids", "payload", "signatures", "held"]) {
      const doc = event("weighed");
      delete doc[field];
      expect(eventOk(doc), field).toBe(false);
    }
    const unknown = event("weighed");
    unknown.event_type = "teleported";
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
  signature: "aGVhZGVy..c2lnbmF0dXJl",
});
const bare = (type: EventType, signatures: Json[], held = false): Json => ({
  "@context": ["https://loopledger.org/schema/v0.1/context.jsonld"],
  "@type": "Event",
  event_id: "evt_01JC8K2M4N6P8R0T2V4X6Z8B90",
  tenant_id: "acme-hospitality",
  asset_ids: ["ast_01JC8K2M4N6P8R0T2V4X6Z8A01"],
  event_type: type,
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

const PARTY_A = "pty_01JC8K2M4N6P8R0T2V4X6Z8P21";
const PARTY_B = "pty_01JC8K2M4N6P8R0T2V4X6Z8P22";
const asParty = (role: string, party: string, key = "did:key:z6MkTestKey"): Json => ({ ...sign(role, 0), party_id: party, key_id: key });
const bindingErrors = (doc: Json): string[] => signerBindingErrors(doc.event_type, doc.payload, doc.signatures);

describe("REQ-EVENT-014 signers are the payload parties", () => {
  const payloads: Record<string, Json> = {
    custody_transferred: { from_party_id: PARTY_A, to_party_id: PARTY_B },
    record_transferred: { from_owner_party_id: PARTY_A, to_owner_party_id: PARTY_B },
    route_confirmed: { receiver_party_id: PARTY_B },
  };

  it.each(Object.keys(payloads))("accepts %s signed by the payload parties", (type) => {
    const doc = bare(type as EventType, []);
    doc.payload = payloads[type];
    const [first, second] = REQUIRED_SIGNERS[type as EventType].roles;
    const parties: Record<string, string> = { sender: PARTY_A, transferring_owner: PARTY_A, receiver: PARTY_B, receiving_owner: PARTY_B, operator: PARTY_A };
    doc.signatures = [asParty(first!, parties[first!]!), asParty(second!, parties[second!]!)];
    expect(bindingErrors(doc)).toEqual([]);
  });

  it.each(Object.keys(payloads))("rejects %s when a bound role is signed by another party", (type) => {
    const doc = bare(type as EventType, []);
    doc.payload = payloads[type];
    const [first, second] = REQUIRED_SIGNERS[type as EventType].roles;
    doc.signatures = [asParty(first!, "pty_01JC8K2M4N6P8R0T2V4X6Z8P23"), asParty(second!, "pty_01JC8K2M4N6P8R0T2V4X6Z8P24")];
    expect(bindingErrors(doc).length).toBeGreaterThan(0);
  });

  it("rejects a custody_transferred signed by the wrong sender when the receiver is right", () => {
    const doc = bare("custody_transferred", [asParty("sender", PARTY_B), asParty("receiver", PARTY_B)]);
    doc.payload = payloads.custody_transferred;
    expect(bindingErrors(doc)).toContain("sender signer is not payload from_party_id");
  });

  it("holds the spec example events to the rule", () => {
    for (const doc of events.filter((e) => REQUIRED_SIGNERS[e.event_type as EventType].min === 2)) expect(bindingErrors(doc), doc.event_id).toEqual([]);
  });

  it("skips a held event with one signature", () => {
    const doc = bare("custody_transferred", [asParty("sender", PARTY_A)], true);
    doc.payload = payloads.custody_transferred;
    expect(bindingErrors(doc)).toEqual([]);
  });
});

describe("REQ-EVENT-015 the two signers of a two-party event are distinct parties (REQ-EVENT-003)", () => {
  const twoParty = EVENT_TYPES.filter((t) => REQUIRED_SIGNERS[t].min === 2);

  it.each(twoParty)("rejects %s signed twice by one party, even with different keys", (type) => {
    const [first, second] = REQUIRED_SIGNERS[type].roles;
    const doc = bare(type, [asParty(first!, PARTY_A, "did:key:z6MkOne"), asParty(second!, PARTY_A, "did:key:z6MkTwo")]);
    expect(bindingErrors(doc)).toContain("two roles are signed by the same party");
  });

  it("accepts removed and disposition_final signed by two parties", () => {
    for (const type of ["removed", "disposition_final"] as const) {
      const [first, second] = REQUIRED_SIGNERS[type].roles;
      expect(bindingErrors(bare(type, [asParty(first!, PARTY_A), asParty(second!, PARTY_B)])), type).toEqual([]);
    }
  });
});

const PLYWOOD = "https://loopledger.org/vocab/material/plywood";
const FACILITY = "pty_01JC8K2M4N6P8R0T2V4X6Z8P03";
const line = (route: string, material = PLYWOOD, mass_kg = 66.9, classification?: Json[]): Json => ({
  material,
  mass_kg,
  route,
  ...(classification ? { classification } : {}),
  facility_party_id: FACILITY,
  end_of_waste: false,
});
const eu = (code: string): Json => ({ scheme: "eu-wfd-2008-98", code });

describe("REQ-EVENT-005 a line with a disposal route needs a linked exception and a cause", () => {
  const disposal = (): Json => {
    const doc = event("disposition_final");
    doc.payload = {
      family: "disposal",
      lines: [line("disposal")],
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

  it("requires them for any disposal line, even when the family is another route", () => {
    const doc = event("disposition_final");
    doc.payload.lines.push(line("disposal", "https://loopledger.org/vocab/material/vinyl", 10));
    expect(eventOk(doc)).toBe(false);
    doc.payload.exception_event_id = "evt_01JC8K2M4N6P8R0T2V4X6Z8B91";
    doc.payload.cause = { term: "https://loopledger.org/vocab/cause/no_receiver", design_addressable: false };
    expect(eventOk(doc)).toBe(true);
  });
});

describe("REQ-EVENT-016 a disposition carries per-fraction lines", () => {
  it("accepts the example, whose line has material, mass, route, classification, facility and end-of-waste flag", () => {
    const doc = event("disposition_final");
    expect(eventOk(doc)).toBe(true);
    expect(Object.keys(doc.payload.lines[0]).sort()).toEqual(["classification", "end_of_waste", "facility_party_id", "mass_kg", "material", "route"]);
    expect(dispositionFamilyErrors(doc.payload)).toEqual([]);
  });

  it("rejects a payload without lines, with none, or with a line missing a field", () => {
    const none = event("disposition_final");
    delete none.payload.lines;
    expect(eventOk(none)).toBe(false);
    const empty = event("disposition_final");
    empty.payload.lines = [];
    expect(eventOk(empty)).toBe(false);
    for (const field of ["material", "mass_kg", "route", "facility_party_id", "end_of_waste"]) {
      const doc = event("disposition_final");
      delete doc.payload.lines[0][field];
      expect(eventOk(doc), field).toBe(false);
    }
  });

  it("accepts each of the six routes and rejects any other, including an EU code", () => {
    const ok = (route: string): boolean => {
      const doc = event("disposition_final");
      doc.payload.lines = [line(route)];
      doc.payload.exception_event_id = "evt_01JC8K2M4N6P8R0T2V4X6Z8B91";
      doc.payload.cause = { term: "https://loopledger.org/vocab/cause/no_receiver", design_addressable: false };
      return eventOk(doc);
    };
    for (const route of ["redeploy", "resale", "donate", "recycle", "recovery", "disposal"]) expect(ok(route), route).toBe(true);
    for (const route of ["reuse", "R3", "D10", "Recycle", ""]) expect(ok(route), route).toBe(false);
  });

  it("has no rd_code field any more", () => {
    const doc = event("disposition_final");
    doc.payload.lines[0].rd_code = "R3";
    expect(eventOk(doc)).toBe(false);
  });

  it("rejects a line without a facility party, with a negative mass or an unknown field", () => {
    for (const change of [{ facility_party_id: "HUB1" }, { mass_kg: -1 }, { end_of_waste: "yes" }, { extra: 1 }]) {
      const doc = event("disposition_final");
      Object.assign(doc.payload.lines[0], change);
      expect(eventOk(doc), JSON.stringify(change)).toBe(false);
    }
  });

  it("names recovery as its own family and compares each line's route directly", () => {
    const doc = event("disposition_final");
    doc.payload.family = "recovery";
    doc.payload.lines = [line("recovery")];
    expect(eventOk(doc)).toBe(true);
    expect(dispositionFamilyErrors(doc.payload)).toEqual([]);
  });

  it("rejects a family that is not the route of the heaviest line", () => {
    const payload = { family: "disposal", lines: [line("recycle", PLYWOOD, 60), line("recovery", "https://loopledger.org/vocab/material/vinyl", 6)] };
    expect(dispositionFamilyErrors(payload)).toHaveLength(1);
    expect(dispositionFamilyErrors({ ...payload, family: "recycle" })).toEqual([]);
    expect(dispositionFamilyErrors({ ...payload, family: "redeploy" })).toHaveLength(1);
    // a tie accepts either route
    const tie = { lines: [line("recycle", PLYWOOD, 5), line("recovery", "https://loopledger.org/vocab/material/vinyl", 5)] };
    expect(dispositionFamilyErrors({ ...tie, family: "recovery" })).toEqual([]);
    expect(dispositionFamilyErrors({ ...tie, family: "recycle" })).toEqual([]);
    expect(dispositionFamilyErrors({ ...tie, family: "disposal" })).toHaveLength(1);
  });
});

describe("REQ-EVENT-020 a line's classification is a scheme and code, checked only for a known scheme", () => {
  const withClass = (route: string, ...classification: Json[]): Json => {
    const doc = event("disposition_final");
    doc.payload.family = route;
    doc.payload.lines = [line(route, PLYWOOD, 66.9, classification)];
    doc.payload.exception_event_id = "evt_01JC8K2M4N6P8R0T2V4X6Z8B91";
    doc.payload.cause = { term: "https://loopledger.org/vocab/cause/no_receiver", design_addressable: false };
    return doc;
  };

  it("accepts a line with no classification, and several, even under one scheme", () => {
    const doc = event("disposition_final");
    delete doc.payload.lines[0].classification;
    expect(eventOk(doc)).toBe(true);
    expect(eventOk(withClass("recycle", eu("R3"), eu("R4"), { scheme: "ewc", code: "17 02 01" }))).toBe(true);
  });

  it("pattern-checks the eu-wfd-2008-98 code: R1 to R13 and D1 to D15 only", () => {
    for (let n = 1; n <= 13; n++) expect(eventOk(withClass("recycle", eu(`R${n}`))), `R${n}`).toBe(true);
    for (let n = 1; n <= 15; n++) expect(eventOk(withClass("disposal", eu(`D${n}`))), `D${n}`).toBe(true);
    for (const code of ["R0", "R14", "D0", "D16", "R01", "r3", "R3 ", "X1", ""]) expect(eventOk(withClass("recycle", eu(code))), code).toBe(false);
  });

  it("does not pattern-check a code under an unknown scheme", () => {
    expect(eventOk(withClass("recycle", { scheme: "us-epa-rcra", code: "anything at all" }))).toBe(true);
    expect(eventOk(withClass("recycle", { scheme: "us-epa-rcra", code: "" }))).toBe(false);
  });

  it("requires a lowercase slug scheme and rejects an unknown field", () => {
    for (const scheme of ["EU", "1eu", "eu_wfd", "eu wfd", ""]) expect(eventOk(withClass("recycle", { scheme, code: "R3" })), scheme).toBe(false);
    expect(eventOk(withClass("recycle", { scheme: "ewc", code: "x", extra: 1 }))).toBe(false);
    expect(eventOk(withClass("recycle", { scheme: "ewc" }))).toBe(false);
  });

  it("rejects a known scheme's code that contradicts the route", () => {
    const errors = (route: string, code: string): string[] => dispositionClassificationErrors({ lines: [line(route, PLYWOOD, 1, [eu(code)])] });
    expect(errors("recovery", "R1")).toEqual([]);
    expect(errors("disposal", "D10")).toEqual([]);
    for (const route of ["redeploy", "resale", "donate", "recycle"]) {
      for (let n = 2; n <= 13; n++) expect(errors(route, `R${n}`), `${route} R${n}`).toEqual([]);
      expect(errors(route, "R1"), `${route} R1`).toHaveLength(1);
      expect(errors(route, "D1"), `${route} D1`).toHaveLength(1);
    }
    for (const route of ["recovery", "disposal"]) expect(errors(route, "R3"), `${route} R3`).toHaveLength(1);
    expect(errors("recovery", "D5")).toHaveLength(1);
    expect(errors("disposal", "R1")).toHaveLength(1);
  });

  it("does not read a code under an unknown scheme against the route", () => {
    expect(dispositionClassificationErrors({ lines: [line("recycle", PLYWOOD, 1, [{ scheme: "ewc", code: "D10" }])] })).toEqual([]);
  });
});

describe("REQ-EVENT-017 a redeploy, resale, donate or recycle line for a fraction never separated is rejected", () => {
  const VINYL = "https://loopledger.org/vocab/material/vinyl";
  const processed = events.find((e) => e.event_type === "processed" && e.payload.operation === "separate")!;

  it("accepts the example, whose plywood was separated by the processed event that birthed the asset", () => {
    const doc = event("disposition_final");
    expect(processed.payload.child_asset_ids).toContain(doc.asset_ids[0]);
    expect(dispositionSeparationErrors(doc.payload, [processed.payload])).toEqual([]);
  });

  it("rejects a recycle or reuse line for a material no processed event names", () => {
    for (const route of ["redeploy", "resale", "donate", "recycle"]) {
      expect(dispositionSeparationErrors({ lines: [line(route, VINYL)] }, [processed.payload]), route).toHaveLength(1);
    }
    expect(dispositionSeparationErrors({ lines: [line("recycle")] }, [])).toHaveLength(1);
  });

  it("accepts recovery and disposal for a fraction that was never separated", () => {
    expect(dispositionSeparationErrors({ lines: [line("recovery", VINYL), line("disposal", VINYL)] }, [processed.payload])).toEqual([]);
  });

  it("matches the material term exactly", () => {
    const other = { fractions: [{ material: `${PLYWOOD}_birch`, mass_kg: 1, weighed_event: "evt_01JC8K2M4N6P8R0T2V4X6Z8B09" }] };
    expect(dispositionSeparationErrors({ lines: [line("recycle")] }, [other])).toHaveLength(1);
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

describe("REQ-EVENT-007 alg is mandatory on signatures and is EdDSA", () => {
  it("rejects an event whose signature has no alg, or an empty one", () => {
    const missing = event("weighed");
    delete missing.signatures[0].alg;
    expect(eventOk(missing)).toBe(false);
    const empty = event("weighed");
    empty.signatures[0].alg = "";
    expect(eventOk(empty)).toBe(false);
  });

  it("accepts EdDSA only: the legacy Ed25519 string and any other suite are rejected until the enum adds one", () => {
    const doc = event("weighed");
    expect(eventOk(doc)).toBe(true);
    for (const alg of ["Ed25519", "ML-DSA-65"]) {
      doc.signatures[0].alg = alg;
      expect(eventOk(doc), alg).toBe(false);
    }
  });

  it("carries the alg in the JWS protected header, equal to the alg field", () => {
    for (const doc of [...events, ...booth.data_grants]) {
      for (const s of doc.signatures) expect(header(s).alg).toBe(s.alg);
    }
  });

  it("rejects a data-grant signature without alg", () => {
    const grant = copy(booth.data_grants[0]);
    delete grant.signatures[0].alg;
    expect(grantCheck(grant)).toBe(false);
  });
});

describe("REQ-EVENT-012 a signature carries a detached JWS", () => {
  it("requires the signature value, in the shape header..signature", () => {
    const missing = event("weighed");
    delete missing.signatures[0].signature;
    expect(eventOk(missing)).toBe(false);
    for (const bad of ["", "header", "a.b.c", "aGVhZGVy.c2ln", "..c2ln", "aGVhZGVy..", "aGVhZGVy..c2ln=", "aGVhZGVy..c2ln!"]) {
      const doc = event("weighed");
      doc.signatures[0].signature = bad;
      expect(eventOk(doc), bad).toBe(false);
    }
    const grant = copy(booth.data_grants[0]);
    delete grant.signatures[0].signature;
    expect(grantCheck(grant)).toBe(false);
  });

  it("has a protected header that is the JCS of alg and the key_id as kid, in every example", () => {
    for (const doc of [...events, ...booth.data_grants]) {
      for (const s of doc.signatures) {
        expect(s.signature.split(".")[1]).toBe("");
        expect(Buffer.from(s.signature.split(".")[0], "base64url").toString()).toBe(jcs({ alg: s.alg, kid: s.key_id }));
        expect(header(s).kid).toBe(s.key_id);
      }
    }
  });
});

describe("REQ-EVENT-013 the signing input is defined and the examples verify against it", () => {
  it("verifies every example event and data-grant signature with an independent JWS check", () => {
    let checked = 0;
    for (const doc of [...events, ...booth.data_grants]) {
      for (const s of doc.signatures) {
        expect(jwsVerifies(doc, s), s.sig_id).toBe(true);
        checked += 1;
      }
    }
    expect(checked).toBe(16);
  });

  it("keeps signed_hash as the digest of the JCS of the event and its evidence hashes", () => {
    for (const doc of [...events, ...booth.data_grants]) {
      const digest = `sha256:${createHash("sha256").update(jcs({ event: subject(doc), evidence_hashes: (doc.evidence ?? []).map((e: Json) => e.content_hash).sort() })).digest("hex")}`;
      for (const s of doc.signatures) expect(s.signed_hash, s.sig_id).toBe(digest);
    }
  });

  it("stops verifying when the event, the party, the role, the time or the key changes", () => {
    const doc = event("weighed");
    const s = doc.signatures[0];
    expect(jwsVerifies(doc, s)).toBe(true);
    const edited = copy(doc);
    edited.payload = { ...edited.payload, mass_kg: 1 };
    expect(jwsVerifies(edited, s)).toBe(false);
    for (const change of [{ party_id: "pty_01JC8K2M4N6P8R0T2V4X6Z8P99" }, { role_at_signing: "receiver" }, { signed_at: "2030-01-01T00:00:00Z" }, { key_id: events[0].signatures[0].key_id }]) {
      expect(jwsVerifies(doc, { ...s, ...change })).toBe(false);
    }
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

describe("REQ-EVENT-011 a joint outcome carries the joint type and catalog revision as signed, and an optional cause", () => {
  it("accepts the example outcomes, which each carry joint_type and catalog_ref", () => {
    for (const type of ["removed", "processed"]) {
      const doc = event(type);
      expect(doc.payload.joints_opened.every((j: Json) => j.joint_type && j.catalog_ref), type).toBe(true);
      expect(eventOk(doc), type).toBe(true);
    }
  });

  it("rejects an outcome with no joint_type or no catalog_ref, or a joint_type outside the scheme", () => {
    for (const field of ["joint_type", "catalog_ref"]) {
      const doc = event("removed");
      delete doc.payload.joints_opened[0][field];
      expect(eventOk(doc), field).toBe(false);
    }
    const doc = event("removed");
    doc.payload.joints_opened[0].joint_type = "bonded";
    expect(eventOk(doc)).toBe(false);
  });

  it("rejects a catalog_ref that is not a revision ref", () => {
    const doc = event("removed");
    delete doc.payload.joints_opened[0].catalog_ref.model_reference;
    expect(eventOk(doc)).toBe(false);
  });

  it("accepts a design-addressable joint cause with a photo, and rejects it without one", () => {
    const doc = event("removed");
    doc.payload.joints_opened[0].cause = { term: "https://loopledger.org/vocab/cause/bonded_joint", design_addressable: true };
    expect(eventOk(doc)).toBe(true);
    delete doc.payload.cause;
    delete doc.evidence;
    expect(eventOk(doc)).toBe(false);
    doc.evidence = [{ evidence_id: "ev-doc", kind: "doc", content_hash: `sha256:${"a".repeat(64)}`, storage_ref: "cas://a" }];
    expect(eventOk(doc)).toBe(false);
  });

  it("asks for no photo when the joint cause is not design-addressable", () => {
    const doc = event("removed");
    delete doc.payload.cause;
    delete doc.evidence;
    doc.payload.joints_opened[0].cause = { term: "https://loopledger.org/vocab/cause/removal_damage", design_addressable: false };
    expect(eventOk(doc)).toBe(true);
  });
});

describe("REQ-EVENT-018 a fraction's weighed event names its lot and its net mass equals mass_kg", () => {
  const set = (): Json[] => copy(events);
  const fractionOf = (all: Json[]): Json => all.find((e) => e.event_type === "processed" && e.payload.fractions).payload.fractions[0];
  const weighedOf = (all: Json[]): Json => all.find((e) => e.event_id === fractionOf(all).weighed_event);

  it("accepts the example events, where each fraction is weighed on its own lot", () => {
    expect(validateEventSet(set())).toEqual([]);
    expect(weighedOf(set()).asset_ids).toEqual([fractionOf(set()).lot]);
  });

  it("rejects a fraction with no lot in the schema", () => {
    const doc = event("processed");
    delete doc.payload.fractions[0].lot;
    expect(eventOk(doc)).toBe(false);
  });

  it("rejects a fraction whose weighed event is missing from the set or is not a weighed event", () => {
    const missing = set();
    fractionOf(missing).weighed_event = "evt_01JC8K2M4N6P8R0T2V4X6Z8B99";
    expect(validateEventSet(missing)).toHaveLength(1);
    const wrongType = set();
    fractionOf(wrongType).weighed_event = wrongType.find((e) => e.event_type === "removed").event_id;
    expect(validateEventSet(wrongType)).toHaveLength(1);
  });

  it("rejects a weighing of another lot, as the fixture's parent weighing was", () => {
    const parent = set();
    fractionOf(parent).weighed_event = parent.find((e) => e.event_type === "weighed").event_id;
    expect(validateEventSet(parent).join("\n")).toMatch(/does not name lot/);
    const lot = set();
    fractionOf(lot).lot = "ast_01JC8K2M4N6P8R0T2V4X6Z8A09";
    expect(validateEventSet(lot).join("\n")).toMatch(/not one of the child assets/);
  });

  it("rejects a net mass that differs from mass_kg by more than 0.01 kg, and accepts one within it", () => {
    const off = set();
    weighedOf(off).payload.mass_kg = 66.92;
    expect(validateEventSet(off).join("\n")).toMatch(/differs from mass_kg/);
    const near = set();
    weighedOf(near).payload.mass_kg = 66.91;
    expect(validateEventSet(near)).toEqual([]);
  });
});

describe("REQ-EVENT-019 weighed carries tare_kg and uncertainty, and moisture_basis for bio-based fractions", () => {
  it("rejects a weighed event without tare_kg or uncertainty, or with an incomplete uncertainty", () => {
    for (const field of ["tare_kg", "uncertainty"]) {
      const doc = event("weighed");
      delete doc.payload[field];
      expect(eventOk(doc), field).toBe(false);
    }
    const doc = event("weighed");
    delete doc.payload.uncertainty.basis;
    expect(eventOk(doc)).toBe(false);
  });

  it("rejects a moisture_basis with an unknown state", () => {
    const doc = event("weighed", 1);
    expect(doc.payload.moisture_basis.state).toBe("as_received");
    expect(eventOk(doc)).toBe(true);
    doc.payload.moisture_basis.state = "dry";
    expect(eventOk(doc)).toBe(false);
  });

  it("lists wood and plywood as bio-based and rejects a wood fraction whose weighing has no moisture_basis", () => {
    expect(BIO_BASED_MATERIALS).toEqual(["wood", "plywood"]);
    expect(isBioBased("https://loopledger.org/vocab/material/plywood")).toBe(true);
    expect(isBioBased("https://loopledger.org/vocab/material/steel")).toBe(false);
    const all: Json[] = copy(events);
    const fraction = all.find((e) => e.event_type === "processed" && e.payload.fractions).payload.fractions[0];
    delete all.find((e) => e.event_id === fraction.weighed_event).payload.moisture_basis;
    expect(validateEventSet(all).join("\n")).toMatch(/no moisture_basis/);
    fraction.material = "https://loopledger.org/vocab/material/steel";
    expect(validateEventSet(all)).toEqual([]);
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

describe("REQ-EVENT-021 processed records the mass that reached no fraction as residual_kg", () => {
  it("accepts a non-negative residual_kg and rejects a negative or non-numeric one", () => {
    const doc = event("processed");
    doc.payload.residual_kg = 12.5;
    expect(eventOk(doc)).toBe(true);
    doc.payload.residual_kg = -1;
    expect(eventOk(doc)).toBe(false);
    doc.payload.residual_kg = "12";
    expect(eventOk(doc)).toBe(false);
  });
});

describe("REQ-SPEC-006 validateEvent checks an event against the schema, a held draft included", () => {
  it("accepts a published event and a draft row with no signatures, and leaves the input unchanged", () => {
    expect(validateEvent(event("weighed"))).toEqual({ valid: true, errors: [] });
    const { signatures: _s, held: _h, "@context": _c, "@type": _t, ...row } = event("weighed");
    const before = structuredClone(row);
    expect(validateEvent(row)).toEqual({ valid: true, errors: [] });
    expect(row).toEqual(before);
  });

  it("returns an error line for each violation of an invalid event", () => {
    const { signatures: _s, held: _h, "@context": _c, "@type": _t, ...row } = event("weighed");
    const bad = validateEvent({ ...row, event_id: "not-an-id", payload: { ...row.payload, mass_kg: "heavy" } });
    expect(bad.valid).toBe(false);
    expect(bad.errors.length).toBeGreaterThanOrEqual(2);
    expect(bad.errors.join("\n")).toContain("/event_id");
    expect(validateEvent("nope").valid).toBe(false);
    expect(validateEvent(null).valid).toBe(false);
  });
});

const VC = "https://www.w3.org/2018/credentials#";
const credentialOf = (kind: "Event" | "Passport", subject: Json): Json => buildCredential(kind, subject, "did:web:example.org", "2026-11-08T10:00:00Z");
/** The credential as the exporter publishes it: expanded with its own `@context` alone, so only the vendored files load. */
const expandCredential = (credential: Json): Promise<Json[]> => jsonld.expand(credential, { documentLoader }) as Promise<Json[]>;

describe("REQ-SPEC-007 an event exports as a VCDM 2.0 credential secured with VC-JOSE-COSE", () => {
  it("wraps the event verbatim, with the #73 signatures still verifying inside credentialSubject", () => {
    for (const doc of events) {
      const credential = credentialOf("Event", doc);
      expect(credentialErrors(credential)).toEqual([]);
      expect(credential["@context"]).toEqual([VC_CONTEXT_V2, "https://loopledger.org/schema/v0.1/context.jsonld"]);
      expect(credential.type).toEqual(["VerifiableCredential", "Event"]);
      expect(credential.credentialSubject).toEqual(doc);
      for (const s of credential.credentialSubject.signatures) expect(jwsVerifies(credential.credentialSubject, s), s.sig_id).toBe(true);
    }
  });

  it("expands against the VC v2 context without a protected-term error, as a VerifiableCredential with the event as subject", async () => {
    const [node] = await expandCredential(credentialOf("Event", event("removed")));
    expect(node["@type"]).toEqual([`${VC}VerifiableCredential`, `${LL}Event`]);
    expect(ids(node[`${VC}issuer`])).toEqual(["did:web:example.org"]);
    expect(node[`${VC}validFrom`]).toEqual([{ "@value": "2026-11-08T10:00:00Z", "@type": "http://www.w3.org/2001/XMLSchema#dateTime" }]);
    const [subject] = node[`${VC}credentialSubject`];
    expect(subject[`${LL}event_type`]).toEqual([{ "@value": "removed" }]);
  });

  it("fails the protected-term check when a context redefines a VC v2 term", async () => {
    const credential = credentialOf("Event", event("removed"));
    credential["@context"].push({ VerifiableCredential: "https://example.com/not-the-credential" });
    await expect(expandCredential(credential)).rejects.toThrow(/protected/i);
  });

  it("is secured as application/vc+jwt", () => {
    expect(VC_MEDIA_TYPE).toBe("application/vc+jwt");
  });

  it("rejects a credential that is not of this shape, one line per violation", () => {
    const good = credentialOf("Event", event("removed"));
    expect(credentialErrors({ ...good, "@context": [VC_CONTEXT_V2] })).toHaveLength(1);
    expect(credentialErrors({ ...good, type: ["Event"] })).toContain("type is not [VerifiableCredential, Event] or [VerifiableCredential, Passport]");
    expect(credentialErrors({ ...good, type: ["VerifiableCredential", "Passport"] })).toHaveLength(1);
    expect(credentialErrors({ ...good, validFrom: "yesterday" })).toHaveLength(1);
    expect(credentialErrors({ ...good, credentialSubject: "x" })).toHaveLength(1);
    expect(credentialErrors(null)).toEqual(["credential is not an object"]);
  });
});

describe("REQ-SPEC-008 a passport exports as a VCDM 2.0 credential secured with VC-JOSE-COSE", () => {
  it("wraps the passport verbatim, with its data-grant signatures still verifying", () => {
    for (const doc of [booth, seat]) {
      const credential = credentialOf("Passport", doc);
      expect(credentialErrors(credential)).toEqual([]);
      expect(credential.type).toEqual(["VerifiableCredential", "Passport"]);
      expect(credential.credentialSubject).toEqual(doc);
    }
    for (const grant of booth.data_grants) for (const s of grant.signatures) expect(jwsVerifies(grant, s), s.sig_id).toBe(true);
  });

  it("expands against the VC v2 context without a protected-term error, with the passport as subject", async () => {
    const [node] = await expandCredential(credentialOf("Passport", booth));
    expect(node["@type"]).toEqual([`${VC}VerifiableCredential`, `${LL}Passport`]);
    const [subject] = node[`${VC}credentialSubject`];
    expect(ids(subject[`${LL}joints`][0][`${LL}joint_type`])).toEqual([booth.joints[0].type]);
  });
});

describe("REQ-SPEC-009 the issuer is a did:web and the spec defines its resolution", () => {
  it("resolves did:web:host to the well-known document and did:web:host:path to a path document", () => {
    expect(didWebUrl("did:web:example.org")).toBe("https://example.org/.well-known/did.json");
    expect(didWebUrl("did:web:example.org:tenants:acme")).toBe("https://example.org/tenants/acme/did.json");
    expect(didWebUrl("did:web:example.org%3A8443")).toBe("https://example.org:8443/.well-known/did.json");
  });

  it("refuses an issuer that is not a did:web, such as an event signer's did:key", () => {
    const key = events[0].signatures[0].key_id;
    expect(() => didWebUrl(key)).toThrow("not a did:web");
    expect(() => buildCredential("Event", event("removed"), key, "2026-11-08T10:00:00Z")).toThrow("not a did:web");
    expect(credentialErrors({ ...credentialOf("Event", event("removed")), issuer: key })).toEqual(["issuer is not a did:web identifier"]);
  });

  it("documents the resolution and the pinned UNTP profile in the README", () => {
    const readme = readFileSync(join(root, "README.md"), "utf8");
    expect(readme).toContain("## VC-JOSE-COSE envelope");
    expect(readme).toContain("/.well-known/did.json");
    expect(readme).toContain(`UNTP ${UNTP_VC_PROFILE_VERSION}`);
  });
});
