// The drill's synthetic, offline event stream: one catalog item (BTH-2S) in two revisions, G4 (bonded upholstery) and
// G5 (mechanically fastened), each asset taken `removed → processed (separate) → weighed → disposition_final`.
// G4 assets are deliberately older, so a pooled comparison measures age as well as design. Some assets never come back.
//
// Every event is signed with throwaway Ed25519 keys generated when the fixture is built: no key is written to a file.
// The catalog items are read from the example passports in packages/spec, so the drill and the schema agree on them.
import { createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { MemoryEventStore, MemoryEvidenceStore, MemoryKeyResolver } from "@loopledger/adapter-memory";
import { Ledger, eventHash, signingInput } from "@loopledger/ledger";
import type { EventInput } from "@loopledger/ledger";
import type { KeyRecord, SignatureRow } from "@loopledger/ports";
import { catalogRevision } from "../src/catalog";
import type { CatalogRevision } from "../src/catalog";

export const TENANT = "acme-hospitality";

const MATERIAL = "https://loopledger.org/vocab/material/";
const JOINT_TYPE = "https://loopledger.org/vocab/joint_type/";

const CROCKFORD = ["0123456789", "ABCDEFGH", "JKMNPQRST", "VWXYZ"].join("");
/** A prefixed 26-character ULID-shaped id: a fixed head and the counter in Crockford base32. */
const id = (prefix: string, n: number): string => {
  let rest = "";
  for (let v = n; rest.length < 22; v = Math.floor(v / 32)) rest = CROCKFORD.charAt(v % 32) + rest;
  return `${prefix}_01JD${rest}`;
};

const ROLES = ["operator", "crew", "adapter", "facility", "scale", "receiver", "device"] as const;
type Role = (typeof ROLES)[number];

const read = (name: string): Record<string, any> =>
  JSON.parse(readFileSync(new URL(`../../spec/examples/${name}.passport.json`, import.meta.url), "utf8"));

export type AssetKind = "recovered" | "leaked" | "in_service" | "held";

export interface FixtureAsset {
  asset_id: string;
  revision: "G4" | "G5";
  kind: AssetKind;
  life_used_pct?: number;
}

export interface Fixture {
  tenant: string;
  catalog: CatalogRevision[];
  keys: KeyRecord[];
  events: EventInput[];
  assets: FixtureAsset[];
  /** The `removed` event that is held for want of its operator signature. */
  held_event_id: string;
}

export const buildFixture = (): Fixture => {
  const pairs = new Map(ROLES.map((role) => [role, generateKeyPairSync("ed25519")] as const));
  const party = (role: Role): string => id("pty", ROLES.indexOf(role) + 1);
  const keys: KeyRecord[] = ROLES.map((role) => ({
    key_id: `key-${role}`,
    party_id: party(role),
    alg: "Ed25519",
    public_key: createPublicKey(pairs.get(role)!.privateKey).export({ format: "der", type: "spki" }).toString("base64"),
    valid_from: "2018-01-01T00:00:00Z",
    valid_until: "2030-01-01T00:00:00Z",
  }));

  let sigs = 0;
  let seq = 0;
  const events: EventInput[] = [];
  const at = (iso: string, plusMin = 0): string => new Date(Date.parse(iso) + plusMin * 60000).toISOString().replace(".000Z", "Z");
  const emit = (type: string, asset: string, occurred: string, payload: Record<string, unknown>, signers: Role[]): string => {
    const event = { event_id: id("evt", ++seq), tenant_id: TENANT, event_type: type, asset_ids: [asset], occurred_at: occurred, recorded_at: at(occurred, 5), payload };
    const signatures: SignatureRow[] = signers.map((role) => {
      const body = { signed_hash: eventHash(event), party_id: party(role), role_at_signing: role, signed_at: at(occurred, 6) };
      return { sig_id: `sig_${++sigs}`, key_id: `key-${role}`, alg: "Ed25519", ...body, signature: sign(null, signingInput(body), pairs.get(role)!.privateKey).toString("base64") };
    });
    events.push({ ...event, signatures });
    return event.event_id;
  };

  const g4 = catalogRevision(read("booth-2s-g4"));
  const g5 = catalogRevision(read("booth-2s-g5"));
  const assets: FixtureAsset[] = [];
  let nextAsset = 0;
  let nextChild = 0;
  let held_event_id = "";

  const born = (item: CatalogRevision, installed: string, kind: AssetKind, life?: number): string => {
    const asset_id = id("ast", ++nextAsset);
    assets.push({ asset_id, revision: item.label as "G4" | "G5", kind, ...(life === undefined ? {} : { life_used_pct: life }) });
    const catalog_ref = { manufacturer: { party_id: item.manufacturer }, model_reference: item.model_reference, version: item.version };
    emit("asset_born", asset_id, `${installed}T08:00:00Z`, { source: "procurement", catalog_ref, revision: { basis: "declared", label: item.label } }, ["operator"]);
    // An asset in service is one the record still sees: an adapter observed it after the recovery events.
    if (kind === "in_service") emit("observed", asset_id, "2026-11-01T10:00:00Z", { adapter_kind: "bms", location: "SITE1" }, ["adapter"]);
    return asset_id;
  };

  /** A joint outcome as signed: the joint type and catalog revision are those of the revision the asset is recovered as (REQ-EVENT-011). */
  const jointOutcome = (item: CatalogRevision, joint_id: string, outcome: string, labor_min: number) => ({
    joint_id,
    joint_type: `${JOINT_TYPE}${item.joints.find((j) => j.joint_id === joint_id)!.type}`,
    catalog_ref: { manufacturer: { party_id: item.manufacturer }, model_reference: item.model_reference, version: item.version },
    outcome,
    labor_min,
  });

  const MASS_KG = 218;
  // Removal labor is the labor of the joints plus an overhead that grows with the life used, so a pooled comparison
  // adds an age effect to the design effect. Bolted joints cost the same in both revisions.
  const recover = (item: CatalogRevision, installed: string, day: string, i: number, life: number, joints: Record<string, [string, number]>, method: "intact" | "destructive", upholsterySeparated: boolean): void => {
    const asset = born(item, installed, "recovered", life);
    const joints_opened = Object.entries(joints).map(([joint_id, [outcome, labor_min]]) => jointOutcome(item, joint_id, outcome, labor_min));
    const started = `${day}T${String(9 + (i % 4)).padStart(2, "0")}:00:00Z`;
    const labor = joints_opened.reduce((s, j) => s + j.labor_min, 0) + 10 + Math.round(0.3 * life);
    emit("telemetry", asset, at(started, -5), { metric: "life_used_pct", value: life, source_device: "dock-meter-1" }, ["device"]);
    emit("removed", asset, started, { cluster: "dining-room-north", method, started_at: started, ended_at: at(started, labor), crew_size: 2, joints_opened }, ["crew", "operator"]);
    const done = at(started, labor);
    const weighedId = id("evt", seq + 2);
    const wear = 1 - (0.2 * life) / 100;
    // Bonded upholstery is not separated: only the frame and the plywood are weighed out as clean fractions.
    const fractions = [
      { material: `${MATERIAL}steel`, kg: 91.6 },
      { material: `${MATERIAL}plywood`, kg: 87.6 },
      ...(upholsterySeparated ? [{ material: `${MATERIAL}vinyl`, kg: 38.8 }] : []),
    ].map((f) => ({ material: f.material, mass_kg: Math.round(f.kg * wear * 100) / 100, weighed_event: weighedId }));
    const children = [id("ast", 5000 + ++nextChild), id("ast", 5000 + ++nextChild)];
    emit("processed", asset, at(done, 60), { operation: "separate", before_refs: [asset], after_refs: children, labor_min: item.label === "G4" ? 35 : 14, crew_size: 2, fractions, child_asset_ids: children }, ["facility"]);
    const w = emit("weighed", asset, at(done, 90), { mass_kg: MASS_KG, scale_id: "scale-1", certification_id: "cert-2026-01" }, ["scale"]);
    if (w !== weighedId) throw new Error("the weighed event id moved");
    emit("disposition_final", asset, at(done, 120), { family: item.label === "G4" ? "recycle" : "redeploy" }, ["receiver", "operator"]);
  };

  // G4: 14 recovered assets, 12 intact and 2 destructive, installed in 2019 and 52 to 97.5 percent through their life.
  for (let i = 0; i < 14; i++) {
    const life = 52 + 3.5 * i;
    const destructive = i >= 12;
    const outcome = i % 2 === 0 ? "damaged" : "destroyed";
    const bonded: [string, number] = destructive ? ["destroyed", 4] : [outcome, 22 + (i % 3)];
    recover(g4, "2019-03-14", `2026-09-${String(1 + i).padStart(2, "0")}`, i, life, { "j-1": ["clean", 6], "j-2": ["clean", 6], "j-3": bonded, "j-4": bonded }, destructive ? "destructive" : "intact", false);
  }
  for (let i = 0; i < 3; i++) born(g4, "2019-03-14", "leaked");
  born(g4, "2019-03-14", "in_service");

  // G5: 12 recovered assets installed in 2024 and 10 to 65 percent through their life; screwed upholstery comes off clean.
  for (let i = 0; i < 12; i++) {
    const life = 10 + 5 * i;
    recover(g5, "2024-06-02", `2026-10-${String(1 + i).padStart(2, "0")}`, i, life, { "j-1": ["clean", 6], "j-2": ["clean", 6], "j-3": ["clean", 5], "j-4": ["clean", 5] }, "intact", true);
  }
  born(g5, "2024-06-02", "leaked");
  for (let i = 0; i < 2; i++) born(g5, "2024-06-02", "in_service");
  // A G5 asset removed so fast it looks too good: only the crew signed, so the ledger holds it and no figure counts it.
  const heldAsset = born(g5, "2024-06-02", "held");
  held_event_id = emit(
    "removed",
    heldAsset,
    "2026-10-20T09:00:00Z",
    { cluster: "dining-room-north", method: "intact", started_at: "2026-10-20T09:00:00Z", ended_at: "2026-10-20T09:05:00Z", crew_size: 2, joints_opened: [jointOutcome(g5, "j-3", "clean", 1)] },
    ["crew"],
  );

  return { tenant: TENANT, catalog: [g4, g5], keys, events, assets, held_event_id };
};

/** Appends the fixture to a ledger on the in-memory adapters (LL-001). Every signature is verified on the way in. */
export const loadFixture = async (): Promise<{ fixture: Fixture; ledger: Ledger }> => {
  const fixture = buildFixture();
  const resolver = new MemoryKeyResolver();
  for (const key of fixture.keys) resolver.register(key);
  const ledger = new Ledger(new MemoryEventStore(), new MemoryEvidenceStore(), resolver);
  for (const event of fixture.events) await ledger.append(event);
  return { fixture, ledger };
};
