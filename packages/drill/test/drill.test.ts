import { beforeAll, describe, expect, it } from "vitest";
import type { EventRow } from "@loopledger/ports";
import { requiredSigners } from "@loopledger/spec";
import type { EventType } from "@loopledger/spec";
import { attributeDifference, compareWithSuccessor, featurePerformance, plan, revisionPerformance } from "../src/index";
import type { CatalogRevision, Figure, PlanAsset, RevisionRow } from "../src/index";
import { loadFixture } from "../fixtures/index";
import type { Fixture } from "../fixtures/index";
import type { Ledger } from "@loopledger/ledger";

let fixture: Fixture;
let ledger: Ledger;
let events: EventRow[];
let held: EventRow[];
let rows: RevisionRow[];

beforeAll(async () => {
  ({ fixture, ledger } = await loadFixture());
  events = await ledger.projection(fixture.tenant);
  held = await ledger.pending(fixture.tenant);
  rows = revisionPerformance(events, fixture.catalog, { pending: held });
});

const row = (revision: string, band = "pooled") => rows.find((r) => r.revision === revision && r.band === band)!;

/** Every figure under a value: an object with a basis, a leakage and sources. */
const figures = (value: unknown): Figure[] => {
  if (value === null || typeof value !== "object") return [];
  const o = value as Record<string, unknown>;
  if ("basis" in o && "sources" in o) return [o as unknown as Figure];
  return Object.values(o).flatMap(figures);
};

describe("REQ-DRILL-001 G5 beats G4 within a life band and the pooled comparison overstates it", () => {
  it("loads signed fixture events with G4 deliberately older than G5", () => {
    const life = (rev: string) => fixture.assets.filter((a) => a.revision === rev && a.kind === "recovered").map((a) => a.life_used_pct!);
    const mean = (xs: number[]) => xs.reduce((s, x) => s + x, 0) / xs.length;
    expect(mean(life("G4"))).toBeGreaterThan(mean(life("G5")) + 30);
    expect(fixture.events.filter((e) => e.event_type === "removed" && e.asset_ids[0] !== undefined).length).toBeGreaterThanOrEqual(26);
  });

  it("is faster and diverts more in the shared 50-75 band, G4 against its successor G5", () => {
    const g4 = row("G4", "50-75");
    const g5 = row("G5", "50-75");
    expect(g5.removal.intact!.p50.value!).toBeLessThan(g4.removal.intact!.p50.value!);
    expect(g5.diversion_pct.value!).toBeGreaterThan(g4.diversion_pct.value!);

    const cmp = compareWithSuccessor(rows, fixture.catalog, "BTH-2S", "G4");
    expect(cmp.successor).toBe("G5");
    expect(cmp.bands.map((b) => b.band)).toEqual(["50-75"]);
    expect(cmp.within_band.labor_gap_min!).toBeGreaterThan(0);
    expect(cmp.within_band.diversion_gap_pct!).toBeGreaterThan(0);
  });

  it("shows the pooled gap larger than the within-band gap on both measures", () => {
    const cmp = compareWithSuccessor(rows, fixture.catalog, "BTH-2S", "G4");
    expect(cmp.pooled.labor_gap_min!).toBeGreaterThan(cmp.within_band.labor_gap_min!);
    expect(cmp.pooled.diversion_gap_pct!).toBeGreaterThan(cmp.within_band.diversion_gap_pct!);
    expect(cmp.overstatement.labor_min!).toBeGreaterThan(5);
    expect(cmp.overstatement.diversion_pct!).toBeGreaterThan(2);
  });

  it("refuses a comparison with no successor revision", () => {
    expect(() => compareWithSuccessor(rows, fixture.catalog, "BTH-2S", "G5")).toThrow(/no revision/);
  });
});

describe("REQ-DRILL-002 feature performance attributes the difference to the bonded joint", () => {
  it("folds outcomes by joint type and material pair: bonded comes apart badly, screwed and bolted cleanly", () => {
    const features = featurePerformance(events, fixture.catalog);
    const find = (type: string, a: string, b: string) => features.find((f) => f.joint_type === type && f.materials.join("+") === `${a}+${b}`)!;
    const bonded = find("bonded", "plywood", "vinyl");
    const screwed = find("screwed", "plywood", "vinyl");
    const bolted = find("bolted", "plywood", "steel");
    expect(bonded.revisions).toEqual(["G4"]);
    expect(screwed.revisions).toEqual(["G5"]);
    expect(bolted.revisions).toEqual(["G4", "G5"]);
    expect(bonded.clean_rate.value).toBe(0);
    expect(screwed.clean_rate.value).toBe(1);
    expect(bonded.labor_p50.value!).toBeGreaterThan(screwed.labor_p50.value! * 3);
  });

  it("puts the largest share of the labor difference on the bonded joint and none on the bolted ones", () => {
    const shares = attributeDifference(events, fixture.catalog, "BTH-2S", "G4", "G5");
    expect(shares[0]!.joint_type).toBe("bonded");
    expect(shares[0]!.share).toBeGreaterThan(0.5);
    for (const s of shares.filter((x) => x.joint_type === "bolted")) expect(s.difference_min).toBe(0);
  });
});

describe("REQ-DRILL-003 a mixed G4/G5 event plans each asset by its own revision", () => {
  const asset = (n: number, label?: string, method?: "intact" | "destructive"): PlanAsset => ({
    asset_id: `ast_${n}`,
    catalog_id: "BTH-2S",
    revision: label === undefined ? { basis: "unknown" } : { basis: "declared", label },
    ...(method === undefined ? {} : { method }),
  });

  it("times G4 and G5 assets from their own measured cohorts", () => {
    const lines = plan([asset(1, "G4"), asset(2, "G5")], fixture.catalog, rows);
    expect(lines.map((l) => l.revision)).toEqual(["G4", "G5"]);
    expect(lines[0]!.est_labor_min).toBe(row("G4").removal.intact!.p50.value);
    expect(lines[1]!.est_labor_min).toBe(row("G5").removal.intact!.p50.value);
    expect(lines[0]!.est_labor_min).toBeGreaterThan(lines[1]!.est_labor_min);
    expect(lines[0]!.basis).toEqual({ kind: "measured", n: 12 });
    expect(lines[1]!.basis).toEqual({ kind: "measured", n: 12 });
  });

  it("uses the declared figure below n of 10 per revision per method", () => {
    const [destructive] = plan([asset(1, "G4", "destructive")], fixture.catalog, rows);
    expect(destructive).toMatchObject({ method: "destructive", est_labor_min: 30, basis: { kind: "declared" } });
    const small = plan([asset(1, "G4"), asset(2, "G5")], fixture.catalog, rows, 13);
    expect(small.map((l) => [l.est_labor_min, l.basis.kind])).toEqual([[70, "declared"], [40, "declared"]]);
  });

  it("plans an unknown-revision asset as the slowest known revision", () => {
    const [line] = plan([asset(3)], fixture.catalog, rows);
    expect(line).toMatchObject({ revision: "unknown", basis: { kind: "slowest_known_revision", from: "G4" } });
    expect(line!.est_labor_min).toBe(row("G4").removal.intact!.p50.value);
    const [declared] = plan([asset(3)], fixture.catalog, rows, 99);
    expect(declared).toMatchObject({ est_labor_min: 70, basis: { kind: "slowest_known_revision", from: "G4" } });
  });
});

describe("REQ-DRILL-004 leakage is reported beside every rate", () => {
  it("counts born − recovered − known in service per revision, non-zero for both", () => {
    expect(row("G4").leakage).toMatchObject({ born: 18, recovered: 14, in_service: 1, pending: 0, leaked: 3 });
    expect(row("G5").leakage).toMatchObject({ born: 16, recovered: 12, in_service: 2, pending: 1, leaked: 1 });
    expect(row("G4").leakage.rate!).toBeGreaterThan(row("G5").leakage.rate!);
  });

  it("carries the revision's leakage on every figure of every row, banded rows included", () => {
    expect(rows.length).toBeGreaterThan(6);
    for (const r of rows) {
      const all = figures(r);
      expect(all.length).toBeGreaterThan(0);
      for (const f of all) expect(f.leakage).toEqual(r.leakage);
    }
  });

  it("carries leakage on every feature row", () => {
    for (const f of featurePerformance(events, fixture.catalog, held)) {
      for (const fig of figures(f)) expect(fig.leakage.born).toBeGreaterThan(0);
      expect(f.leakage.leaked).toBeGreaterThan(0);
    }
  });
});

describe("REQ-DRILL-006 an asset whose only removal is held counts as pending, not recovered or leaked", () => {
  /** The figures of a row with the leakage taken out, so only rates, counts and sources remain. */
  const bare = (value: unknown): unknown => JSON.parse(JSON.stringify(value, (k, v) => (k === "leakage" ? undefined : v)));
  const without = () => revisionPerformance(events, fixture.catalog);

  it("lists the held removal as pending for G5 and nowhere else", () => {
    expect(held.map((e) => e.event_id)).toEqual([fixture.held_event_id]);
    expect(row("G5").leakage.pending).toBe(1);
    expect(rows.filter((r) => r.revision === "G4").every((r) => r.leakage.pending === 0)).toBe(true);
    expect(featurePerformance(events, fixture.catalog, held).find((f) => f.joint_type === "screwed")!.leakage).toMatchObject({ pending: 1, leaked: 1 });
  });

  it("changes no rate, no count and no source: the held asset moves from leaked to pending only", () => {
    const base = without();
    expect(bare(rows)).toEqual(bare(base));
    rows.forEach((r, i) => {
      const was = base[i]!.leakage;
      expect({ ...r.leakage, pending: 0, leaked: r.leakage.leaked + r.leakage.pending, rate: 0 }).toEqual({ ...was, pending: 0, rate: 0 });
      expect(was.pending).toBe(0);
    });
    expect(row("G5").leakage.leaked + row("G5").leakage.pending).toBe(without().find((r) => r.revision === "G5")!.leakage.leaked);
  });

  it("leaves a held removal out of every feature figure and source", () => {
    const base = featurePerformance(events, fixture.catalog);
    const withHeld = featurePerformance(events, fixture.catalog, held);
    expect(bare(withHeld)).toEqual(bare(base));
    for (const f of withHeld) for (const fig of figures(f)) expect(fig.sources).not.toContain(fixture.held_event_id);
  });

  it("counts an asset with a held removal and an observed event as in service, not pending", async () => {
    const observed = events.find((e) => e.event_type === "observed" && e.asset_ids[0] !== undefined)!;
    const heldAsset = held[0]!.asset_ids[0]!;
    const g5 = revisionPerformance([...events, { ...observed, event_id: "evt_extra", asset_ids: [heldAsset] }], fixture.catalog, { pending: held }).find((r) => r.revision === "G5" && r.band === "pooled")!;
    expect(g5.leakage).toMatchObject({ in_service: 3, pending: 0, leaked: 1 });
  });
});

describe("REQ-DRILL-005 every figure traces to signed events and carries its basis", () => {
  const all = (): Figure[] => [...rows.flatMap(figures), ...featurePerformance(events, fixture.catalog).flatMap(figures)];

  it("names only final events whose signatures meet the signer table", async () => {
    const final = new Set(events.map((e) => e.event_id));
    const sources = new Set(all().flatMap((f) => [...f.sources, ...f.leakage.sources]));
    expect(sources.size).toBeGreaterThan(100);
    for (const id of sources) {
      expect(final.has(id)).toBe(true);
      const read = await ledger.read(fixture.tenant, id);
      expect(read.held).toBe(false);
      expect(read.signatures.length).toBeGreaterThanOrEqual(requiredSigners(read.event_type as EventType).min);
    }
  });

  it("carries a measured n equal to the events behind it, or the declared basis", () => {
    for (const f of all()) {
      if (f.basis.kind === "measured") expect(f.basis.n).toBeGreaterThan(0);
      expect(["measured", "declared"]).toContain(f.basis.kind);
    }
    const removal = row("G4").removal.intact!.p50;
    expect(removal.basis).toEqual({ kind: "measured", n: 12 });
    expect(removal.sources).toHaveLength(12);
  });

  it("reports a revision with no recovered asset on the declared basis", () => {
    const g6: CatalogRevision = { catalog_id: "BTH-2S", revision: "G6", supersedes: "G5", components: [], joints: [], recovery_method: [{ method: "intact", declared_labor_min: 25 }] };
    const next = revisionPerformance(events, [...fixture.catalog, g6]).find((r) => r.revision === "G6")!;
    expect(next.removal.intact!.p50).toMatchObject({ value: 25, basis: { kind: "declared" } });
  });

  it("leaves a held event out of every figure", () => {
    expect(events.some((e) => e.event_id === fixture.held_event_id)).toBe(false);
    expect(fixture.events.some((e) => e.event_id === fixture.held_event_id)).toBe(true);
    const sources = new Set(all().flatMap((f) => f.sources));
    expect(sources.has(fixture.held_event_id)).toBe(false);
    expect(row("G5").removal.intact!.p50.basis).toEqual({ kind: "measured", n: 12 });
  });
});
