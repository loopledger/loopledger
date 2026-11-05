// REVISION_PERFORMANCE and FEATURE_PERFORMANCE as pure functions of the log (SPEC-data-model.md §4).
// The input is `Ledger.projection(tenant)`: final events only, so a held event is in no figure (REQ-LEDGER-002).
// `Ledger.pending(tenant)` is optional and only marks assets whose removal is held (REQ-DRILL-006).
// Every figure carries its basis, the leakage of the revision it measures and the event_ids it was folded from.
import type { EventRow } from "@loopledger/ports";
import { successorOf } from "./catalog";
import type { CatalogRevision, Method } from "./catalog";

/** Width of a `life_used_pct` band in points; a constant so a tenant can change it. */
export const LIFE_BAND_WIDTH = 25;
export const POOLED = "pooled";
export const UNKNOWN_REVISION = "unknown";

export type Basis = { kind: "measured"; n: number } | { kind: "declared" };

/** born − recovered − known in service − pending: assets that left the record. Reported beside every rate. */
export interface Leakage {
  born: number;
  recovered: number;
  in_service: number;
  /** Assets whose only removal is held for a countersignature: neither recovered nor leaked. */
  pending: number;
  leaked: number;
  rate: number | null;
  sources: string[];
}

export interface Figure {
  value: number | null;
  basis: Basis;
  leakage: Leakage;
  sources: string[];
}

export interface JointFigure {
  joint_id: string;
  outcomes: { clean: number; damaged: number; destroyed: number };
  clean_rate: Figure;
  labor_p50: Figure;
}

export interface RevisionRow {
  catalog_id: string;
  revision: string;
  /** `pooled` for every recovered asset, else `from-to` in `life_used_pct` points. */
  band: string;
  assets_removed: number;
  /** Revision-level in every row: an asset that never came back has no `life_used_pct` to band it by. */
  leakage: Leakage;
  removal: Partial<Record<Method, { p50: Figure; p90: Figure }>>;
  intact_removal_rate: Figure;
  diversion_pct: Figure;
  joints: JointFigure[];
}

export interface FeatureRow {
  joint_type: string;
  materials: [string, string];
  /** Revisions whose catalog item carries this feature. */
  revisions: string[];
  n: number;
  outcomes: { clean: number; damaged: number; destroyed: number };
  clean_rate: Figure;
  labor_p50: Figure;
  leakage: Leakage;
}

export interface FeatureShare {
  joint_type: string;
  materials: [string, string];
  slower_min_per_asset: number;
  faster_min_per_asset: number;
  difference_min: number;
  /** |difference| over the sum of |difference| across features. */
  share: number;
}

interface Options {
  /** Defaults to `LIFE_BAND_WIDTH`. */
  bandWidth?: number;
  /** `Ledger.pending(tenant)`: held events, used only to count assets whose removal is held. */
  pending?: readonly EventRow[];
}

type Outcome = "clean" | "damaged" | "destroyed";

interface Joint {
  event_id: string;
  joint_id: string;
  outcome: Outcome;
  labor_min: number;
}

interface Asset {
  asset_id: string;
  catalog_id: string;
  revision: string;
  born: string;
  observed: boolean;
  /** A `removed` event is held for want of a countersignature; read only by `leakageOf`. */
  held_removal?: boolean;
  life?: number;
  removed?: EventRow;
  processed: EventRow[];
  weighed?: EventRow;
  final?: EventRow;
}

/** Two decimals; `+ 0` turns a rounded -0 into 0. */
const round = (value: number): number => Math.round(value * 100) / 100 + 0;
const minutes = (event: EventRow): number => (Date.parse(String(event.payload.ended_at)) - Date.parse(String(event.payload.started_at))) / 60000;
const groupKey = (catalogId: string, revision: string): string => `${catalogId}\u0000${revision}`;

const percentile = (values: readonly number[], p: number): number | null => {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const at = (sorted.length - 1) * p;
  const lo = Math.floor(at);
  const hi = Math.ceil(at);
  return round(sorted[lo]! + (sorted[hi]! - sorted[lo]!) * (at - lo));
};

const bandOf = (life: number, width: number): { from: number; label: string } => {
  const from = Math.floor(life / width) * width;
  return { from, label: `${from}-${from + width}` };
};

/** Folds the final events into one record per born asset. An asset with no `asset_born` is not folded. */
const foldAssets = (events: readonly EventRow[], pending: readonly EventRow[] = []): Asset[] => {
  const assets = new Map<string, Asset>();
  for (const e of events) {
    if (e.type !== "asset_born") continue;
    const ref = e.payload.catalog_ref as { catalog_id: string } | undefined;
    const revision = e.payload.revision as { label?: string } | undefined;
    for (const id of e.asset_ids) {
      assets.set(id, { asset_id: id, catalog_id: ref?.catalog_id ?? "", revision: revision?.label ?? UNKNOWN_REVISION, born: e.event_id, observed: false, processed: [] });
    }
  }
  const lifeAt = new Map<string, string>();
  for (const e of events) {
    for (const id of e.asset_ids) {
      const a = assets.get(id);
      if (!a) continue;
      if (e.type === "removed") a.removed = e;
      else if (e.type === "processed") a.processed.push(e);
      else if (e.type === "weighed") a.weighed = e;
      else if (e.type === "disposition_final") a.final = e;
      else if (e.type === "observed") a.observed = true;
      else if (e.type === "telemetry" && e.payload.metric === "life_used_pct" && e.occurred_at >= (lifeAt.get(id) ?? "")) {
        a.life = Number(e.payload.value);
        lifeAt.set(id, e.occurred_at);
      }
    }
  }
  // A held event feeds no figure: it only marks that a born asset has a removal waiting for its countersignature.
  for (const e of pending) {
    if (e.type !== "removed") continue;
    for (const id of e.asset_ids) {
      const a = assets.get(id);
      if (a) a.held_removal = true;
    }
  }
  return [...assets.values()];
};

const leakageOf = (assets: readonly Asset[]): Leakage => {
  const recovered = assets.filter((a) => a.final);
  const inService = assets.filter((a) => !a.final && a.observed);
  const pending = assets.filter((a) => !a.final && !a.observed && !a.removed && a.held_removal);
  const leaked = assets.length - recovered.length - inService.length - pending.length;
  const sources = [...assets.map((a) => a.born), ...recovered.map((a) => a.final!.event_id)];
  return { born: assets.length, recovered: recovered.length, in_service: inService.length, pending: pending.length, leaked, rate: assets.length === 0 ? null : round(leaked / assets.length), sources };
};

const figure = (value: number | null, n: number, leakage: Leakage, sources: readonly string[]): Figure => ({ value, basis: { kind: "measured", n }, leakage, sources: [...sources] });

const jointsOf = (asset: Asset): Joint[] =>
  [asset.removed, ...asset.processed].flatMap((e) =>
    e === undefined ? [] : ((e.payload.joints_opened ?? []) as { joint_id: string; outcome: Outcome; labor_min: number }[]).map((j) => ({ event_id: e.event_id, ...j })),
  );

const diversion = (assets: readonly Asset[], leakage: Leakage): Figure => {
  const weighed = assets.filter((a) => a.weighed);
  const total = weighed.reduce((sum, a) => sum + Number(a.weighed!.payload.mass_kg), 0);
  const separated = weighed.reduce(
    (sum, a) => sum + a.processed.flatMap((p) => (p.payload.fractions ?? []) as { mass_kg: number }[]).reduce((s, f) => s + f.mass_kg, 0),
    0,
  );
  const sources = weighed.flatMap((a) => [a.weighed!.event_id, ...a.processed.map((p) => p.event_id)]);
  return figure(total === 0 ? null : round((separated / total) * 100), weighed.length, leakage, sources);
};

const jointFigures = (assets: readonly Asset[], leakage: Leakage): JointFigure[] => {
  const byJoint = new Map<string, Joint[]>();
  for (const j of assets.flatMap(jointsOf)) byJoint.set(j.joint_id, [...(byJoint.get(j.joint_id) ?? []), j]);
  return [...byJoint.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([joint_id, list]) => {
      const count = (o: Outcome) => list.filter((j) => j.outcome === o).length;
      const sources = list.map((j) => j.event_id);
      return {
        joint_id,
        outcomes: { clean: count("clean"), damaged: count("damaged"), destroyed: count("destroyed") },
        clean_rate: figure(round(count("clean") / list.length), list.length, leakage, sources),
        labor_p50: figure(percentile(list.map((j) => j.labor_min), 0.5), list.length, leakage, sources),
      };
    });
};

const row = (item: CatalogRevision | undefined, catalogId: string, revision: string, band: string, assets: readonly Asset[], leakage: Leakage): RevisionRow => {
  const removed = assets.filter((a) => a.removed);
  const methods = new Set<Method>([...removed.map((a) => a.removed!.payload.method as Method), ...(band === POOLED ? (item?.recovery_method ?? []).map((m) => m.method) : [])]);
  const removal: RevisionRow["removal"] = {};
  for (const method of [...methods].sort()) {
    const events = removed.map((a) => a.removed!).filter((e) => e.payload.method === method);
    const sources = events.map((e) => e.event_id);
    const declared = item?.recovery_method.find((m) => m.method === method)?.declared_labor_min;
    if (events.length === 0 && declared !== undefined) {
      const basis: Basis = { kind: "declared" };
      removal[method] = { p50: { value: declared, basis, leakage, sources }, p90: { value: null, basis, leakage, sources } };
    } else {
      const labor = events.map(minutes);
      removal[method] = { p50: figure(percentile(labor, 0.5), labor.length, leakage, sources), p90: figure(percentile(labor, 0.9), labor.length, leakage, sources) };
    }
  }
  const intact = removed.filter((a) => a.removed!.payload.method === "intact").length;
  return {
    catalog_id: catalogId,
    revision,
    band,
    assets_removed: removed.length,
    leakage,
    removal,
    intact_removal_rate: figure(removed.length === 0 ? null : round(intact / removed.length), removed.length, leakage, removed.map((a) => a.removed!.event_id)),
    diversion_pct: diversion(removed, leakage),
    joints: jointFigures(removed, leakage),
  };
};

/**
 * One pooled row and one row per `life_used_pct` band for every `(catalog_id, revision)` that has a born asset or a
 * catalog item. Rows within a revision come pooled first, then by band.
 */
export const revisionPerformance = (events: readonly EventRow[], catalog: readonly CatalogRevision[], options: Options = {}): RevisionRow[] => {
  const width = options.bandWidth ?? LIFE_BAND_WIDTH;
  const assets = foldAssets(events, options.pending);
  const keys = new Map<string, { catalog_id: string; revision: string }>();
  for (const c of catalog) keys.set(groupKey(c.catalog_id, c.revision), { catalog_id: c.catalog_id, revision: c.revision });
  for (const a of assets) keys.set(groupKey(a.catalog_id, a.revision), { catalog_id: a.catalog_id, revision: a.revision });
  const rows: RevisionRow[] = [];
  for (const [key, { catalog_id, revision }] of [...keys.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const group = assets.filter((a) => groupKey(a.catalog_id, a.revision) === key);
    const item = catalog.find((c) => c.catalog_id === catalog_id && c.revision === revision);
    const leakage = leakageOf(group);
    rows.push(row(item, catalog_id, revision, POOLED, group, leakage));
    const bands = new Map<number, string>();
    for (const a of group) if (a.removed && a.life !== undefined) bands.set(bandOf(a.life, width).from, bandOf(a.life, width).label);
    for (const [, label] of [...bands.entries()].sort(([a], [b]) => a - b)) {
      const inBand = group.filter((a) => a.removed && a.life !== undefined && bandOf(a.life, width).label === label);
      rows.push(row(item, catalog_id, revision, label, inBand, leakage));
    }
  }
  return rows;
};

export interface BandGap {
  band: string;
  /** Predecessor minus successor, in minutes: positive when the successor removes faster. */
  labor_gap_min: number | null;
  /** Successor minus predecessor, in percentage points: positive when the successor diverts more. */
  diversion_gap_pct: number | null;
}

export interface Comparison {
  predecessor: string;
  successor: string;
  method: Method;
  bands: BandGap[];
  pooled: BandGap;
  /** Mean of the band gaps, weighted by the smaller cohort of the two revisions in the band. */
  within_band: BandGap;
  /** Pooled gap minus the within-band gap: how much of the pooled difference is age, not design. */
  overstatement: { labor_min: number | null; diversion_pct: number | null };
}

const gap = (band: string, from: RevisionRow, to: RevisionRow, method: Method): BandGap => {
  const a = from.removal[method]?.p50.value ?? null;
  const b = to.removal[method]?.p50.value ?? null;
  const d = (to.diversion_pct.value ?? NaN) - (from.diversion_pct.value ?? NaN);
  return { band, labor_gap_min: a === null || b === null ? null : round(a - b), diversion_gap_pct: Number.isNaN(d) ? null : round(d) };
};

/**
 * The revision against its successor along `supersedes` lineage: band by band where both have recovered assets,
 * and pooled. The pooled gap mostly measures age when the successor's assets are younger.
 */
export const compareWithSuccessor = (rows: readonly RevisionRow[], catalog: readonly CatalogRevision[], catalogId: string, revision: string, method: Method = "intact"): Comparison => {
  const next = successorOf(catalog, catalogId, revision);
  if (!next) throw new Error(`no revision of ${catalogId} supersedes ${revision}`);
  const find = (rev: string, band: string) => rows.find((r) => r.catalog_id === catalogId && r.revision === rev && r.band === band);
  const pair = (band: string) => {
    const from = find(revision, band);
    const to = find(next.revision, band);
    return from && to ? { from, to } : undefined;
  };
  const pooledPair = pair(POOLED);
  if (!pooledPair) throw new Error(`${catalogId} has no pooled row for ${revision} and ${next.revision}`);
  const bandNames = [...new Set(rows.filter((r) => r.catalog_id === catalogId && r.band !== POOLED).map((r) => r.band))].sort((a, b) => parseInt(a) - parseInt(b));
  const shared = bandNames.flatMap((band) => {
    const p = pair(band);
    return p ? [{ band, ...p }] : [];
  });
  const bands = shared.map((s) => gap(s.band, s.from, s.to, method));
  const weighted = (pick: (g: BandGap) => number | null): number | null => {
    let total = 0;
    let weight = 0;
    shared.forEach((s, i) => {
      const value = pick(bands[i]!);
      const w = Math.min(s.from.assets_removed, s.to.assets_removed);
      if (value !== null) {
        total += value * w;
        weight += w;
      }
    });
    return weight === 0 ? null : round(total / weight);
  };
  const pooled = gap(POOLED, pooledPair.from, pooledPair.to, method);
  const within: BandGap = { band: "within", labor_gap_min: weighted((g) => g.labor_gap_min), diversion_gap_pct: weighted((g) => g.diversion_gap_pct) };
  const over = (a: number | null, b: number | null) => (a === null || b === null ? null : round(a - b));
  return {
    predecessor: revision,
    successor: next.revision,
    method,
    bands,
    pooled,
    within_band: within,
    overstatement: { labor_min: over(pooled.labor_gap_min, within.labor_gap_min), diversion_pct: over(pooled.diversion_gap_pct, within.diversion_gap_pct) },
  };
};

interface Feature {
  joint_type: string;
  materials: [string, string];
}

const featureKey = (f: Feature): string => `${f.joint_type}|${f.materials.join("+")}`;

/** The joint type × material pair of each joint of each revision, from the catalog's joint graph. */
const featureOf = (item: CatalogRevision, jointId: string): Feature | undefined => {
  const joint = item.joints.find((j) => j.joint_id === jointId);
  if (!joint) return undefined;
  const material = (id: string) => item.components.find((c) => c.component_id === id)?.material;
  const [a, b] = joint.between.map(material);
  return a === undefined || b === undefined ? undefined : { joint_type: joint.type, materials: [a, b].sort() as [string, string] };
};

const catalogOf = (catalog: readonly CatalogRevision[], asset: Asset): CatalogRevision | undefined =>
  catalog.find((c) => c.catalog_id === asset.catalog_id && c.revision === asset.revision);

/**
 * The same outcomes folded by joint type × material pair instead of revision, so evidence carries across revisions
 * that share a feature. Leakage is summed over the revisions that carry the feature.
 */
export const featurePerformance = (events: readonly EventRow[], catalog: readonly CatalogRevision[], pending: readonly EventRow[] = []): FeatureRow[] => {
  const assets = foldAssets(events, pending);
  const byFeature = new Map<string, { feature: Feature; joints: Joint[]; revisions: Set<string> }>();
  for (const item of catalog) {
    for (const j of item.joints) {
      const feature = featureOf(item, j.joint_id);
      if (!feature) continue;
      const entry = byFeature.get(featureKey(feature)) ?? { feature, joints: [], revisions: new Set<string>() };
      entry.revisions.add(groupKey(item.catalog_id, item.revision));
      byFeature.set(featureKey(feature), entry);
    }
  }
  for (const a of assets) {
    const item = catalogOf(catalog, a);
    if (!item) continue;
    for (const j of jointsOf(a)) {
      const feature = featureOf(item, j.joint_id);
      if (feature) byFeature.get(featureKey(feature))!.joints.push(j);
    }
  }
  return [...byFeature.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([, { feature, joints, revisions }]) => {
      const group = assets.filter((a) => revisions.has(groupKey(a.catalog_id, a.revision)));
      const parts = [...revisions].map((k) => leakageOf(group.filter((a) => groupKey(a.catalog_id, a.revision) === k)));
      const born = parts.reduce((s, l) => s + l.born, 0);
      const leaked = parts.reduce((s, l) => s + l.leaked, 0);
      const leakage: Leakage = {
        born,
        recovered: parts.reduce((s, l) => s + l.recovered, 0),
        in_service: parts.reduce((s, l) => s + l.in_service, 0),
        pending: parts.reduce((s, l) => s + l.pending, 0),
        leaked,
        rate: born === 0 ? null : round(leaked / born),
        sources: parts.flatMap((l) => l.sources),
      };
      const count = (o: Outcome) => joints.filter((j) => j.outcome === o).length;
      const sources = joints.map((j) => j.event_id);
      return {
        ...feature,
        revisions: [...revisions].map((k) => k.split("\u0000")[1]!).sort(),
        n: joints.length,
        outcomes: { clean: count("clean"), damaged: count("damaged"), destroyed: count("destroyed") },
        clean_rate: figure(joints.length === 0 ? null : round(count("clean") / joints.length), joints.length, leakage, sources),
        labor_p50: figure(percentile(joints.map((j) => j.labor_min), 0.5), joints.length, leakage, sources),
        leakage,
      };
    });
};

/**
 * Where the removal-labor difference between two revisions of an item sits, by feature: mean joint labor per removed
 * asset of each revision, feature by feature, largest difference first. A feature only one revision has counts as zero
 * for the other.
 */
export const attributeDifference = (events: readonly EventRow[], catalog: readonly CatalogRevision[], catalogId: string, slower: string, faster: string): FeatureShare[] => {
  const assets = foldAssets(events).filter((a) => a.catalog_id === catalogId && a.removed);
  const perAsset = (revision: string): Map<string, { feature: Feature; minutes: number }> => {
    const group = assets.filter((a) => a.revision === revision);
    const totals = new Map<string, { feature: Feature; minutes: number }>();
    for (const a of group) {
      const item = catalogOf(catalog, a);
      if (!item) continue;
      for (const j of jointsOf(a)) {
        const feature = featureOf(item, j.joint_id);
        if (!feature) continue;
        const entry = totals.get(featureKey(feature)) ?? { feature, minutes: 0 };
        entry.minutes += j.labor_min / group.length;
        totals.set(featureKey(feature), entry);
      }
    }
    return totals;
  };
  const a = perAsset(slower);
  const b = perAsset(faster);
  const keys = new Set([...a.keys(), ...b.keys()]);
  const rows = [...keys].map((k) => {
    const s = a.get(k)?.minutes ?? 0;
    const f = b.get(k)?.minutes ?? 0;
    return { ...(a.get(k)?.feature ?? b.get(k)!.feature), slower_min_per_asset: round(s), faster_min_per_asset: round(f), difference_min: round(s - f) };
  });
  const total = rows.reduce((sum, r) => sum + Math.abs(r.difference_min), 0);
  return rows
    .map((r) => ({ ...r, share: total === 0 ? 0 : round(Math.abs(r.difference_min) / total) }))
    .sort((x, y) => Math.abs(y.difference_min) - Math.abs(x.difference_min));
};
