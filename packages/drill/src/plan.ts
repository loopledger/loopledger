// The plan line of each asset in a recovery event (SPEC-data-model.md §4 RECOVERY_EVENT, SPEC-router.md "Design
// revisions and the schedule"): each asset is timed from its own revision, never from its class.
import { revisionId } from "./catalog";
import type { CatalogRevision, Method, RevisionKey } from "./catalog";
import { POOLED, UNKNOWN_REVISION } from "./performance";
import type { RevisionRow } from "./performance";

/** SPEC-data-model.md §8 Q8: a measured figure replaces the declared one at n ≥ 10 per revision per method. */
export const COHORT_MINIMUM = 10;

export type PlanBasis = { kind: "measured"; n: number } | { kind: "declared" } | { kind: "slowest_known_revision"; from: string };

/** An asset to plan: its catalog revision by manufacturer, model reference and version, or no version when the revision is unknown. */
export interface PlanAsset {
  asset_id: string;
  manufacturer: string;
  model_reference: string;
  version?: number;
  method?: Method;
}

export interface PlanLine {
  asset_id: string;
  revision: string;
  method: Method;
  est_labor_min: number;
  basis: PlanBasis;
}

interface Estimate {
  est_labor_min: number;
  basis: PlanBasis;
}

/** The measured p50 once the cohort qualifies, else the catalog's declared labor, else nothing. */
const estimate = (rows: readonly RevisionRow[], catalog: readonly CatalogRevision[], key: RevisionKey, method: Method, minimum: number): Estimate | undefined => {
  const measured = rows.find((r) => revisionId(r) === revisionId(key) && r.band === POOLED)?.removal[method]?.p50;
  if (measured && measured.basis.kind === "measured" && measured.basis.n >= minimum && measured.value !== null) {
    return { est_labor_min: measured.value, basis: { kind: "measured", n: measured.basis.n } };
  }
  const declared = catalog.find((c) => revisionId(c) === revisionId(key))?.recovery_method.find((m) => m.method === method)?.declared_labor_min;
  return declared === undefined ? undefined : { est_labor_min: declared, basis: { kind: "declared" } };
};

/**
 * One line per asset. An asset whose revision is unknown is timed as the slowest known revision of its model
 * for that method: the conservative default, so resolving the revision can only shorten the plan.
 */
export const plan = (assets: readonly PlanAsset[], catalog: readonly CatalogRevision[], rows: readonly RevisionRow[], minimum: number = COHORT_MINIMUM): PlanLine[] =>
  assets.map((asset) => {
    const method = asset.method ?? "intact";
    const model = `${asset.model_reference} by ${asset.manufacturer}`;
    if (asset.version !== undefined) {
      const key = { manufacturer: asset.manufacturer, model_reference: asset.model_reference, version: asset.version };
      const own = estimate(rows, catalog, key, method, minimum);
      if (!own) throw new Error(`${model} version ${asset.version} has no ${method} estimate`);
      const label = catalog.find((c) => revisionId(c) === revisionId(key))?.label ?? String(asset.version);
      return { asset_id: asset.asset_id, revision: label, method, ...own };
    }
    const known = catalog
      .filter((c) => c.manufacturer === asset.manufacturer && c.model_reference === asset.model_reference)
      .flatMap((c) => {
        const e = estimate(rows, catalog, c, method, minimum);
        return e ? [{ revision: c.label, ...e }] : [];
      });
    const slowest = known.reduce<(typeof known)[number] | undefined>((a, b) => (a === undefined || b.est_labor_min > a.est_labor_min ? b : a), undefined);
    if (!slowest) throw new Error(`${model} has no known revision with a ${method} estimate`);
    return { asset_id: asset.asset_id, revision: UNKNOWN_REVISION, method, est_labor_min: slowest.est_labor_min, basis: { kind: "slowest_known_revision", from: slowest.revision } };
  });
