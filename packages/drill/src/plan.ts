// The plan line of each asset in a recovery event (SPEC-data-model.md §4 RECOVERY_EVENT, SPEC-router.md "Design
// revisions and the schedule"): each asset is timed from its own revision, never from its class.
import type { CatalogRevision, Method } from "./catalog";
import { POOLED, UNKNOWN_REVISION } from "./performance";
import type { RevisionRow } from "./performance";

/** SPEC-data-model.md §8 Q8: a measured figure replaces the declared one at n ≥ 10 per revision per method. */
export const COHORT_MINIMUM = 10;

export type PlanBasis = { kind: "measured"; n: number } | { kind: "declared" } | { kind: "slowest_known_revision"; from: string };

export interface PlanAsset {
  asset_id: string;
  catalog_id: string;
  revision: { basis: "declared" | "observed" | "unknown"; label?: string };
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
const estimate = (rows: readonly RevisionRow[], catalog: readonly CatalogRevision[], catalogId: string, revision: string, method: Method, minimum: number): Estimate | undefined => {
  const measured = rows.find((r) => r.catalog_id === catalogId && r.revision === revision && r.band === POOLED)?.removal[method]?.p50;
  if (measured && measured.basis.kind === "measured" && measured.basis.n >= minimum && measured.value !== null) {
    return { est_labor_min: measured.value, basis: { kind: "measured", n: measured.basis.n } };
  }
  const declared = catalog.find((c) => c.catalog_id === catalogId && c.revision === revision)?.recovery_method.find((m) => m.method === method)?.declared_labor_min;
  return declared === undefined ? undefined : { est_labor_min: declared, basis: { kind: "declared" } };
};

/**
 * One line per asset. An asset whose revision is unknown is timed as the slowest known revision of its catalog item
 * for that method: the conservative default, so resolving the revision can only shorten the plan.
 */
export const plan = (assets: readonly PlanAsset[], catalog: readonly CatalogRevision[], rows: readonly RevisionRow[], minimum: number = COHORT_MINIMUM): PlanLine[] =>
  assets.map((asset) => {
    const method = asset.method ?? "intact";
    const label = asset.revision.basis === "unknown" ? undefined : asset.revision.label;
    if (label !== undefined) {
      const own = estimate(rows, catalog, asset.catalog_id, label, method, minimum);
      if (!own) throw new Error(`${asset.catalog_id} ${label} has no ${method} estimate`);
      return { asset_id: asset.asset_id, revision: label, method, ...own };
    }
    const known = catalog
      .filter((c) => c.catalog_id === asset.catalog_id)
      .flatMap((c) => {
        const e = estimate(rows, catalog, c.catalog_id, c.revision, method, minimum);
        return e ? [{ revision: c.revision, ...e }] : [];
      });
    const slowest = known.reduce<(typeof known)[number] | undefined>((a, b) => (a === undefined || b.est_labor_min > a.est_labor_min ? b : a), undefined);
    if (!slowest) throw new Error(`${asset.catalog_id} has no known revision with a ${method} estimate`);
    return { asset_id: asset.asset_id, revision: UNKNOWN_REVISION, method, est_labor_min: slowest.est_labor_min, basis: { kind: "slowest_known_revision", from: slowest.revision } };
  });
