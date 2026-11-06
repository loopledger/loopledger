// Per-fraction disposition lines (`disposition_final`, REQ-EVENT-016, REQ-EVENT-017). The R/D codes are those of
// Directive 2008/98/EC Annexes I (recovery) and II (disposal). JSON Schema checks the code's shape; the rules that
// compare a line to the asset-level `family`, or to an earlier `processed` event, are code.

export type RouteGroup = "reuse" | "recycle" | "recovery" | "disposal";

/** The asset-level `family` values and the route group each belongs to. */
const FAMILY_GROUP: Readonly<Record<string, RouteGroup>> = {
  redeploy: "reuse",
  resale: "reuse",
  donate: "reuse",
  recycle: "recycle",
  recovery: "recovery",
  disposal: "disposal",
};

/**
 * The route group of an R/D code. D codes are final deposition and R1 is energy recovery. R2 to R11 are recycling and
 * reclamation. No annex code names preparing for re-use, so R12 (exchange) and R13 (storage) carry the reuse group.
 */
export const routeGroup = (rdCode: string): RouteGroup | undefined => {
  const hit = /^([RD])(\d{1,2})$/.exec(rdCode);
  if (!hit) return undefined;
  const n = Number(hit[2]);
  if (hit[1] === "D") return n >= 1 && n <= 15 ? "disposal" : undefined;
  if (n === 1) return "recovery";
  if (n >= 2 && n <= 11) return "recycle";
  return n === 12 || n === 13 ? "reuse" : undefined;
};

export interface DispositionLine {
  readonly material: string;
  readonly mass_kg: number;
  readonly rd_code: string;
}

const groupOf = (family: unknown): RouteGroup | undefined => (typeof family === "string" && Object.hasOwn(FAMILY_GROUP, family) ? FAMILY_GROUP[family] : undefined);

const linesOf = (payload: Readonly<Record<string, unknown>>): DispositionLine[] =>
  (Array.isArray(payload["lines"]) ? payload["lines"] : []).filter((l): l is DispositionLine => l !== null && typeof l === "object");

/**
 * What a `disposition_final` payload breaks beyond the schema: a `family` that is not the route of the heaviest line
 * (any of the tied lines when masses tie). The schema checks that `lines` is present and well formed.
 */
export const dispositionFamilyErrors = (payload: Readonly<Record<string, unknown>>): string[] => {
  const lines = linesOf(payload);
  if (lines.length === 0) return [];
  const heaviest = Math.max(...lines.map((l) => l.mass_kg));
  const groups = new Set(lines.filter((l) => l.mass_kg === heaviest).map((l) => routeGroup(l.rd_code)));
  const family = groupOf(payload["family"]);
  return family !== undefined && groups.has(family) ? [] : [`family ${String(payload["family"])} is not the route of the heaviest line`];
};

/**
 * Lines whose route is reuse or recycling for a material no earlier `processed` event separated. `processed` is the
 * payloads of the `processed` events on the asset (or that birthed it); a fraction counts as separated when one of
 * their `fractions` names the same material (an exact term match, no hierarchy).
 */
export const dispositionSeparationErrors = (
  payload: Readonly<Record<string, unknown>>,
  processed: readonly Readonly<Record<string, unknown>>[],
): string[] => {
  const separated = new Set(
    processed.flatMap((p) => (Array.isArray(p["fractions"]) ? p["fractions"] : [])).map((f) => (f !== null && typeof f === "object" ? (f as { material?: unknown }).material : undefined)),
  );
  return linesOf(payload).flatMap((l) => {
    const group = routeGroup(l.rd_code);
    return (group === "reuse" || group === "recycle") && !separated.has(l.material) ? [`${l.rd_code} line for ${l.material} was never separated`] : [];
  });
};
