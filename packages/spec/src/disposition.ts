// Per-fraction disposition lines (`disposition_final`, REQ-EVENT-016, REQ-EVENT-017, REQ-EVENT-020). A line records
// LoopLedger's own `route`; regional and standards codes sit beside it as `classification` entries. JSON Schema checks
// the shape of a known scheme's code; the rules that compare a line to the asset-level `family`, to its classification,
// or to an earlier `processed` event, are code.

/** The routes a line, and the asset-level `family`, can take. */
export const ROUTES = ["redeploy", "resale", "donate", "recycle", "recovery", "disposal"] as const;

export type Route = (typeof ROUTES)[number];

export interface Classification {
  readonly scheme: string;
  readonly code: string;
}

export interface DispositionLine {
  readonly material: string;
  readonly mass_kg: number;
  readonly route: Route;
  readonly classification?: readonly Classification[];
}

/**
 * The routes a known scheme's code is consistent with, or undefined for an unknown scheme or an unrecognised code. In
 * Directive 2008/98/EC, D codes are final deposition and R1 is energy recovery. R2 to R13 are anything else: recycling
 * and reclamation, and no annex code names preparing for re-use, so exchange (R12) and storage (R13) carry the reuse
 * routes.
 */
const EU_WFD = (code: string): readonly Route[] | undefined => {
  const hit = /^([RD])(\d{1,2})$/.exec(code);
  if (!hit) return undefined;
  const n = Number(hit[2]);
  if (hit[1] === "D") return n >= 1 && n <= 15 ? ["disposal"] : undefined;
  if (n === 1) return ["recovery"];
  return n >= 2 && n <= 13 ? ["redeploy", "resale", "donate", "recycle"] : undefined;
};

const SCHEMES: Readonly<Record<string, (code: string) => readonly Route[] | undefined>> = { "eu-wfd-2008-98": EU_WFD };

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
  const routes = new Set(lines.filter((l) => l.mass_kg === heaviest).map((l) => l.route));
  return routes.has(payload["family"] as Route) ? [] : [`family ${String(payload["family"])} is not the route of the heaviest line`];
};

/**
 * Classifications of a known scheme whose code contradicts the line's `route`. Codes under an unknown scheme are not
 * read, and a scheme may repeat with a different code.
 */
export const dispositionClassificationErrors = (payload: Readonly<Record<string, unknown>>): string[] =>
  linesOf(payload).flatMap((l) =>
    (Array.isArray(l.classification) ? l.classification : []).flatMap((c) => {
      const allowed = Object.hasOwn(SCHEMES, c.scheme) ? SCHEMES[c.scheme]!(c.code) : undefined;
      return allowed !== undefined && !allowed.includes(l.route) ? [`${c.scheme} code ${c.code} contradicts route ${l.route} for ${l.material}`] : [];
    }),
  );

/**
 * Lines whose route is redeploy, resale, donate or recycle for a material no earlier `processed` event separated.
 * `processed` is the payloads of the `processed` events on the asset (or that birthed it); a fraction counts as
 * separated when one of their `fractions` names the same material (an exact term match, no hierarchy). Recovery and
 * disposal lines need no separation.
 */
export const dispositionSeparationErrors = (
  payload: Readonly<Record<string, unknown>>,
  processed: readonly Readonly<Record<string, unknown>>[],
): string[] => {
  const separated = new Set(
    processed.flatMap((p) => (Array.isArray(p["fractions"]) ? p["fractions"] : [])).map((f) => (f !== null && typeof f === "object" ? (f as { material?: unknown }).material : undefined)),
  );
  return linesOf(payload).flatMap((l) =>
    l.route !== "recovery" && l.route !== "disposal" && !separated.has(l.material) ? [`${l.route} line for ${l.material} was never separated`] : [],
  );
};
