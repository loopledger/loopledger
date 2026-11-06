// The drill's report as text: the pooled revision rows with their diversion, headed by the pilot banner (REQ-DRILL-013).
import { POOLED } from "./performance";
import type { RevisionRow } from "./performance";

export const PILOT_BANNER = "Pilot, not evidence";

/** One line per pooled revision row. The banner leads when any row is from a pilot ledger. */
export const renderReport = (rows: readonly RevisionRow[]): string => {
  const lines = rows
    .filter((r) => r.band === POOLED)
    .map((r) => {
      const d = r.diversion_pct;
      return `${r.model_reference} ${r.revision}: ${r.assets_removed} removed, diversion ${d.value === null ? "n/a" : `${d.value}%`} of ${d.weighed_kg} kg, leaked ${r.leakage.leaked} of ${r.leakage.born}`;
    });
  return [...(rows.some((r) => r.pilot) ? [PILOT_BANNER] : []), ...lines, ""].join("\n");
};
