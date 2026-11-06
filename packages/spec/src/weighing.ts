// A fraction's weighing is bound to that fraction (REQ-EVENT-018, REQ-EVENT-019). JSON Schema checks the shape of a
// `weighed` payload and of a fraction; the rules that compare a fraction to the weighed event it cites, and to the
// `processed` event that birthed its lot, span two events and are code.

/** The most a weighed event's net mass may differ from the `mass_kg` of the fraction that cites it, in kg. */
export const MASS_TOLERANCE_KG = 0.01;

/**
 * Material terms (the last segment of the material IRI, an exact match with no hierarchy) whose weighing needs a
 * `moisture_basis`. Vocabulary membership is #18's job: this is the small list the spec package needs until then.
 */
export const BIO_BASED_MATERIALS: readonly string[] = ["wood", "plywood"];

export interface WeighingEvent {
  readonly event_id: string;
  readonly event_type: string;
  readonly asset_ids: readonly string[];
  readonly payload: Readonly<Record<string, unknown>>;
}

const MATERIAL_PREFIX = "https://loopledger.org/vocab/material/";

/** Whether a material term IRI names a bio-based material. */
export const isBioBased = (material: string): boolean => material.startsWith(MATERIAL_PREFIX) && BIO_BASED_MATERIALS.includes(material.slice(MATERIAL_PREFIX.length));

interface Fraction {
  readonly material?: unknown;
  readonly mass_kg?: unknown;
  readonly lot?: unknown;
  readonly weighed_event?: unknown;
}

/**
 * What a set of events breaks beyond the schema, for each fraction of each `processed` event: a `lot` that is not one of
 * the event's `child_asset_ids`; a `weighed_event` that is missing from the set, is not a `weighed` event, or does not
 * name the lot in its `asset_ids`; a net mass that differs from the fraction's `mass_kg` by more than
 * `MASS_TOLERANCE_KG`; and a bio-based fraction whose weighing carries no `moisture_basis`.
 */
export const validateEventSet = (events: readonly WeighingEvent[]): string[] => {
  const byId = new Map(events.map((e) => [e.event_id, e]));
  return events
    .filter((e) => e.event_type === "processed")
    .flatMap((e) => {
      const fractions = (Array.isArray(e.payload["fractions"]) ? e.payload["fractions"] : []).filter((f): f is Fraction => f !== null && typeof f === "object");
      const children = Array.isArray(e.payload["child_asset_ids"]) ? e.payload["child_asset_ids"] : [];
      return fractions.flatMap((f) => {
        const name = `fraction ${String(f.material)} of ${e.event_id}`;
        const errors: string[] = [];
        if (!children.includes(f.lot)) errors.push(`${name}: lot ${String(f.lot)} is not one of the child assets`);
        const weighed = typeof f.weighed_event === "string" ? byId.get(f.weighed_event) : undefined;
        if (weighed === undefined || weighed.event_type !== "weighed") return [...errors, `${name}: weighed event ${String(f.weighed_event)} is not a weighed event in the set`];
        if (typeof f.lot !== "string" || !weighed.asset_ids.includes(f.lot)) errors.push(`${name}: weighed event ${weighed.event_id} does not name lot ${String(f.lot)}`);
        const net = weighed.payload["mass_kg"];
        if (typeof net !== "number" || typeof f.mass_kg !== "number" || Math.abs(net - f.mass_kg) > MASS_TOLERANCE_KG + 1e-9) {
          errors.push(`${name}: net mass ${String(net)} kg differs from mass_kg ${String(f.mass_kg)}`);
        }
        if (typeof f.material === "string" && isBioBased(f.material) && weighed.payload["moisture_basis"] === undefined) errors.push(`${name}: weighed event ${weighed.event_id} has no moisture_basis`);
        return errors;
      });
    });
};
