// Validates an event against schema/event.schema.json, in Node and in the browser (REQ-SPEC-006).
import Ajv2020 from "ajv/dist/2020.js";
import type { ValidateFunction } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import eventSchema from "../schema/event.schema.json" with { type: "json" };
import passportSchema from "../schema/passport.schema.json" with { type: "json" };

export const EVENT_CONTEXT = "https://loopledger.org/schema/v0.1/context.jsonld";

export interface EventValidation {
  valid: boolean;
  /** One line per schema violation, `<path> <message>`; empty when valid. */
  errors: string[];
}

let check: ValidateFunction | undefined;

const compiled = (): ValidateFunction => {
  if (check) return check;
  const ajv = new Ajv2020({ allErrors: true, strictTypes: false });
  (addFormats as unknown as (a: Ajv2020) => void)(ajv);
  ajv.addSchema(passportSchema);
  check = ajv.compile(eventSchema);
  return check;
};

/**
 * Validates an event. The input is the full document or the row a ledger stores: a row without `@context`, `@type`,
 * `signatures` or `held` is checked as a held draft with no signatures, so it can be validated before anything is stored.
 * Nothing is changed in the input.
 */
export const validateEvent = (event: unknown): EventValidation => {
  const doc =
    event !== null && typeof event === "object" && !Array.isArray(event)
      ? { "@context": [EVENT_CONTEXT], "@type": "Event", signatures: [], held: true, ...(event as Record<string, unknown>) }
      : event;
  const validate = compiled();
  if (validate(doc)) return { valid: true, errors: [] };
  return { valid: false, errors: (validate.errors ?? []).map((e) => `${e.instancePath === "" ? "/" : e.instancePath} ${e.message ?? "is invalid"}`) };
};
