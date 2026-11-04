// Jurisdiction corpus entries (SPEC-data-model.md §2 RULE / RULE_VERSION) and the check that refuses a malformed one.
import { readFileSync, readdirSync } from "node:fs";

// The ten site-side blind-spot categories of docs/kickoff/JURISDICTION.md.
export const CATEGORIES = [
  "code_triggers",
  "health_code_food_contact",
  "flow_control",
  "end_of_waste",
  "worker_privacy",
  "night_work_noise",
  "donation_substantiation",
  "legal_metrology",
  "diversion_mandate",
  "hub_siting",
] as const;
export type Category = (typeof CATEGORIES)[number];

export const CONFIDENCE = ["low", "medium", "high"] as const;
export const STATUSES = ["draft", "verified", "active", "superseded"] as const;

export interface CorpusEntry {
  jurisdiction: string;
  category: Category;
  rule: string;
  effective_from: string | null;
  pinpoint_citation: string | null;
  confidence: (typeof CONFIDENCE)[number];
  extracted_by: string;
  verified_by?: string;
  status: (typeof STATUSES)[number];
}

const nonEmpty = (v: unknown): v is string => typeof v === "string" && v.trim() !== "";

// Returns the problems with an entry; an empty list means it is accepted.
export const validateEntry = (entry: unknown): string[] => {
  if (typeof entry !== "object" || entry === null || Array.isArray(entry)) return ["entry is not an object"];
  const e = entry as Record<string, unknown>;
  const errors: string[] = [];
  if (!nonEmpty(e.extracted_by)) errors.push("extracted_by is missing or empty");
  if (!nonEmpty(e.jurisdiction)) errors.push("jurisdiction is missing or empty");
  if (!CATEGORIES.includes(e.category as Category)) errors.push("category is not one of the ten categories");
  if (!nonEmpty(e.rule)) errors.push("rule is missing or empty");
  if (e.effective_from !== null && !nonEmpty(e.effective_from)) errors.push("effective_from must be a date or null");
  if (e.pinpoint_citation !== null && !nonEmpty(e.pinpoint_citation)) errors.push("pinpoint_citation must be a string or null");
  if (!CONFIDENCE.includes(e.confidence as (typeof CONFIDENCE)[number])) errors.push("confidence must be low, medium or high");
  if (!STATUSES.includes(e.status as (typeof STATUSES)[number])) errors.push("status is not a known status");
  if (e.verified_by !== undefined && !nonEmpty(e.verified_by)) errors.push("verified_by must be non-empty when present");
  if (e.pinpoint_citation === null && e.confidence !== "low") errors.push("a null pinpoint_citation requires confidence low");
  if (e.verified_by === undefined && e.status !== "draft") errors.push("an entry without verified_by can only be draft");
  return errors;
};

const DATA = new URL("../data/", import.meta.url);

// Reads every `data/<jurisdiction>/*.json` file; each holds an array of entries.
export const loadCorpus = (jurisdiction: string): CorpusEntry[] =>
  readdirSync(new URL(`${jurisdiction}/`, DATA))
    .filter((f) => f.endsWith(".json"))
    .sort()
    .flatMap((f) => JSON.parse(readFileSync(new URL(`${jurisdiction}/${f}`, DATA), "utf8")) as CorpusEntry[]);
