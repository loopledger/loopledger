import { describe, expect, it } from "vitest";
import { CATEGORIES, loadCorpus, validateEntry } from "../src/index.js";

const good = {
  jurisdiction: "Chicago",
  category: "flow_control",
  rule: "A rule.",
  effective_from: null,
  pinpoint_citation: null,
  confidence: "low",
  extracted_by: "someone",
  status: "draft",
};

describe("corpus", () => {
  it("REQ-CORPUS-001 covers the ten categories for Chicago", () => {
    const entries = loadCorpus("chicago");
    expect(CATEGORIES).toHaveLength(10);
    for (const c of CATEGORIES) expect(entries.some((e) => e.category === c)).toBe(true);
  });

  it("REQ-CORPUS-002 refuses an entry without extracted_by, and every data entry passes", () => {
    expect(validateEntry(good)).toEqual([]);
    const { extracted_by: _, ...missing } = good;
    expect(validateEntry(missing)).toContain("extracted_by is missing or empty");
    expect(validateEntry({ ...good, extracted_by: "  " })).toContain("extracted_by is missing or empty");
    for (const e of loadCorpus("chicago")) expect(validateEntry(e)).toEqual([]);
  });

  it("REQ-CORPUS-003 allows only draft without verified_by", () => {
    for (const status of ["verified", "active", "superseded"]) {
      expect(validateEntry({ ...good, status })).toContain("an entry without verified_by can only be draft");
    }
    expect(validateEntry({ ...good, status: "active", verified_by: "counsel" })).toEqual([]);
    for (const e of loadCorpus("chicago")) expect(e.verified_by === undefined && e.status === "draft").toBe(true);
  });

  it("REQ-CORPUS-004 requires confidence low for a null citation", () => {
    expect(validateEntry({ ...good, confidence: "high" })).toContain("a null pinpoint_citation requires confidence low");
    expect(validateEntry({ ...good, confidence: "high", pinpoint_citation: "x" })).toEqual([]);
  });
});
