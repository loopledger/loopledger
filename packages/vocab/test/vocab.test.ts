import { describe, expect, it } from "vitest";
import { SCHEMES, VOCABULARY, isTermInScheme, termForIri } from "../src/index.js";

const CAUSE_FALSE = ["removal_damage", "window_capacity", "no_receiver", "constraint_forbids"];

describe("vocab v0.1", () => {
  it("REQ-VOC-001 publishes the three schemes as versioned JSON-LD", () => {
    expect(SCHEMES).toEqual(["joint_type", "material", "cause"]);
    for (const s of SCHEMES) {
      const file = VOCABULARY[s] as unknown as Record<string, unknown>;
      expect(file["@context"]).toBeTruthy();
      expect(file["@id"]).toBe(`https://loopledger.org/vocab/${s}/v0.1`);
      expect(file.version).toBe("0.1");
      expect(file.scheme).toBe(s);
      expect(VOCABULARY[s].terms.length).toBeGreaterThan(0);
      const ids = VOCABULARY[s].terms.map((t) => t.term_id);
      expect(new Set(ids).size).toBe(ids.length);
      for (const t of VOCABULARY[s].terms) {
        expect(t.scheme).toBe(s);
        expect(t["@id"]).toBe(`https://loopledger.org/vocab/${s}/${t.term_id}`);
        expect(t.status).toBe("draft");
      }
    }
    expect(VOCABULARY.cause.terms).toHaveLength(13);
  });

  it("REQ-VOC-002 gives every term external_refs, holding only verified references", () => {
    for (const s of SCHEMES) {
      for (const t of VOCABULARY[s].terms) {
        expect(Array.isArray(t.external_refs)).toBe(true);
        for (const ref of t.external_refs) expect(ref).toMatch(/^(https?:\/\/|none$)/);
      }
    }
  });

  it("REQ-VOC-005 maps joint types to bSDD IFC 4.3 classes, or an explicit none", () => {
    const base = "https://identifier.buildingsmart.org/uri/buildingsmart/ifc/4.3/class/";
    const refs = Object.fromEntries(VOCABULARY.joint_type.terms.map((t) => [t.term_id, t.external_refs]));
    expect(refs).toEqual({
      bonded: [`${base}IfcFastenerGLUE`],
      screwed: [`${base}IfcMechanicalFastenerSCREW`],
      bolted: [`${base}IfcMechanicalFastenerBOLT`],
      welded: [`${base}IfcFastenerWELD`],
      clipped: ["none"],
      snap_fit: ["none"],
    });
  });

  it("REQ-VOC-006 maps material terms to bSDD NAAKT 2.5 classes, or an explicit none", () => {
    const base = "https://identifier.buildingsmart.org/uri/nkt/naakt/2.5/class/";
    const refs = Object.fromEntries(VOCABULARY.material.terms.map((t) => [t.term_id, t.external_refs]));
    expect(refs).toEqual({
      wood: [`${base}hout_generiek_generiek`],
      plywood: [`${base}hout_multiplex_generiek`],
      steel: [`${base}metaal_staal_generiek`],
      aluminium: [`${base}metaal_aluminium_generiek`],
      plastic: [`${base}kunststof_generiek_generiek`],
      vinyl: [`${base}kunststof_pvc_generiek`],
      foam: ["none"],
      textile: ["none"],
    });
  });

  it("REQ-VOC-007 lists the ISO 20887:2020 principles each joint type serves, as LoopLedger's judgment", () => {
    const standard: Record<string, string> = {
      "5.2.2": "Versatility",
      "5.2.3": "Convertibility",
      "5.2.4": "Expandability",
      "5.3.2": "Ease of access to components and services",
      "5.3.3": "Independence",
      "5.3.4": "Avoidance of unnecessary treatments and finishes",
      "5.3.5": "Supporting re-use (circular economy) business models",
      "5.3.6": "Simplicity",
      "5.3.7": "Standardization",
      "5.3.8": "Safety of disassembly",
    };
    for (const t of VOCABULARY.joint_type.terms) {
      expect(Array.isArray(t.iso_20887_principles)).toBe(true);
      for (const p of t.iso_20887_principles!) expect(standard[p.clause]).toBe(p.name);
    }
    const clauses = Object.fromEntries(VOCABULARY.joint_type.terms.map((t) => [t.term_id, t.iso_20887_principles!.map((p) => p.clause)]));
    expect(clauses).toEqual({
      screwed: ["5.3.3", "5.3.6", "5.3.7"],
      bolted: ["5.3.3", "5.3.6", "5.3.7", "5.2.3"],
      clipped: ["5.3.3", "5.3.6"],
      snap_fit: ["5.3.3", "5.3.6"],
      bonded: [],
      welded: [],
    });
    const comment = (VOCABULARY.joint_type as unknown as Record<string, string>)["$comment"]!;
    expect(comment).toContain("LoopLedger's judgment");
    for (const s of ["material", "cause"] as const) {
      for (const t of VOCABULARY[s].terms) expect(t.iso_20887_principles).toBeUndefined();
    }
  });

  it("REQ-VOC-003 tags every cause code with a boolean design_addressable", () => {
    for (const t of VOCABULARY.cause.terms) expect(typeof t.design_addressable).toBe("boolean");
    const no = VOCABULARY.cause.terms.filter((t) => !t.design_addressable).map((t) => t.term_id);
    expect(no.sort()).toEqual([...CAUSE_FALSE].sort());
    for (const id of ["wear_beyond_refurb", "contamination"]) {
      expect(VOCABULARY.cause.terms.find((t) => t.term_id === id)?.design_addressable).toBe(true);
    }
    for (const s of ["joint_type", "material"] as const) {
      for (const t of VOCABULARY[s].terms) expect(t.design_addressable).toBeUndefined();
    }
  });

  it("REQ-VOC-004 rejects a term outside its published scheme", () => {
    expect(isTermInScheme("joint_type", "bonded")).toBe(true);
    expect(isTermInScheme("material", "bonded")).toBe(false);
    expect(isTermInScheme("cause", "made_up")).toBe(false);
    expect(isTermInScheme("colour", "steel")).toBe(false);
    expect(termForIri("https://loopledger.org/vocab/material/steel")?.term_id).toBe("steel");
    expect(termForIri("https://loopledger.org/vocab/material/v0.1/steel")?.term_id).toBe("steel");
    expect(termForIri("https://loopledger.org/vocab/material/v9.9/steel")).toBeUndefined();
    expect(termForIri("https://loopledger.org/vocab/material/unobtainium")).toBeUndefined();
    expect(termForIri("https://loopledger.org/vocab/joint_type/steel")).toBeUndefined();
    expect(termForIri("https://example.org/vocab/material/steel")).toBeUndefined();
  });
});
