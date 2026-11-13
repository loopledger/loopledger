import { beforeAll, describe, expect, it } from "vitest";
import { PROPERTY_SET, revisionPerformance, writeIfc } from "../src/index";
import type { CatalogRevision, RevisionRow } from "../src/index";
import { loadFixture } from "../fixtures/index";

let catalog: CatalogRevision[];
let rows: RevisionRow[];
let step: string;
let skipped: string[];

/** The DATA section as id → entity name and arguments text. */
const entities = (text: string): Map<number, { name: string; args: string }> => {
  const data = text.split("DATA;\n")[1]!.split("\nENDSEC;")[0]!;
  const map = new Map<number, { name: string; args: string }>();
  for (const line of data.split("\n")) {
    const m = /^#(\d+)=([A-Z0-9]+)\((.*)\);$/.exec(line);
    if (!m) throw new Error(`not an entity line: ${line}`);
    map.set(Number(m[1]), { name: m[2]!, args: m[3]! });
  }
  return map;
};

const IDENTITY = ["Manufacturer", "ModelReference", "ArticleNumber", "GlobalTradeItemNumber"];
const refs = (args: string): number[] => [...args.matchAll(/#(\d+)/g)].map((m) => Number(m[1]));
const guidOf = (item: CatalogRevision): string => item.design_ref!.find((d) => d.scheme === "ifc_type_guid")!.value;

beforeAll(async () => {
  const { fixture, ledger } = await loadFixture();
  catalog = fixture.catalog;
  rows = revisionPerformance(await ledger.projection(fixture.tenant), catalog);
  ({ step, skipped } = writeIfc(rows, catalog));
});

describe("REQ-DRILL-007 the IFC writer attaches one property set to the type object matched by ifc_type_guid", () => {
  it("opens with the ISO-10303-21 header and IFC4 schema and closes the file", () => {
    const lines = step.split("\n");
    expect(lines[0]).toBe("ISO-10303-21;");
    expect(lines[1]).toBe("HEADER;");
    expect(step).toContain("FILE_SCHEMA(('IFC4'));");
    expect(lines.filter((l) => l === "ENDSEC;")).toHaveLength(2);
    expect(step.trimEnd().endsWith("END-ISO-10303-21;")).toBe(true);
  });

  it("numbers entities from #1 without a gap and resolves every reference", () => {
    const map = entities(step);
    expect([...map.keys()]).toEqual([...Array(map.size).keys()].map((i) => i + 1));
    for (const [id, { args }] of map) for (const ref of refs(args)) expect(map.has(ref), `#${id} refers to missing #${ref}`).toBe(true);
  });

  it("names the property set exactly, once per revision", () => {
    const sets = [...entities(step).values()].filter((e) => e.name === "IFCPROPERTYSET");
    expect(PROPERTY_SET).toBe("LoopLedger_RecoveryPerformance");
    expect(sets).toHaveLength(2);
    for (const set of sets) expect(set.args).toContain(",'LoopLedger_RecoveryPerformance',");
  });

  it("links each property set to the type object whose GlobalId is the revision's ifc_type_guid, G4 and G5 apart", () => {
    const map = entities(step);
    const rels = [...map.values()].filter((e) => e.name === "IFCRELDEFINESBYPROPERTIES");
    expect(rels).toHaveLength(2);
    const linked = rels.map((rel) => {
      const m = /,\(#(\d+)\),#(\d+)$/.exec(rel.args)!;
      const type = map.get(Number(m[1]))!;
      const set = map.get(Number(m[2]))!;
      expect(type.name).toBe("IFCTYPEOBJECT");
      expect(set.name).toBe("IFCPROPERTYSET");
      return type.args.split(",")[0]!.replaceAll("'", "");
    });
    expect(linked).toEqual(catalog.map(guidOf));
    expect(new Set(linked).size).toBe(2);
  });

  it("matches only on ifc_type_guid: a revision without one is skipped and listed, and no GUID is invented", () => {
    const bare = catalog.map((c) => (c.label === "G5" ? { ...c, design_ref: c.design_ref!.filter((d) => d.scheme !== "ifc_type_guid") } : c));
    const result = writeIfc(rows, bare);
    expect(result.skipped).toEqual([`${bare[1]!.manufacturer} BTH-2S version 3`]);
    expect(result.step).not.toContain(guidOf(catalog[1]!));
    expect([...entities(result.step).values()].filter((e) => e.name === "IFCTYPEOBJECT")).toHaveLength(1);
    expect(skipped).toEqual([]);
  });

  it("is the same text every time it is written", () => {
    expect(writeIfc(rows, catalog).step).toBe(step);
  });
});

describe("REQ-DRILL-008 the property values carry their basis and leakage beside every rate", () => {
  const propsOf = (revision: string): Map<string, string> => {
    const map = entities(step);
    const item = catalog.find((c) => c.label === revision)!;
    const type = [...map.entries()].find(([, e]) => e.name === "IFCTYPEOBJECT" && e.args.startsWith(`'${guidOf(item)}'`))![0];
    const rel = [...map.values()].find((e) => e.name === "IFCRELDEFINESBYPROPERTIES" && e.args.includes(`(#${type}),`))!;
    const set = map.get(Number(/#(\d+)$/.exec(rel.args)![1]))!;
    const out = new Map<string, string>();
    for (const id of refs(set.args.slice(set.args.indexOf("(")))) {
      const m = /^'([^']*)',\$,(.*),\$$/.exec(map.get(id)!.args)!;
      out.set(m[1]!, m[2]!);
    }
    return out;
  };

  it("writes the pooled row's counts, rates and removal times as plain IfcReal, IfcInteger and IfcLabel values", () => {
    for (const revision of ["G4", "G5"]) {
      const row = rows.find((r) => r.revision === revision && r.band === "pooled")!;
      const props = propsOf(revision);
      expect(props.get("assets_removed")).toBe(`IFCINTEGER(${row.assets_removed})`);
      expect(props.get("diversion_pct")).toMatch(/^IFCREAL\(/);
      expect(props.get("intact_removal_rate")).toMatch(/^IFCREAL\(/);
      for (const method of Object.keys(row.removal)) {
        expect(props.has(`removal_${method}_p50_min`)).toBe(true);
        expect(props.has(`removal_${method}_p90_min`)).toBe(true);
      }
      expect([...props.values()].every((v) => v === "$" || /^IFC(REAL|INTEGER|LABEL|BOOLEAN)\(/.test(v))).toBe(true);
    }
  });

  it("REQ-PASSPORT-009 writes the revision's identity under the Pset_ManufacturerTypeInformation property names", () => {
    const g4 = propsOf("G4");
    const item = catalog.find((c) => c.label === "G4")!;
    expect(g4.get("Manufacturer")).toBe(`IFCLABEL('${item.manufacturer}')`);
    expect(g4.get("ModelReference")).toBe("IFCLABEL('BTH-2S')");
    expect(g4.get("ArticleNumber")).toBe("IFCLABEL('BTH-2S-G4')");
    expect(g4.get("GlobalTradeItemNumber")).toBe("IFCLABEL('09506000134352')");
    const g5 = propsOf("G5");
    expect(g5.get("ArticleNumber")).toBe("IFCLABEL('BTH-2S-G5')");
    expect(g5.has("GlobalTradeItemNumber")).toBe(false);
  });

  it("writes a basis, measured n or declared, beside every figure", () => {
    for (const revision of ["G4", "G5"]) {
      const props = propsOf(revision);
      const figures = [...props.keys()].filter(
        (k) => !k.endsWith("_basis") && !k.endsWith("_leakage_leaked") && !k.endsWith("_leakage_rate") && !k.startsWith("leakage_") && k !== "assets_removed" && k !== "pilot" && !(k.startsWith("diversion_") && k !== "diversion_pct") && !IDENTITY.includes(k),
      );
      expect(figures.length).toBeGreaterThanOrEqual(4);
      for (const name of figures) expect(props.get(`${name}_basis`), name).toMatch(/^IFCLABEL\('(measured n=\d+|declared)'\)$/);
    }
  });

  it("REQ-DRILL-012 writes the diversion masses, the energy-recovery line and the residual beside the rate", () => {
    for (const revision of ["G4", "G5"]) {
      const d = rows.find((r) => r.revision === revision && r.band === "pooled")!.diversion_pct;
      const props = propsOf(revision);
      expect(props.get("diversion_residual_kg")).toMatch(/^IFCREAL\(/);
      expect(props.get("diversion_energy_recovery_kg")).toMatch(/^IFCREAL\(/);
      expect(props.get("diversion_disposed_kg")).toMatch(/^IFCREAL\(/);
      expect(props.get("diversion_unbalanced")).toBe(`IFCINTEGER(${d.unbalanced})`);
    }
  });

  it("writes the revision's leakage as the row carries it, and leakage beside every rate", () => {
    for (const revision of ["G4", "G5"]) {
      const row = rows.find((r) => r.revision === revision && r.band === "pooled")!;
      const props = propsOf(revision);
      expect(props.get("leakage_born")).toBe(`IFCINTEGER(${row.leakage.born})`);
      expect(props.get("leakage_leaked")).toBe(`IFCINTEGER(${row.leakage.leaked})`);
      for (const rate of ["intact_removal_rate", "diversion_pct"]) {
        expect(props.get(`${rate}_leakage_leaked`)).toBe(`IFCINTEGER(${row.leakage.leaked})`);
        expect(props.has(`${rate}_leakage_rate`)).toBe(true);
      }
    }
  });
});
