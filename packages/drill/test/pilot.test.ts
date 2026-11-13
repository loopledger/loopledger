import { describe, expect, it } from "vitest";
import { PILOT_BANNER, revisionPerformance, renderReport, writeIfc } from "../src/index";
import { loadFixture } from "../fixtures/index";

const compute = async (mode: "pilot" | "evidence") => {
  const { fixture, ledger } = await loadFixture(mode);
  const rows = revisionPerformance(await ledger.projection(fixture.tenant), fixture.catalog, { pilot: ledger.mode === "pilot" });
  return { rows, catalog: fixture.catalog };
};

describe("REQ-DRILL-013 figures computed from a pilot ledger carry pilot: true", () => {
  it("marks every revision row and its diversion figure, and the IFC property set", async () => {
    const { rows, catalog } = await compute("pilot");
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expect(row.pilot).toBe(true);
      expect(row.diversion_pct.pilot).toBe(true);
    }
    const ifc = writeIfc(rows, catalog);
    expect(ifc.pilot).toBe(true);
    expect(ifc.step).toContain("IFCPROPERTYSINGLEVALUE('pilot',$,IFCBOOLEAN(.T.),$)");
  });

  it("marks nothing from an evidence ledger", async () => {
    const { rows, catalog } = await compute("evidence");
    for (const row of rows) {
      expect(row.pilot).toBe(false);
      expect(row.diversion_pct.pilot).toBe(false);
    }
    const ifc = writeIfc(rows, catalog);
    expect(ifc.pilot).toBe(false);
    expect(ifc.step).toContain("IFCPROPERTYSINGLEVALUE('pilot',$,IFCBOOLEAN(.F.),$)");
  });

  it("prints Pilot, not evidence in the report when it is set, and only then", async () => {
    expect(renderReport((await compute("pilot")).rows).split("\n")[0]).toBe(PILOT_BANNER);
    expect(PILOT_BANNER).toBe("Pilot, not evidence");
    const evidence = renderReport((await compute("evidence")).rows);
    expect(evidence).not.toContain(PILOT_BANNER);
    expect(evidence).toContain("diversion");
  });
});
