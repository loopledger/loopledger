// The id and carrier helpers: the Crockford ULID mint and shape check (REQ-SPEC-011) and the GS1
// Digital Link regex the server's by-carrier lookup uses (REQ-PASSPORT-004).
import { describe, expect, it } from "vitest";
import { digitalLinkIdentifier, isId, newId, parseDigitalLink } from "../src/ids";

describe("ids", () => {
  it("mints prefixed Crockford ULIDs that isId accepts", () => {
    for (const prefix of ["evt", "ast", "sig"] as const) {
      const id = newId(prefix);
      expect(id.startsWith(`${prefix}_`)).toBe(true);
      expect(isId(id, prefix)).toBe(true);
      expect(isId(id)).toBe(true);
      expect(isId(id, prefix === "evt" ? "ast" : "evt")).toBe(false);
    }
  });

  it("parses a GS1 Digital Link URI into its GTIN-14 and serial", () => {
    expect(parseDigitalLink("https://id.gs1.org/01/09506000134352/21/NS000001")).toEqual({
      gtin: "09506000134352",
      serial: "NS000001",
    });
    expect(parseDigitalLink("http://example.com/01/09506000134352/21/NS%2F1")).toEqual({
      gtin: "09506000134352",
      serial: "NS/1",
    });
    expect(parseDigitalLink("https://id.gs1.org/01/short/21/NS000001")).toBeUndefined();
    expect(parseDigitalLink("not a link")).toBeUndefined();
    // A malformed percent escape is not a readable link: it must be refused, not thrown.
    expect(parseDigitalLink("https://id.gs1.org/01/09506000134352/21/NS%zz")).toBeUndefined();
  });

  it("builds the ISO/IEC 15459 identifier the passport schema stores", () => {
    expect(digitalLinkIdentifier("09506000134352", "NS000001")).toBe("(01)09506000134352(21)NS000001");
  });
});
