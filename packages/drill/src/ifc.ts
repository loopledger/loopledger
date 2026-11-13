// The drill's revision performance as a minimal IFC4 STEP file (REQ-DRILL-007, REQ-DRILL-008): one property set,
// LoopLedger_RecoveryPerformance, per catalog revision, attached through IfcRelDefinesByProperties to the
// IfcTypeObject whose GlobalId is the revision's `ifc_type_guid` design_ref. Hand-built text, no dependency.
import { createHash } from "node:crypto";
import { revisionId } from "./catalog";
import type { CatalogRevision } from "./catalog";
import { POOLED } from "./performance";
import type { Basis, Figure, RevisionRow } from "./performance";

export const PROPERTY_SET = "LoopLedger_RecoveryPerformance";

export interface IfcResult {
  step: string;
  /** Revisions left out for want of an `ifc_type_guid` or of a pooled row: `manufacturer model_reference version n`. */
  skipped: string[];
  /** `true` when any row written is from a pilot ledger: the file is test data, never evidence (REQ-DRILL-013). */
  pilot: boolean;
}

type Value = { kind: "boolean"; value: boolean } | { kind: "real"; value: number } | { kind: "integer"; value: number } | { kind: "label"; value: string } | null;

const IFC_GUID = /^[0-3][0-9A-Za-z_$]{21}$/;
const BASE64 = ["0123456789", "ABCDEFGHIJKLM", "NOPQRSTUVWXYZ", "abcdefghijklm", "nopqrstuvwxyz", "_$"].join("");

/** A STEP string: quotes doubled, backslashes doubled, anything outside printable ASCII as \X2\…\X0\. */
const str = (text: string): string => {
  let out = "";
  for (const ch of text) {
    const code = ch.codePointAt(0)!;
    if (ch === "'") out += "''";
    else if (ch === "\\") out += "\\\\";
    else if (code >= 0x20 && code < 0x7f) out += ch;
    else out += `\\X2\\${code.toString(16).toUpperCase().padStart(code > 0xffff ? 8 : 4, "0")}\\X0\\`;
  }
  return `'${out}'`;
};

const real = (value: number): string => {
  const text = String(value);
  return /^-?\d+$/.test(text) ? `${text}.` : text.toUpperCase();
};

/** A GlobalId derived from a seed, so the file is the same every time it is written from the same rows. */
const guid = (seed: string): string => {
  const bytes = createHash("sha256").update(seed).digest().subarray(0, 16);
  let bits = BigInt(`0x${bytes.toString("hex")}`);
  let out = "";
  for (let i = 0; i < 21; i++, bits >>= 6n) out = BASE64.charAt(Number(bits & 63n)) + out;
  return BASE64.charAt(Number(bits & 3n)) + out;
};

const basisText = (basis: Basis): string => (basis.kind === "measured" ? `measured n=${basis.n}` : "declared");

/** The properties of one revision row: each figure with its basis and the leakage of its revision beside it. */
const properties = (item: CatalogRevision, row: RevisionRow): [string, Value][] => {
  const out: [string, Value][] = [];
  // The revision's identity under the Pset_ManufacturerTypeInformation property names (REQ-PASSPORT-009).
  out.push(["Manufacturer", { kind: "label", value: item.manufacturer }]);
  out.push(["ModelReference", { kind: "label", value: item.model_reference }]);
  if (item.article_number !== undefined) out.push(["ArticleNumber", { kind: "label", value: item.article_number }]);
  if (item.gtin !== undefined) out.push(["GlobalTradeItemNumber", { kind: "label", value: item.gtin }]);
  const figure = (name: string, f: Figure): void => {
    out.push([name, f.value === null ? null : { kind: "real", value: f.value }]);
    out.push([`${name}_basis`, { kind: "label", value: basisText(f.basis) }]);
    out.push([`${name}_leakage_leaked`, { kind: "integer", value: f.leakage.leaked }]);
    out.push([`${name}_leakage_rate`, f.leakage.rate === null ? null : { kind: "real", value: f.leakage.rate }]);
  };
  out.push(["pilot", { kind: "boolean", value: row.pilot }]);
  out.push(["assets_removed", { kind: "integer", value: row.assets_removed }]);
  out.push(["leakage_born", { kind: "integer", value: row.leakage.born }]);
  out.push(["leakage_recovered", { kind: "integer", value: row.leakage.recovered }]);
  out.push(["leakage_in_service", { kind: "integer", value: row.leakage.in_service }]);
  out.push(["leakage_leaked", { kind: "integer", value: row.leakage.leaked }]);
  out.push(["leakage_rate", row.leakage.rate === null ? null : { kind: "real", value: row.leakage.rate }]);
  figure("intact_removal_rate", row.intact_removal_rate);
  figure("diversion_pct", row.diversion_pct);
  for (const name of ["weighed_kg", "diverted_kg", "energy_recovery_kg", "disposed_kg", "residual_kg"] as const) out.push([`diversion_${name}`, { kind: "real", value: row.diversion_pct[name] }]);
  out.push(["diversion_unbalanced", { kind: "integer", value: row.diversion_pct.unbalanced }]);
  for (const method of ["intact", "destructive"] as const) {
    const removal = row.removal[method];
    if (removal === undefined) continue;
    figure(`removal_${method}_p50_min`, removal.p50);
    figure(`removal_${method}_p90_min`, removal.p90);
  }
  return out;
};

const nominal = (value: Value): string => {
  if (value === null) return "$";
  if (value.kind === "boolean") return `IFCBOOLEAN(${value.value ? ".T." : ".F."})`;
  if (value.kind === "real") return `IFCREAL(${real(value.value)})`;
  if (value.kind === "integer") return `IFCINTEGER(${value.value})`;
  return `IFCLABEL(${str(value.value)})`;
};

/** Writes the pooled revision performance of every catalog revision that carries an `ifc_type_guid` design_ref. */
export const writeIfc = (rows: readonly RevisionRow[], catalog: readonly CatalogRevision[]): IfcResult => {
  const entities: string[] = [];
  const add = (body: string): number => entities.push(body);
  const skipped: string[] = [];

  add("IFCPERSON($,'LoopLedger',$,$,$,$,$,$)");
  add("IFCORGANIZATION($,'LoopLedger',$,$,$)");
  add("IFCPERSONANDORGANIZATION(#1,#2,$)");
  add("IFCAPPLICATION(#2,'0.0','LoopLedger drill','loopledger-drill')");
  const owner = add("IFCOWNERHISTORY(#3,#4,$,.NOCHANGE.,$,$,$,0)");

  for (const item of catalog) {
    const label = `${item.model_reference} ${item.label}`;
    const typeGuid = item.design_ref?.find((d) => d.scheme === "ifc_type_guid")?.value;
    const row = rows.find((r) => revisionId(r) === revisionId(item) && r.band === POOLED);
    if (typeGuid === undefined || !IFC_GUID.test(typeGuid) || row === undefined) {
      skipped.push(`${item.manufacturer} ${item.model_reference} version ${item.version}`);
      continue;
    }
    const values = properties(item, row).map(([name, value]) => add(`IFCPROPERTYSINGLEVALUE(${str(name)},$,${nominal(value)},$)`));
    const set = add(`IFCPROPERTYSET('${guid(`pset:${typeGuid}`)}',#${owner},${str(PROPERTY_SET)},$,(${values.map((v) => `#${v}`).join(",")}))`);
    const type = add(`IFCTYPEOBJECT('${typeGuid}',#${owner},${str(label)},$,$,$)`);
    add(`IFCRELDEFINESBYPROPERTIES('${guid(`rel:${typeGuid}`)}',#${owner},$,$,(#${type}),#${set})`);
  }

  const step = [
    "ISO-10303-21;",
    "HEADER;",
    "FILE_DESCRIPTION(('ViewDefinition [NotAssigned]'),'2;1');",
    "FILE_NAME('loopledger-recovery-performance.ifc','1970-01-01T00:00:00',('LoopLedger'),('LoopLedger'),'loopledger-drill','loopledger-drill','');",
    "FILE_SCHEMA(('IFC4'));",
    "ENDSEC;",
    "DATA;",
    ...entities.map((body, i) => `#${i + 1}=${body};`),
    "ENDSEC;",
    "END-ISO-10303-21;",
    "",
  ].join("\n");
  return { step, skipped, pilot: rows.some((r) => r.pilot) };
};
