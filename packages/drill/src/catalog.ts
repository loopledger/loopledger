// The part of a catalog item the drill reads: its revision lineage, joint graph and declared recovery labor.
// A catalog item has the shape of a passport's catalog fields (REQ-PASSPORT-003, REQ-PASSPORT-008).

export type Method = "intact" | "destructive";

export interface CatalogRevision {
  catalog_id: string;
  revision: string;
  supersedes?: string;
  design_ref?: { scheme: string; value: string }[];
  components: { component_id: string; material: string }[];
  joints: { joint_id: string; type: string; between: [string, string] }[];
  recovery_method: { method: Method; declared_labor_min: number }[];
}

/** The last path segment of a vocabulary IRI: `https://loopledger.org/vocab/joint_type/bonded` is `bonded`. */
export const termId = (iri: string): string => iri.slice(iri.lastIndexOf("/") + 1);

/** A catalog revision from a passport document that carries `catalog_ref`, a revision label and the catalog fields. */
export const catalogRevision = (passport: Record<string, any>): CatalogRevision => {
  const ref = passport.catalog_ref;
  const label = passport.revision?.label;
  if (!ref || typeof label !== "string") throw new Error("a catalog revision needs a catalog_ref and a revision label");
  return {
    catalog_id: ref.catalog_id,
    revision: label,
    ...(ref.supersedes === undefined ? {} : { supersedes: ref.supersedes }),
    ...(passport.design_ref === undefined ? {} : { design_ref: passport.design_ref.map((d: any) => ({ scheme: d.scheme, value: d.value })) }),
    components: (passport.components ?? []).map((c: any) => ({ component_id: c.component_id, material: termId(c.material) })),
    joints: (passport.joints ?? []).map((j: any) => ({ joint_id: j.joint_id, type: termId(j.type), between: j.between })),
    recovery_method: (passport.recovery_method ?? []).map((m: any) => ({ method: m.method, declared_labor_min: m.declared_labor_min })),
  };
};

/** The revision that names `revision` in its `supersedes`: the other half of the A/B pair design feedback compares. */
export const successorOf = (catalog: readonly CatalogRevision[], catalogId: string, revision: string): CatalogRevision | undefined =>
  catalog.find((c) => c.catalog_id === catalogId && c.supersedes === revision);
