// The part of a catalog item the drill reads: its revision lineage, joint graph and declared recovery labor.
// A catalog item has the shape of a passport's catalog fields (REQ-PASSPORT-003, REQ-PASSPORT-008).
// A revision is identified by manufacturer, model reference and version (REQ-PASSPORT-009); `label` is display-only.

export type Method = "intact" | "destructive";

/** What identifies a catalog revision: a manufacturer's `party_id`, a model reference and a version. */
export interface RevisionKey {
  manufacturer: string;
  model_reference: string;
  version: number;
}

export interface CatalogRevision extends RevisionKey {
  article_number?: string;
  gtin?: string;
  /** Display only, from `revision.label` (G4, G5); never matched on. */
  label: string;
  supersedes?: RevisionKey;
  design_ref?: { scheme: string; value: string }[];
  components: { component_id: string; material: string }[];
  joints: { joint_id: string; type: string; between: [string, string] }[];
  recovery_method: { method: Method; declared_labor_min: number }[];
}

/** The last path segment of a vocabulary IRI: `https://loopledger.org/vocab/joint_type/bonded` is `bonded`. */
export const termId = (iri: string): string => iri.slice(iri.lastIndexOf("/") + 1);

const keyOf = (ref: Record<string, any>): RevisionKey => ({ manufacturer: ref.manufacturer.party_id, model_reference: ref.model_reference, version: ref.version });

/** A revision key as one string; a missing version is the unknown revision. Versions are padded so keys sort numerically. */
export const revisionId = (key: { manufacturer: string; model_reference: string; version: number | null }): string =>
  [key.manufacturer, key.model_reference, key.version === null ? "unknown" : String(key.version).padStart(8, "0")].join("\u0000");

export const sameRevision = (a: RevisionKey, b: RevisionKey): boolean => revisionId(a) === revisionId(b);

/** A catalog revision from a passport document that carries `catalog_ref`, a revision label and the catalog fields. */
export const catalogRevision = (passport: Record<string, any>): CatalogRevision => {
  const ref = passport.catalog_ref;
  const label = passport.revision?.label;
  if (!ref || typeof label !== "string") throw new Error("a catalog revision needs a catalog_ref and a revision label");
  return {
    ...keyOf(ref),
    ...(ref.article_number === undefined ? {} : { article_number: ref.article_number }),
    ...(ref.gtin === undefined ? {} : { gtin: ref.gtin }),
    label,
    ...(ref.supersedes === undefined ? {} : { supersedes: keyOf(ref.supersedes) }),
    ...(passport.design_ref === undefined ? {} : { design_ref: passport.design_ref.map((d: any) => ({ scheme: d.scheme, value: d.value })) }),
    components: (passport.components ?? []).map((c: any) => ({ component_id: c.component_id, material: termId(c.material) })),
    joints: (passport.joints ?? []).map((j: any) => ({ joint_id: j.joint_id, type: termId(j.type), between: j.between })),
    recovery_method: (passport.recovery_method ?? []).map((m: any) => ({ method: m.method, declared_labor_min: m.declared_labor_min })),
  };
};

/** The revision whose `supersedes` ref names `key`: the other half of the A/B pair design feedback compares. */
export const successorOf = (catalog: readonly CatalogRevision[], key: RevisionKey): CatalogRevision | undefined =>
  catalog.find((c) => c.supersedes !== undefined && sameRevision(c.supersedes, key));
