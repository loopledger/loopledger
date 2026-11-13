// The catalog-revision rules JSON Schema cannot state because they compare two values (REQ-PASSPORT-009).

interface RevisionRef {
  manufacturer?: { party_id?: string };
  model_reference?: string;
  version?: number;
  supersedes?: RevisionRef;
}

/** The problems with one `catalog_ref`: a `supersedes` of another manufacturer or model, or one that is not an earlier version. */
export const catalogRefErrors = (ref: RevisionRef): string[] => {
  const older = ref.supersedes;
  if (older === undefined) return [];
  const errors: string[] = [];
  if (older.manufacturer?.party_id !== ref.manufacturer?.party_id) errors.push("supersedes names another manufacturer");
  if (older.model_reference !== ref.model_reference) errors.push("supersedes names another model_reference");
  if (typeof older.version !== "number" || typeof ref.version !== "number" || older.version >= ref.version) errors.push("supersedes must name a lower version");
  return errors;
};

/**
 * The problems with every `catalog_ref` in a passport (its own and its components') or an event (an `asset_born` payload),
 * each prefixed with the path of the ref.
 */
export const catalogErrors = (doc: Record<string, any>): string[] => {
  const refs: [string, RevisionRef][] = [];
  if (doc.catalog_ref) refs.push(["catalog_ref", doc.catalog_ref]);
  if (doc.payload?.catalog_ref) refs.push(["payload.catalog_ref", doc.payload.catalog_ref]);
  (doc.components ?? []).forEach((c: Record<string, any>, i: number) => {
    if (c.catalog_ref) refs.push([`components[${i}].catalog_ref`, c.catalog_ref]);
  });
  return refs.flatMap(([path, ref]) => catalogRefErrors(ref).map((e) => `${path}: ${e}`));
};
