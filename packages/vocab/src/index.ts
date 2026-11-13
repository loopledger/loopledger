// Loads the published v0.1 schemes (joint-type.jsonld, material.jsonld, cause.jsonld) and resolves terms against them.
import { readFileSync } from "node:fs";

export const SCHEMES = ["joint_type", "material", "cause"] as const;
export type Scheme = (typeof SCHEMES)[number];

export interface Term {
  "@id": string;
  term_id: string;
  scheme: Scheme;
  label: string;
  external_refs: string[];
  iso_20887_principles?: { clause: string; name: string }[];
  design_addressable?: boolean;
  status: string;
}

export interface SchemeFile {
  "@id": string;
  scheme: Scheme;
  version: string;
  terms: Term[];
}

const FILES: Record<Scheme, string> = { joint_type: "joint-type.jsonld", material: "material.jsonld", cause: "cause.jsonld" };

export const VOCABULARY: Record<Scheme, SchemeFile> = Object.fromEntries(
  SCHEMES.map((s) => [s, JSON.parse(readFileSync(new URL(`../${FILES[s]}`, import.meta.url), "utf8")) as SchemeFile]),
) as Record<Scheme, SchemeFile>;

export const isTermInScheme = (scheme: string, termId: string): boolean =>
  (SCHEMES as readonly string[]).includes(scheme) && VOCABULARY[scheme as Scheme].terms.some((t) => t.term_id === termId);

// A term IRI is `https://loopledger.org/vocab/<scheme>/<term_id>`, the one canonical form; any versioned form does not resolve.
export const termForIri = (iri: string): Term | undefined => {
  const m = /^https:\/\/loopledger\.org\/vocab\/([a-z_]+)\/([a-z][a-z0-9_]*)$/.exec(iri);
  if (!m) return undefined;
  const [, scheme, termId] = m;
  if (!(SCHEMES as readonly string[]).includes(scheme!)) return undefined;
  return VOCABULARY[scheme as Scheme].terms.find((t) => t.term_id === termId);
};
