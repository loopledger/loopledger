// The VCDM 2.0 credential an event or a passport is exported as, and the did:web resolution rule
// (packages/spec/README.md "VC-JOSE-COSE envelope"). Pure: the clock, the issuer and the keys come from the caller;
// the issuer JWS is in `packages/ledger`.
import { EVENT_CONTEXT } from "./validate";

export const VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2";
/** The UNTP release the credential shape is read at: the one that goes with the DPP 0.7.0 alignment target. */
export const UNTP_VC_PROFILE_VERSION = "0.7.0";
/** The media type of a credential secured with VC-JOSE-COSE as a JWS. */
export const VC_MEDIA_TYPE = "application/vc+jwt";

export type CredentialKind = "Event" | "Passport";

export interface Credential {
  "@context": [typeof VC_CONTEXT_V2, typeof EVENT_CONTEXT];
  type: ["VerifiableCredential", CredentialKind];
  issuer: string;
  validFrom: string;
  credentialSubject: Record<string, unknown>;
}

const DID_WEB = /^did:web:[A-Za-z0-9.%_-]+(?::[A-Za-z0-9._%~-]+)*$/;
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

/**
 * The URL a `did:web` resolves to: `did:web:host[:path…]` is `https://host/[path/…]did.json`, and with no path
 * `https://host/.well-known/did.json`. A `%3A` in the host is a port. Throws when the identifier is not a `did:web`.
 */
export const didWebUrl = (did: string): string => {
  if (!DID_WEB.test(did)) throw new Error(`${did} is not a did:web identifier`);
  const [host, ...path] = did.slice("did:web:".length).split(":");
  const base = `https://${decodeURIComponent(host!)}`;
  return path.length === 0 ? `${base}/.well-known/did.json` : `${base}/${path.join("/")}/did.json`;
};

/**
 * The credential for an event or a passport. The subject is the document verbatim, so the #73 signatures inside it
 * still verify; the issuer is the exporting tenant's `did:web`, never an event signer.
 */
export const buildCredential = (
  kind: CredentialKind,
  subject: Record<string, unknown>,
  issuer: string,
  validFrom: string,
): Credential => {
  if (!DID_WEB.test(issuer)) throw new Error(`issuer ${issuer} is not a did:web identifier`);
  return {
    "@context": [VC_CONTEXT_V2, EVENT_CONTEXT],
    type: ["VerifiableCredential", kind],
    issuer,
    validFrom,
    credentialSubject: subject,
  };
};

/** One line per way the value is not an event or passport credential of this spec; empty when it is one. */
export const credentialErrors = (value: unknown): string[] => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return ["credential is not an object"];
  const c = value as Record<string, unknown>;
  const errors: string[] = [];
  const context = c["@context"];
  if (!Array.isArray(context) || context[0] !== VC_CONTEXT_V2 || context[1] !== EVENT_CONTEXT || context.length !== 2) {
    errors.push(`@context is not [${VC_CONTEXT_V2}, ${EVENT_CONTEXT}]`);
  }
  const type = c.type;
  const kind = Array.isArray(type) ? type[1] : undefined;
  if (!Array.isArray(type) || type.length !== 2 || type[0] !== "VerifiableCredential" || (kind !== "Event" && kind !== "Passport")) {
    errors.push("type is not [VerifiableCredential, Event] or [VerifiableCredential, Passport]");
  }
  if (typeof c.issuer !== "string" || !DID_WEB.test(c.issuer)) errors.push("issuer is not a did:web identifier");
  if (typeof c.validFrom !== "string" || !DATE_TIME.test(c.validFrom) || Number.isNaN(Date.parse(c.validFrom))) {
    errors.push("validFrom is not an RFC 3339 date-time");
  }
  const subject = c.credentialSubject;
  if (subject === null || typeof subject !== "object" || Array.isArray(subject)) {
    errors.push("credentialSubject is not an object");
  } else if ((subject as Record<string, unknown>)["@type"] !== kind) {
    errors.push("credentialSubject @type does not equal the credential type");
  }
  return errors;
};
