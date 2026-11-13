// Required signers per event type, transcribed from the "Event taxonomy and required signers" table in
// docs/kickoff/SPEC-data-model.md §3 (and SPEC-passport.md for `rule_version_applied`). This is the one place the count
// lives: schema/event.schema.json repeats it and a test fails if the two differ; #7 imports it rather than keeping a map.

export const EVENT_TYPES = [
  "asset_born",
  "carrier_attached",
  "observed",
  "identity_resolved",
  "route_proposed",
  "route_confirmed",
  "route_fallback",
  "removed",
  "custody_transferred",
  "weighed",
  "processed",
  "maintained",
  "disposition_final",
  "record_transferred",
  "exception_opened",
  "exception_updated",
  "exception_closed",
  "gate_passed",
  "telemetry",
  "rule_version_applied",
] as const;

export type EventType = (typeof EVENT_TYPES)[number];

export interface SignerRule {
  /** Signatures needed before the event stops being `held`. 2 means two-party. */
  readonly min: 1 | 2;
  /** `all`: every role signs (two-party). `any`: at least one signature comes from one of the roles. */
  readonly mode: "any" | "all";
  /** `role_at_signing` values. Empty means any role. */
  readonly roles: readonly string[];
  /** A signer the table adds in some cases that v0.1 does not enforce (it needs tenant config or payload context). */
  readonly conditional?: string;
}

export const REQUIRED_SIGNERS: Readonly<Record<EventType, SignerRule>> = {
  asset_born: { min: 1, mode: "any", roles: ["adapter", "operator"] },
  carrier_attached: { min: 1, mode: "any", roles: ["operator", "manufacturer"] },
  observed: { min: 1, mode: "any", roles: ["adapter"], conditional: "human confirm when confidence is below the tenant threshold" },
  identity_resolved: { min: 1, mode: "any", roles: ["system"], conditional: "adjudicator when the resolution is manual" },
  route_proposed: { min: 1, mode: "any", roles: ["system"] },
  route_confirmed: { min: 2, mode: "all", roles: ["operator", "receiver"] },
  route_fallback: { min: 1, mode: "any", roles: ["system"] },
  removed: { min: 2, mode: "all", roles: ["crew", "operator"] },
  custody_transferred: { min: 2, mode: "all", roles: ["sender", "receiver"] },
  weighed: { min: 1, mode: "any", roles: ["scale"] },
  processed: { min: 1, mode: "any", roles: ["facility"], conditional: "a second verifier for a controlled demark" },
  maintained: { min: 1, mode: "any", roles: ["maintainer"], conditional: "owner" },
  disposition_final: { min: 2, mode: "all", roles: ["receiver", "operator"] },
  record_transferred: { min: 2, mode: "all", roles: ["transferring_owner", "receiving_owner"] },
  exception_opened: { min: 1, mode: "any", roles: [] },
  exception_updated: { min: 1, mode: "any", roles: [] },
  exception_closed: { min: 1, mode: "any", roles: [] },
  gate_passed: { min: 1, mode: "any", roles: ["system", "inspector"] },
  telemetry: { min: 1, mode: "any", roles: ["device"] },
  rule_version_applied: { min: 1, mode: "any", roles: ["system"] },
};

export const requiredSigners = (type: EventType): SignerRule => REQUIRED_SIGNERS[type];

/**
 * The payload field whose party each bound signing role must be. Roles missing here (`removed`, `disposition_final`
 * and the `operator` of `route_confirmed`) are only held distinct: the payload has no party to bind them to.
 */
export const SIGNER_PARTY_FIELDS: Readonly<Partial<Record<EventType, Readonly<Record<string, string>>>>> = {
  custody_transferred: { sender: "from_party_id", receiver: "to_party_id" },
  record_transferred: { transferring_owner: "from_owner_party_id", receiving_owner: "to_owner_party_id" },
  route_confirmed: { receiver: "receiver_party_id" },
};

/** The signature fields the binding check reads. */
export interface SignerBinding {
  readonly party_id: string;
  readonly role_at_signing: string;
}

/**
 * What a two-party event that is not held breaks: a bound role signed by a party other than the payload's, or two
 * required roles signed by the same party (whatever their keys). Only signatures present are checked, so a held
 * event with one signature passes. JSON Schema cannot compare a signature to the payload, hence code.
 */
export const signerBindingErrors = (
  type: EventType,
  payload: Readonly<Record<string, unknown>>,
  signatures: readonly SignerBinding[],
): string[] => {
  const rule = REQUIRED_SIGNERS[type];
  if (rule.min !== 2) return [];
  const errors: string[] = [];
  const present = rule.roles.flatMap((role) => signatures.filter((s) => s.role_at_signing === role));
  const fields = SIGNER_PARTY_FIELDS[type] ?? {};
  for (const s of present) {
    const field = fields[s.role_at_signing];
    if (field !== undefined && payload[field] !== s.party_id) errors.push(`${s.role_at_signing} signer is not payload ${field}`);
  }
  if (new Set(present.map((s) => s.party_id)).size < present.length) errors.push("two roles are signed by the same party");
  return errors;
};
