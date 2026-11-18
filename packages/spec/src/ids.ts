// Ids for events, assets and signatures: a prefix and a 26-character Crockford ULID (48-bit time, 80-bit random).
// The same form apps/capture/src/ids.ts mints on a device (the spec names it the reference); that copy stays
// as is in this batch — porting capture is out of scope (01-passport-custody, scope boundaries).
const CROCKFORD = ["0123456789", "ABCDEFGH", "JK", "MN", "PQRST", "VWXYZ"].join("");

export const ID_PREFIXES = ["evt", "ast", "sig"] as const;

export type IdPrefix = (typeof ID_PREFIXES)[number];

export const ulid = (now: number = Date.now()): string => {
  let time = "";
  for (let v = now, i = 0; i < 10; i++, v = Math.floor(v / 32)) time = CROCKFORD.charAt(v % 32) + time;
  const random = globalThis.crypto.getRandomValues(new Uint8Array(16));
  return time + Array.from(random, (b) => CROCKFORD.charAt(b % 32)).join("");
};

export const newId = (prefix: IdPrefix, now?: number): string => `${prefix}_${ulid(now)}`;

/** True when the value is `<prefix>_<26 Crockford characters>` for one of the minted prefixes. */
export const isId = (value: string, prefix?: IdPrefix): boolean =>
  new RegExp(`^(${prefix ?? ID_PREFIXES.join("|")})_` + "[0-9A-HJKMNP-TV-Z]{26}$").test(value);

// The GS1 Digital Link URI of a carrier (`https://<host>/01/<gtin>/21/<serial>`): the regex the server's
// by-carrier lookup uses here, and the field app (PR 7) imports. apps/capture/src/pilot.ts keeps its own
// copy for now — porting capture is out of scope for this batch (01-passport-custody, scope boundaries);
// unifying it is a follow-up for the batch owner to weigh.
const DIGITAL_LINK = /^https?:\/\/[^/\s]+\/01\/([0-9]{14})\/21\/([A-Za-z0-9._~%-]{1,20})$/;

/** The GTIN-14 and serial of a GS1 Digital Link URI, or undefined when the text is not one (a malformed
 * percent escape is not a readable link either). */
export const parseDigitalLink = (text: string): { gtin: string; serial: string } | undefined => {
  const match = DIGITAL_LINK.exec(text.trim());
  if (!match) return undefined;
  try {
    return { gtin: match[1]!, serial: decodeURIComponent(match[2]!) };
  } catch {
    return undefined;
  }
};

/** The ISO/IEC 15459 identifier of a carrier: `(01)<gtin>(21)<serial>`, as the passport schema stores it. */
export const digitalLinkIdentifier = (gtin: string, serial: string): string => `(01)${gtin}(21)${serial}`;
