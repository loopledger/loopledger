// Ids for events, assets and signatures: a prefix and a 26-character Crockford ULID (48-bit time, 80-bit random).
// Mirrors apps/capture/src/ids.ts, the device reference; the app is not imported so the spec package stays free of app code.
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
