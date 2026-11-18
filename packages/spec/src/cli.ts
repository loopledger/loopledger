// The validator CLI (`pnpm validate`, REQ-VALIDATE-*): files in, one line per violation
// `<file>:<index>:<path> <message>` out, exit 1 when any line is printed. Passports go through `validatePassport` and
// `catalogErrors`; an events file is an array checked per event (`validateEvent`, `signerBindingErrors`,
// `dispositionFamilyErrors`, `dispositionClassificationErrors`) and as a set (`validateEventSet`), and every signature
// is verified as an independent detached JWS against the Ed25519 public key in its `did:key` `key_id` — that check is
// written from packages/spec/README.md (Signatures) alone and shares no code with the ledger, as
// packages/spec/test/spec.test.ts does.
import { createPublicKey, verify } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { catalogErrors } from "./catalog";
import { dispositionClassificationErrors, dispositionFamilyErrors } from "./disposition";
import { signerBindingErrors } from "./signers";
import type { EventType } from "./signers";
import { validateEvent, validatePassport } from "./validate";
import { validateEventSet } from "./weighing";
import type { WeighingEvent } from "./weighing";

export interface ValidatorResult {
  /** One line per violation (and, in `--expect-invalid` mode, per file that passed), `<file>:<index>:<path> <message>`. */
  readonly lines: readonly string[];
  /** Files that produced no line, named by `--expect-invalid`. */
  readonly passed: readonly string[];
  /** False when any violation was found, or — in `--expect-invalid` mode — when any file produced none. */
  readonly ok: boolean;
}

type Json = Record<string, unknown>;

const isObject = (v: unknown): v is Json => v !== null && typeof v === "object" && !Array.isArray(v);

const message = (e: unknown): string => (e instanceof Error ? e.message : String(e));

// --- file collection -----------------------------------------------------------------------------------------------

const isDocument = (p: string): boolean => p.endsWith(".passport.json") || p.endsWith(".events.json");

const collect = (p: string): string[] => {
  if (!statSync(p).isDirectory()) return isDocument(p) ? [p] : [];
  const files: string[] = [];
  for (const e of readdirSync(p, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (e.name === "node_modules") continue;
    const child = join(p, e.name);
    if (e.isDirectory()) files.push(...collect(child));
    else if (isDocument(child)) files.push(child);
  }
  return files;
};

// --- independent JWS check (no ledger code) -------------------------------------------------------------------------

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");

/** The raw 32-byte Ed25519 public key of a `did:key:z6Mk…` identifier (multibase base58btc, multicodec 0xed01). */
const didKeyBytes = (kid: string): Buffer | undefined => {
  if (!kid.startsWith("did:key:z")) return undefined;
  let n = 0n;
  for (const c of kid.slice("did:key:z".length)) {
    const digit = B58.indexOf(c);
    if (digit < 0) return undefined;
    n = n * 58n + BigInt(digit);
  }
  const bytes = Buffer.from(n.toString(16).padStart(68, "0"), "hex");
  return bytes.length === 34 && bytes[0] === 0xed && bytes[1] === 0x01 ? bytes.subarray(2) : undefined;
};

const jcs = (v: unknown): string => {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(jcs).join(",")}]`;
  const keys = Object.keys(v).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs((v as Json)[k])}`).join(",")}}`;
};

/** The signed event: the document without `signatures` and `held`. */
const subject = (doc: Json): Json => {
  const { signatures: _s, held: _h, ...rest } = doc;
  return rest;
};

const jwsVerifies = (event: Json, s: Json): boolean => {
  const raw = s["signature"];
  const kid = s["key_id"];
  if (typeof raw !== "string" || typeof kid !== "string") return false;
  const [h, payload, value] = raw.split(".");
  const publicKey = didKeyBytes(kid);
  if (!h || payload !== "" || value === undefined || !publicKey) return false;
  const evidence = Array.isArray(event["evidence"]) ? event["evidence"].filter(isObject) : [];
  const body = jcs({
    event: subject(event),
    evidence_hashes: evidence.map((e) => e["content_hash"]).sort(),
    party_id: s["party_id"],
    role_at_signing: s["role_at_signing"],
    signed_at: s["signed_at"],
  });
  if (h !== Buffer.from(jcs({ alg: s["alg"], kid })).toString("base64url")) return false;
  try {
    const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519, publicKey]), format: "der", type: "spki" });
    return verify(null, Buffer.from(`${h}.${Buffer.from(body).toString("base64url")}`), key, Buffer.from(value, "base64url"));
  } catch {
    return false;
  }
};

// --- per-document checks --------------------------------------------------------------------------------------------

const signaturesOf = (event: Json): Json[] => (Array.isArray(event["signatures"]) ? event["signatures"].filter(isObject) : []);

const eventLines = (file: string, index: number, event: unknown): string[] => {
  const at = (path: string, m: string): string => `${file}:${index}:${path} ${m}`;
  if (!isObject(event)) return [at("/", "is not an object")];
  const schema = validateEvent(event);
  const lines = schema.errors.map((e) => `${file}:${index}:${e}`);
  if (!schema.valid) return lines;
  const type = event["event_type"] as EventType;
  const payload = isObject(event["payload"]) ? event["payload"] : {};
  const signatures = signaturesOf(event);
  for (const e of signerBindingErrors(type, payload, signatures.map((s) => ({ party_id: String(s["party_id"]), role_at_signing: String(s["role_at_signing"]) })))) {
    lines.push(at("/signatures", e));
  }
  for (const e of dispositionFamilyErrors(payload)) lines.push(at("/payload/family", e));
  for (const e of dispositionClassificationErrors(payload)) lines.push(at("/payload/lines", e));
  signatures.forEach((s, i) => {
    if (!jwsVerifies(event, s)) lines.push(at(`/signatures/${i}`, `signature does not verify against did:key ${String(s["key_id"])}`));
  });
  return lines;
};

const eventsFileLines = (file: string, doc: unknown): string[] => {
  if (!Array.isArray(doc)) return [`${file}:0:/ is not an array of events`];
  const events = doc.filter(isObject);
  const indexById = new Map(events.map((e, i) => [String(e["event_id"]), i]));
  const lines = events.flatMap((event, index) => eventLines(file, index, event));
  for (const e of validateEventSet(events as unknown as WeighingEvent[])) {
    const owner = /\bevt_\S+/.exec(e)?.[0];
    lines.push(`${file}:${owner !== undefined && indexById.has(owner) ? indexById.get(owner) : 0}:/payload/fractions ${e}`);
  }
  return lines;
};

const passportLines = (file: string, doc: unknown): string[] => {
  const schema = validatePassport(doc);
  const lines = schema.errors.map((e) => `${file}:0:${e}`);
  if (isObject(doc)) for (const e of catalogErrors(doc)) lines.push(`${file}:0:/ ${e}`);
  return lines;
};

const checkFile = (file: string): string[] => {
  let doc: unknown;
  try {
    doc = JSON.parse(readFileSync(file, "utf8"));
  } catch (e) {
    return [`${file}:0:/ cannot be parsed as JSON: ${message(e)}`];
  }
  return file.endsWith(".passport.json") ? passportLines(file, doc) : eventsFileLines(file, doc);
};

// --- entry points ---------------------------------------------------------------------------------------------------

/** Validates every `*.passport.json` and `*.events.json` file under each path (a file or a directory, walked). */
export const validatePaths = (paths: readonly string[]): ValidatorResult => {
  const lines: string[] = [];
  const passed: string[] = [];
  for (const p of paths) {
    let files: string[];
    try {
      files = collect(p);
    } catch (e) {
      lines.push(`${p}:0:/ cannot be read: ${message(e)}`);
      continue;
    }
    if (files.length === 0) {
      lines.push(`${p}:0:/ no *.passport.json or *.events.json files`);
      continue;
    }
    for (const file of files) {
      const fileLines = checkFile(file);
      lines.push(...fileLines);
      if (fileLines.length === 0) passed.push(file);
    }
  }
  return { lines, passed, ok: lines.length === 0 };
};

/** The CLI behaviour: argv without the script name. Exit code 2 is a usage error, 1 any failure, 0 success. */
export const run = (argv: readonly string[]): ValidatorResult & { exitCode: number } => {
  const expectInvalid = argv[0] === "--expect-invalid";
  const paths = expectInvalid ? argv.slice(1) : [...argv];
  if (paths.length === 0) return { lines: ["usage: pnpm validate <file|dir>… | pnpm validate --expect-invalid <dir>"], passed: [], ok: false, exitCode: 2 };
  if (expectInvalid) {
    const result = validatePaths(paths);
    const lines = [...result.lines, ...result.passed.map((f) => `${f}:0:/ expected at least one violation but the file passed`)];
    return { lines, passed: result.passed, ok: result.passed.length === 0, exitCode: result.passed.length > 0 ? 1 : 0 };
  }
  const result = validatePaths(paths);
  return { ...result, exitCode: result.ok ? 0 : 1 };
};

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { lines, exitCode } = run(process.argv.slice(2));
  for (const line of lines) console.log(line);
  process.exit(exitCode);
}
