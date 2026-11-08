import { createHash, createPrivateKey, createPublicKey, verify } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { MemoryEventStore, MemoryEvidenceStore, MemoryKeyResolver } from "@loopledger/adapter-memory";
import { buildCredential } from "@loopledger/spec";
import type { EventRow, EvidenceStore, LedgerMode, SignatureRow } from "@loopledger/ports";
import { Ledger, VERIFIERS, WEBCRYPTO_VERIFIERS, canonical, detachedSignature, eventHash, jwsHeader, jwsSigningInput, merkleRoot, sha256, signCredential, signEvent, signEventWebCrypto } from "../src/index";
import { eventRow } from "../src/crypto";
import type { EventInput } from "../src/index";

const TENANT = "acme-hospitality";
const ULID = "0123456789ABCDEFGHJKMNPQRS";
const evt = (n: number) => `evt_${ULID.slice(0, 24)}${String(n).padStart(2, "0")}`;
const ASSET = `ast_${ULID}`;
const party = (n: number) => `pty_${ULID.slice(0, 24)}${String(n).padStart(2, "0")}`;
const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");

/** Keys come from fixed seeds: nothing secret is committed. */
const keyFor = (name: string) => {
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, createHash("sha256").update(`seed:${name}`).digest()]), format: "der", type: "pkcs8" });
  const public_key = createPublicKey(privateKey).export({ format: "der", type: "spki" }).toString("base64");
  return { privateKey, public_key };
};

const keys = { sender: keyFor("sender"), receiver: keyFor("receiver"), scale: keyFor("scale"), other: keyFor("other") };
const owners: Record<keyof typeof keys, number> = { sender: 1, receiver: 2, scale: 3, other: 4 };

const setup = (mode: LedgerMode = "evidence", keyMode: "test" | "production" = mode === "pilot" ? "test" : "production") => {
  const resolver = new MemoryKeyResolver();
  for (const [name, k] of Object.entries(keys)) {
    resolver.register({ key_id: `key-${name}`, party_id: party(owners[name as keyof typeof keys]), alg: "EdDSA", mode: keyMode, public_key: k.public_key, valid_from: "2026-01-01T00:00:00Z", valid_until: "2027-01-01T00:00:00Z" });
  }
  const events = new MemoryEventStore(mode);
  const evidence = new MemoryEvidenceStore(mode);
  return { events, evidence, resolver, ledger: new Ledger(events, evidence, resolver, mode) };
};

const base = (n: number, type: string, extra: Partial<EventRow> = {}): EventRow => ({
  event_id: evt(n),
  tenant_id: TENANT,
  event_type: type,
  asset_ids: [ASSET],
  occurred_at: "2026-02-02T08:00:00Z",
  recorded_at: "2026-02-02T08:00:05Z",
  payload: { note: "opaque until #6 lands" },
  ...extra,
});

let sigCount = 0;
const sig = (event: EventRow, name: keyof typeof keys, role: string, over: Partial<SignatureRow> = {}): SignatureRow => ({
  ...signEvent(event, keys[name].privateKey, {
    sig_id: `sig_${++sigCount}`,
    key_id: `key-${name}`,
    party_id: party(owners[name]),
    role_at_signing: role,
    signed_at: "2026-02-02T08:00:10Z",
    ...over,
  }),
  ...over,
});

const custody = (n = 1): EventRow => base(n, "custody_transferred", { payload: { from_party_id: party(owners.sender), to_party_id: party(owners.receiver) } });
const weighed = (n = 2): EventRow => base(n, "weighed");

describe("REQ-LEDGER-001 events append and are never updated", () => {
  it("appends events and reads them back with their signatures", async () => {
    const { ledger } = setup();
    const event = weighed();
    expect(await ledger.append({ ...event, signatures: [sig(event, "scale", "scale")] })).toEqual({ event_id: event.event_id, held: false });
    const read = await ledger.read(TENANT, event.event_id);
    expect(read.held).toBe(false);
    expect(read.signatures).toHaveLength(1);
  });

  it("refuses to update an event: a second append of the same event_id fails and the stored event is unchanged", async () => {
    const { ledger } = setup();
    const event = weighed();
    await ledger.append({ ...event, signatures: [sig(event, "scale", "scale")] });
    const changed = { ...event, payload: { note: "rewritten" } };
    await expect(ledger.append({ ...changed, signatures: [sig(changed, "scale", "scale")] })).rejects.toThrow(/already in the log/);
    expect((await ledger.read(TENANT, event.event_id)).payload).toEqual(event.payload);
  });

  it("has no update or delete on the store, and the memory store refuses a duplicate id on its own", async () => {
    const { events } = setup();
    expect(Object.getOwnPropertyNames(Object.getPrototypeOf(events)).filter((m) => /update|delete|remove|set|put/i.test(m))).toEqual([]);
    await events.append(weighed());
    await expect(events.append(weighed())).rejects.toThrow(/already in the log/);
  });

  it("does not let a caller change a stored event through a value it passed in or read", async () => {
    const { ledger, events } = setup();
    const event = weighed();
    await ledger.append({ ...event, signatures: [sig(event, "scale", "scale")] });
    ((await events.read(event.event_id))!.payload as Record<string, unknown>).note = "tampered";
    expect((await events.read(event.event_id))!.payload).toEqual(event.payload);
  });

  it("amends only through correction_of: both events stay in the log and the projection shows the correction", async () => {
    const { ledger } = setup();
    const first = weighed(2);
    await ledger.append({ ...first, signatures: [sig(first, "scale", "scale")] });
    const fix = base(3, "weighed", { correction_of: first.event_id, payload: { note: "re-weighed" } });
    await ledger.append({ ...fix, signatures: [sig(fix, "scale", "scale")] });
    expect((await ledger.log()).map((e) => e.event_id)).toEqual([first.event_id, fix.event_id]);
    expect((await ledger.projection(TENANT)).map((e) => e.event_id)).toEqual([fix.event_id]);
    const dangling = base(4, "weighed", { correction_of: evt(99) });
    await expect(ledger.append({ ...dangling, signatures: [sig(dangling, "scale", "scale")] })).rejects.toThrow(/not in the log/);
  });

  it("refuses an event with a malformed envelope", async () => {
    const { ledger } = setup();
    const bad: EventInput[] = [
      { ...weighed(), event_id: "evt_nope" },
      { ...weighed(), tenant_id: "" },
      { ...weighed(), event_type: "made_up" },
      { ...weighed(), asset_ids: [] },
      { ...weighed(), occurred_at: "yesterday" },
      { ...weighed(), payload: [] as never },
    ];
    for (const event of bad) await expect(ledger.append(event)).rejects.toThrow();
  });
});

describe("REQ-LEDGER-002 an event with too few signatures is held and never final", () => {
  it("refuses a two-party event as final with one signer: it is held, absent from the projection and pending", async () => {
    const { ledger } = setup();
    const event = custody();
    expect(await ledger.append({ ...event, signatures: [sig(event, "sender", "sender")] })).toEqual({ event_id: event.event_id, held: true });
    expect((await ledger.read(TENANT, event.event_id)).held).toBe(true);
    expect(await ledger.projection(TENANT)).toEqual([]);
    expect((await ledger.pending(TENANT)).map((e) => e.event_id)).toEqual([event.event_id]);
  });

  it("countersign appends a signature row, completes the event and leaves the event row unchanged", async () => {
    const { ledger, events } = setup();
    const event = custody();
    await ledger.append({ ...event, signatures: [sig(event, "sender", "sender")] });
    const before = await events.read(event.event_id);
    expect(await ledger.countersign(event.event_id, sig(event, "receiver", "receiver"))).toEqual({ event_id: event.event_id, held: false });
    expect(await events.read(event.event_id)).toEqual(before);
    expect((await ledger.projection(TENANT)).map((e) => e.event_id)).toEqual([event.event_id]);
    expect(await ledger.pending(TENANT)).toEqual([]);
    await expect(ledger.countersign(event.event_id, sig(event, "other", "receiver"))).rejects.toThrow(/not held/);
  });

  it("REQ-EVENT-014 holds a custody event whose sender is not the payload's from_party_id", async () => {
    const { ledger } = setup();
    const event = base(1, "custody_transferred", { payload: { from_party_id: party(owners.other), to_party_id: party(owners.receiver) } });
    const result = await ledger.append({ ...event, signatures: [sig(event, "sender", "sender"), sig(event, "receiver", "receiver")] });
    expect(result.held).toBe(true);
    expect(await ledger.projection(TENANT)).toEqual([]);
  });

  it("holds a two-party event whose two signers share a role", async () => {
    const { ledger } = setup();
    const event = custody();
    const result = await ledger.append({ ...event, signatures: [sig(event, "sender", "sender"), sig(event, "receiver", "sender")] });
    expect(result.held).toBe(true);
  });

  it("refuses a second signature from the same party", async () => {
    const { ledger } = setup();
    const event = custody();
    await ledger.append({ ...event, signatures: [sig(event, "sender", "sender")] });
    await expect(ledger.countersign(event.event_id, sig(event, "sender", "receiver"))).rejects.toThrow(/already signed/);
  });

  it("refuses one key signing as two parties", async () => {
    const { ledger } = setup();
    const event = custody();
    const second = sig(event, "sender", "receiver", { party_id: party(2) });
    await expect(ledger.append({ ...event, signatures: [sig(event, "sender", "sender"), second] })).rejects.toThrow(/does not belong to party/);
  });

  it("refuses a signature whose role or time was edited after signing", async () => {
    const { ledger } = setup();
    const event = custody();
    const good = sig(event, "sender", "sender");
    await expect(ledger.append({ ...event, signatures: [{ ...good, role_at_signing: "receiver" }] })).rejects.toThrow(/does not verify/);
    await expect(ledger.append({ ...event, signatures: [{ ...good, signed_at: "2026-02-03T08:00:10Z" }] })).rejects.toThrow(/does not verify/);
    await expect(ledger.append({ ...event, signatures: [{ ...good, party_id: party(2) }] })).rejects.toThrow(/does not belong to party/);
  });

  it("refuses a signature that is invalid, signed over another event, or made outside its key's validity window", async () => {
    const { ledger } = setup();
    const event = custody();
    const own = sig(event, "sender", "sender");
    const forged = { ...own, signature: `${own.signature.split(".")[0]}..${sig(event, "other", "sender").signature.split(".")[2]}` };
    await expect(ledger.append({ ...event, signatures: [forged] })).rejects.toThrow(/does not verify/);
    const elsewhere = sig(weighed(), "sender", "sender");
    await expect(ledger.append({ ...event, signatures: [elsewhere] })).rejects.toThrow(/does not match the event/);
    await expect(ledger.append({ ...event, signatures: [sig(event, "sender", "sender", { signed_at: "2025-12-31T00:00:00Z" })] })).rejects.toThrow(/validity window/);
    await expect(ledger.append({ ...event, signatures: [sig(event, "sender", "sender", { key_id: "key-missing" })] })).rejects.toThrow(/unknown key/);
  });

  it("refuses signed_hash that does not cover the event's evidence hashes", async () => {
    const { ledger } = setup();
    const hash = await ledger.putEvidence(new TextEncoder().encode("photo"));
    const event = weighed(5);
    const withEvidence = { ...event, evidence: [{ evidence_id: "ev1", kind: "photo", content_hash: hash, storage_ref: "mem" }] };
    const signedWithout = sig(event, "scale", "scale");
    await expect(ledger.append({ ...withEvidence, signatures: [signedWithout] })).rejects.toThrow(/does not match the event/);
    expect((await ledger.append({ ...withEvidence, signatures: [sig(withEvidence, "scale", "scale")] })).held).toBe(false);
  });
});

describe("REQ-LEDGER-003 evidence is stored by hash and checked on read", () => {
  it("returns the bytes stored under their sha256 hash", async () => {
    const { ledger } = setup();
    const bytes = new TextEncoder().encode("scale ticket");
    const hash = await ledger.putEvidence(bytes);
    expect(hash).toBe(`sha256:${createHash("sha256").update(bytes).digest("hex")}`);
    expect(await ledger.readEvidence(hash)).toEqual(bytes);
  });

  it("throws when the stored bytes no longer match the hash, or the hash is unknown", async () => {
    const { events, resolver, evidence } = setup();
    const hash = await evidence.put(new TextEncoder().encode("original"));
    const corrupt: EvidenceStore = { mode: "evidence", put: (b) => evidence.put(b), get: async () => new TextEncoder().encode("tampered") };
    const ledger = new Ledger(events, corrupt, resolver);
    await expect(ledger.readEvidence(hash)).rejects.toThrow(/does not match its hash/);
    await expect(ledger.readEvidence(`sha256:${"0".repeat(64)}`)).rejects.toThrow(/does not match its hash/);
    await expect(setup().ledger.readEvidence(`sha256:${"0".repeat(64)}`)).rejects.toThrow(/not stored/);
  });

  it("refuses an event that names evidence which is not stored", async () => {
    const { ledger } = setup();
    const event = { ...weighed(), evidence: [{ evidence_id: "ev1", kind: "photo", content_hash: `sha256:${"1".repeat(64)}`, storage_ref: "mem" }] };
    await expect(ledger.append({ ...event, signatures: [sig(event, "scale", "scale")] })).rejects.toThrow(/not stored/);
  });
});

describe("REQ-LEDGER-004 every signature carries alg and verification dispatches on it", () => {
  it("accepts EdDSA and refuses the legacy Ed25519 string, an unknown alg or a missing one", async () => {
    const { ledger } = setup();
    const event = weighed();
    expect((await ledger.append({ ...event, signatures: [sig(event, "scale", "scale")] })).held).toBe(false);
    const legacy = weighed(6);
    await expect(ledger.append({ ...legacy, signatures: [sig(legacy, "scale", "scale", { alg: "Ed25519" })] })).rejects.toThrow(/unknown alg/);
    const third = weighed(7);
    await expect(ledger.append({ ...third, signatures: [sig(third, "scale", "scale", { alg: "ML-DSA-65" })] })).rejects.toThrow(/unknown alg/);
    await expect(ledger.append({ ...third, signatures: [sig(third, "scale", "scale", { alg: "toString" })] })).rejects.toThrow(/unknown alg/);
    await expect(ledger.append({ ...third, signatures: [sig(third, "scale", "scale", { alg: undefined as never })] })).rejects.toThrow(/unknown alg/);
  });

  it("signs and verifies identically through WebCrypto and node:crypto", async () => {
    const seed = createHash("sha256").update("seed:sender").digest();
    const webKey = await globalThis.crypto.subtle.importKey("pkcs8", Buffer.concat([PKCS8_ED25519, seed]), "Ed25519", false, ["sign"]);
    const event = weighed(8);
    const fields = { sig_id: "sig_web", key_id: "key-sender", party_id: party(1), role_at_signing: "sender", signed_at: "2026-02-02T08:00:10Z" };
    const viaNode = signEvent(event, keys.sender.privateKey, fields);
    const viaWeb = await signEventWebCrypto(event, webKey, fields);
    expect(viaWeb).toEqual(viaNode);
    const input = jwsSigningInput(event, viaNode);
    const bytes = detachedSignature(viaNode);
    for (const table of [VERIFIERS, WEBCRYPTO_VERIFIERS]) {
      expect(await table.EdDSA!(keys.sender.public_key, input, bytes)).toBe(true);
      expect(await table.EdDSA!(keys.sender.public_key, Buffer.from("other"), bytes)).toBe(false);
      expect(await table.EdDSA!(keys.receiver.public_key, input, bytes)).toBe(false);
      expect(Object.keys(table)).toEqual(["EdDSA"]);
    }
  });

  it("appends through a ledger that verifies with WebCrypto and refuses the legacy alg", async () => {
    const resolver = setup().resolver;
    const ledger = new Ledger(new MemoryEventStore("evidence"), new MemoryEvidenceStore("evidence"), resolver, "evidence", WEBCRYPTO_VERIFIERS);
    const event = weighed(9);
    expect((await ledger.append({ ...event, signatures: [sig(event, "scale", "scale")] })).held).toBe(false);
    const legacy = weighed(10);
    await expect(ledger.append({ ...legacy, signatures: [sig(legacy, "scale", "scale", { alg: "Ed25519" })] })).rejects.toThrow(/unknown alg/);
    const forged = weighed(11);
    await expect(ledger.append({ ...forged, signatures: [sig(forged, "other", "scale", { key_id: "key-scale", party_id: party(3) })] })).rejects.toThrow(/does not verify/);
  });

  it("refuses a signature whose alg differs from its key's", async () => {
    const { ledger, resolver } = setup();
    resolver.register({ key_id: "key-other-suite", party_id: party(3), alg: "ML-DSA-65", mode: "production", public_key: keys.scale.public_key, valid_from: "2026-01-01T00:00:00Z" });
    const event = weighed();
    await expect(ledger.append({ ...event, signatures: [sig(event, "scale", "scale", { key_id: "key-other-suite" })] })).rejects.toThrow(/is not an EdDSA key/);
  });
});

describe("REQ-LEDGER-008 the ledger mode is fixed at creation and decides which keys it takes", () => {
  it("takes test keys in a pilot ledger and refuses a production key", async () => {
    const pilot = setup("pilot");
    expect(pilot.ledger.mode).toBe("pilot");
    const event = weighed();
    expect(await pilot.ledger.append({ ...event, signatures: [sig(event, "scale", "scale")] })).toEqual({ event_id: event.event_id, held: false });
    const production = setup("pilot", "production");
    await expect(production.ledger.append({ ...event, signatures: [sig(event, "scale", "scale")] })).rejects.toThrow(/not a test key/);
  });

  it("refuses an event made with a test key in an evidence ledger", async () => {
    const { ledger } = setup("evidence", "test");
    const event = weighed();
    await expect(ledger.append({ ...event, signatures: [sig(event, "scale", "scale")] })).rejects.toThrow(/is a test key/);
  });

  it("refuses a countersignature made with a test key in an evidence ledger", async () => {
    const { ledger, resolver } = setup("evidence");
    resolver.register({ key_id: "key-test", party_id: party(5), alg: "EdDSA", mode: "test", public_key: keys.other.public_key, valid_from: "2026-01-01T00:00:00Z" });
    const event = weighed();
    await ledger.append(event);
    await expect(ledger.countersign(event.event_id, sig(event, "other", "scale", { key_id: "key-test", party_id: party(5) }))).rejects.toThrow(/is a test key/);
  });

  it("refuses stores whose mode differs from the ledger's", () => {
    const { resolver } = setup();
    expect(() => new Ledger(new MemoryEventStore("pilot"), new MemoryEvidenceStore("evidence"), resolver, "evidence")).toThrow(/not evidence stores/);
    expect(() => new Ledger(new MemoryEventStore("evidence"), new MemoryEvidenceStore("pilot"), resolver, "pilot")).toThrow(/not pilot stores/);
  });
});

describe("REQ-LEDGER-009 nothing from a pilot ledger enters an evidence ledger", () => {
  it("refuses to import a pilot event into an evidence ledger", async () => {
    const pilot = setup("pilot");
    const event = weighed();
    await pilot.ledger.append({ ...event, signatures: [sig(event, "scale", "scale")] });
    const evidence = setup("evidence");
    await expect(evidence.ledger.importFrom(pilot.ledger, TENANT, event.event_id)).rejects.toThrow(/pilot ledger can't enter an evidence ledger/);
    expect(await evidence.ledger.log()).toEqual([]);
  });

  it("imports within a mode", async () => {
    const source = setup("pilot");
    const event = weighed();
    await source.ledger.append({ ...event, signatures: [sig(event, "scale", "scale")] });
    const target = setup("pilot");
    expect(await target.ledger.importFrom(source.ledger, TENANT, event.event_id)).toEqual({ event_id: event.event_id, held: false });
  });
});

describe("REQ-LEDGER-010 a pilot ledger is discarded whole", () => {
  it("drops every event, signature and blob of a pilot store, and refuses to discard an evidence store", async () => {
    const { events, evidence, ledger } = setup("pilot");
    const event = weighed();
    await ledger.append({ ...event, signatures: [sig(event, "scale", "scale")] });
    const hash = await ledger.putEvidence(new TextEncoder().encode("photo"));
    events.discard();
    evidence.discard();
    expect(await ledger.log()).toEqual([]);
    expect(await events.signatures(event.event_id)).toEqual([]);
    expect(await evidence.get(hash)).toBeUndefined();
    expect(() => new MemoryEventStore("evidence").discard()).toThrow(/only a pilot store/);
    expect(() => new MemoryEvidenceStore("evidence").discard()).toThrow(/only a pilot store/);
  });
});

describe("REQ-LEDGER-007 the ledger signs and verifies a detached JWS", () => {
  const detach = (row: SignatureRow, header: string, middle = "") => `${header}.${middle}.${row.signature.split(".")[2]}`;

  it("signs a detached JWS whose header is the JCS of alg and kid, and verifies it", async () => {
    const { ledger } = setup();
    const event = weighed();
    const row = sig(event, "scale", "scale");
    const [header, payload, value] = row.signature.split(".");
    expect(payload).toBe("");
    expect(value).toMatch(/^[A-Za-z0-9_-]{86}$/);
    expect(Buffer.from(header!, "base64url").toString()).toBe(`{"alg":"EdDSA","kid":"key-scale"}`);
    expect((await ledger.append({ ...event, signatures: [row] })).held).toBe(false);
  });

  it("refuses a signature that is tampered with: the event, the role, the time or the signature value", async () => {
    const { ledger } = setup();
    const event = weighed();
    const good = sig(event, "scale", "scale");
    const at = good.signature.length - 10;
    const flipped = good.signature.slice(0, at) + (good.signature[at] === "A" ? "B" : "A") + good.signature.slice(at + 1);
    await expect(ledger.append({ ...event, signatures: [{ ...good, signature: flipped }] })).rejects.toThrow(/does not verify/);
    await expect(ledger.append({ ...event, signatures: [{ ...good, signed_at: "2026-02-03T08:00:10Z" }] })).rejects.toThrow(/does not verify/);
    await expect(ledger.append({ ...event, payload: { note: "other" }, signatures: [good] })).rejects.toThrow(/does not match the event/);
    expect((await ledger.append({ ...event, signatures: [good] })).held).toBe(false);
  });

  it("refuses a header whose alg or kid differs from the row's alg and key_id", async () => {
    const { ledger } = setup();
    const event = weighed();
    const good = sig(event, "scale", "scale");
    await expect(ledger.append({ ...event, signatures: [{ ...good, key_id: "key-other" }] })).rejects.toThrow(/JWS header does not match/);
    await expect(ledger.append({ ...event, signatures: [{ ...good, signature: detach(good, jwsHeader("ML-DSA-65", "key-scale")) }] })).rejects.toThrow(/JWS header does not match/);
    await expect(ledger.append({ ...event, signatures: [{ ...good, signature: detach(good, Buffer.from(`{"kid":"key-scale","alg":"EdDSA"}`).toString("base64url")) }] })).rejects.toThrow(/JWS header does not match/);
  });

  it("refuses a JWS that is not detached, and a signature that is not a JWS", async () => {
    const { ledger } = setup();
    const event = weighed();
    const good = sig(event, "scale", "scale");
    const header = good.signature.split(".")[0]!;
    for (const signature of [detach(good, header, "e30"), `${header}.${good.signature.split(".")[2]}`, "", "not a jws", Buffer.from("raw").toString("base64")]) {
      await expect(ledger.append({ ...event, signatures: [{ ...good, signature }] })).rejects.toThrow(/detached JWS/);
    }
    await expect(ledger.append({ ...event, signatures: [{ ...good, signature: undefined as never }] })).rejects.toThrow(/detached JWS/);
  });
});

describe("REQ-LEDGER-005 and REQ-LEDGER-007 canonical form is RFC 8785 JCS", () => {
  it("serialises the RFC 8785 §3.2.4 example", () => {
    const value = { numbers: [333333333.33333329, 1e30, 4.5, 2e-3, 1e-27], string: "€$\u000f\nA'B\"\\\\\"/", literals: [null, true, false] };
    expect(canonical(value)).toBe(String.raw`{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`);
  });

  it("sorts members by UTF-16 code units (RFC 8785 §3.2.3) and drops undefined members", () => {
    const order = ["\r", "1", "\u0080", "ö", "€", "\u{1f600}", "דּ"];
    const value = Object.fromEntries(order.map((k, i) => [k, i]).reverse());
    expect(canonical({ ...value, dropped: undefined })).toBe(`{${order.map((k, i) => `${JSON.stringify(k)}:${i}`).join(",")}}`);
  });

  it("serialises numbers as ECMAScript does and refuses one with no JSON form", () => {
    expect(canonical([0, -0, 1e21, 1e-7, 123456789012345680000, 0.1])).toBe("[0,0,1e+21,1e-7,123456789012345680000,0.1]");
    expect(() => canonical({ n: Number.NaN })).toThrow(/non-finite/);
    expect(() => canonical([Number.POSITIVE_INFINITY])).toThrow(/non-finite/);
  });
});

describe("REQ-LEDGER-005 the Merkle root over the log is deterministic", () => {
  it("gives the same root for the same events and a different root when an event or the order changes", async () => {
    const { ledger } = setup();
    for (const e of [weighed(2), weighed(3), weighed(4)]) await ledger.append({ ...e, signatures: [sig(e, "scale", "scale")] });
    const log = await ledger.log();
    expect(merkleRoot(log)).toBe(merkleRoot(structuredClone(log)));
    expect(merkleRoot(log)).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(merkleRoot([...log].reverse())).not.toBe(merkleRoot(log));
    expect(merkleRoot(log.slice(0, 2))).not.toBe(merkleRoot(log));
    const edited = structuredClone(log);
    edited[1]!.payload = { note: "edited" };
    expect(merkleRoot(edited)).not.toBe(merkleRoot(log));
    expect(merkleRoot([])).toBe(`sha256:${createHash("sha256").update("").digest("hex")}`);
  });
});

describe("REQ-LEDGER-006 tenant_id is checked on read", () => {
  it("refuses to read an event under another tenant and keeps tenants apart in the projection", async () => {
    const { ledger } = setup();
    const event = weighed();
    await ledger.append({ ...event, signatures: [sig(event, "scale", "scale")] });
    await expect(ledger.read("other-tenant", event.event_id)).rejects.toThrow(/another tenant/);
    expect(await ledger.projection("other-tenant")).toEqual([]);
  });
});

describe("REQ-EVENT-017 the ledger refuses a redeploy, resale, donate or recycle line for a fraction never separated", () => {
  const PLYWOOD = "https://loopledger.org/vocab/material/plywood";
  const VINYL = "https://loopledger.org/vocab/material/vinyl";
  const line = (route: string, material: string, mass_kg: number, classification?: unknown[]) => ({
    material,
    mass_kg,
    route,
    ...(classification ? { classification } : {}),
    facility_party_id: party(2),
    end_of_waste: false,
  });
  const disposition = (n: number, family: string, lines: unknown[]): EventRow => base(n, "disposition_final", { payload: { family, lines } });
  const processed = (n: number): EventRow =>
    base(n, "processed", { payload: { operation: "sort", fractions: [{ material: PLYWOOD, mass_kg: 60, weighed_event: evt(9) }] } });
  const append = (ledger: Ledger, event: EventRow) => ledger.append({ ...event, signatures: [sig(event, "receiver", "receiver"), sig(event, "other", "operator")] });

  it("appends a recycle line for a separated material and recovery for one that was not", async () => {
    const { ledger } = setup();
    const sorted = processed(1);
    await ledger.append({ ...sorted, signatures: [sig(sorted, "scale", "facility")] });
    const final = disposition(2, "recycle", [line("recycle", PLYWOOD, 60), line("recovery", VINYL, 10)]);
    expect(await append(ledger, final)).toEqual({ event_id: final.event_id, held: false });
  });

  it("refuses a recycle line for a material no processed event on the asset separated", async () => {
    const { ledger } = setup();
    await expect(append(ledger, disposition(2, "recycle", [line("recycle", VINYL, 60)]))).rejects.toThrow(/never separated/);
    const sorted = processed(1);
    await ledger.append({ ...sorted, signatures: [sig(sorted, "scale", "facility")] });
    await expect(append(ledger, disposition(3, "recycle", [line("recycle", PLYWOOD, 60), line("redeploy", VINYL, 10)]))).rejects.toThrow(/never separated/);
    expect((await ledger.log()).map((e) => e.event_type)).toEqual(["processed"]);
  });

  it("refuses a family that is not the route of the heaviest line", async () => {
    const { ledger } = setup();
    const sorted = processed(1);
    await ledger.append({ ...sorted, signatures: [sig(sorted, "scale", "facility")] });
    await expect(append(ledger, disposition(2, "disposal", [line("recycle", PLYWOOD, 60)]))).rejects.toThrow(/heaviest line/);
  });

  it("REQ-EVENT-020 refuses a known scheme's code that contradicts the route, and accepts an unknown scheme's", async () => {
    const { ledger } = setup();
    const sorted = processed(1);
    await ledger.append({ ...sorted, signatures: [sig(sorted, "scale", "facility")] });
    const eu = (code: string) => [{ scheme: "eu-wfd-2008-98", code }];
    await expect(append(ledger, disposition(2, "recycle", [line("recycle", PLYWOOD, 60, eu("R1"))]))).rejects.toThrow(/contradicts route/);
    const other = disposition(3, "recycle", [line("recycle", PLYWOOD, 60, [{ scheme: "ewc", code: "D10" }])]);
    expect(await append(ledger, other)).toEqual({ event_id: other.event_id, held: false });
  });
});

describe("REQ-LEDGER-011 sha256 and merkleRoot give the same result in Node and the browser", () => {
  const sample = [weighed(1), weighed(2), weighed(3)];
  const hashOf = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest();
  const reference = (bytes: Uint8Array) => `sha256:${hashOf(bytes).toString("hex")}`;
  const referenceRoot = (events: EventRow[]): string => {
    const leaves = events.map((e) => hashOf(Buffer.concat([Buffer.from([0]), Buffer.from(canonical(eventRow(e)))])));
    const tree = (l: Buffer[]): Buffer => {
      if (l.length === 1) return l[0]!;
      let split = 1;
      while (split * 2 < l.length) split *= 2;
      return hashOf(Buffer.concat([Buffer.from([1]), tree(l.slice(0, split)), tree(l.slice(split))]));
    };
    return `sha256:${tree(leaves).toString("hex")}`;
  };

  it("matches node:crypto for strings, bytes and the Merkle root", () => {
    expect(sha256("")).toBe(reference(new Uint8Array()));
    expect(sha256("loopledger ✓")).toBe(reference(new TextEncoder().encode("loopledger ✓")));
    expect(sha256(Uint8Array.from([0, 1, 2, 255]))).toBe(reference(Uint8Array.from([0, 1, 2, 255])));
    expect(merkleRoot(sample)).toBe(referenceRoot(sample));
    expect(merkleRoot(sample.slice(0, 2))).toBe(referenceRoot(sample.slice(0, 2)));
    expect(merkleRoot([])).toBe(sha256(""));
  });

  it("hashes, signs and verifies with no Buffer defined, as in a browser", async () => {
    const seed = createHash("sha256").update("seed:sender").digest();
    const webKey = await globalThis.crypto.subtle.importKey("pkcs8", Buffer.concat([PKCS8_ED25519, seed]), "Ed25519", false, ["sign"]);
    const event = weighed(20);
    const fields = { sig_id: "sig_nobuffer", key_id: "key-sender", party_id: party(1), role_at_signing: "sender", signed_at: "2026-02-02T08:00:10Z" };
    const expectedRoot = referenceRoot(sample);
    const expectedHash = reference(new TextEncoder().encode("x"));
    const viaNode = signEvent(event, keys.sender.privateKey, fields);
    vi.stubGlobal("Buffer", undefined);
    try {
      expect(merkleRoot(sample)).toBe(expectedRoot);
      expect(sha256("x")).toBe(expectedHash);
      const signed = await signEventWebCrypto(event, webKey, fields);
      expect(signed).toEqual(viaNode);
      const input = jwsSigningInput(event, signed);
      expect(await WEBCRYPTO_VERIFIERS.EdDSA!(keys.sender.public_key, input, detachedSignature(signed))).toBe(true);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe("REQ-SPEC-007 the issuer JWS secures the credential and leaves the event signatures verbatim", () => {
  const ISSUER = "did:web:example.org";
  const KID = `${ISSUER}#key-1`;
  const event = { "@context": ["https://loopledger.org/schema/v0.1/context.jsonld"], "@type": "Event", ...custody() } as EventRow;
  const signed = { ...event, signatures: [sig(event, "sender", "sender")] };
  const credential = buildCredential("Event", signed, ISSUER, "2026-11-08T10:00:00Z");
  const jws = signCredential(credential, keys.other.privateKey, KID);
  const [h, p, s] = jws.split(".") as [string, string, string];
  // An independent check, from the README alone: Ed25519 over the ASCII of `header.payload`.
  const verifies = (token: string, publicKey: string): boolean => {
    const [header, payload, value] = token.split(".") as [string, string, string];
    return verify(null, Buffer.from(`${header}.${payload}`), createPublicKey({ key: Buffer.from(publicKey, "base64"), format: "der", type: "spki" }), Buffer.from(value, "base64url"));
  };

  it("carries the vc+jwt header, the credential as payload and a signature that verifies under the issuer key only", () => {
    expect(JSON.parse(Buffer.from(h, "base64url").toString())).toEqual({ alg: "EdDSA", cty: "vc", kid: KID, typ: "vc+jwt" });
    expect(JSON.parse(Buffer.from(p, "base64url").toString())).toEqual(credential);
    expect(Buffer.from(p, "base64url").toString()).toBe(canonical(credential));
    expect(verifies(jws, keys.other.public_key)).toBe(true);
    expect(verifies(jws, keys.sender.public_key)).toBe(false);
    const tampered = buildCredential("Event", { ...signed, payload: { note: "edited" } }, ISSUER, "2026-11-08T10:00:00Z");
    expect(verifies(`${h}.${Buffer.from(canonical(tampered)).toString("base64url")}.${s}`, keys.other.public_key)).toBe(false);
  });

  it("keeps the event signature rows verbatim, and they still verify under the event signer's key", () => {
    const payload = JSON.parse(Buffer.from(p, "base64url").toString());
    const [row] = payload.credentialSubject.signatures;
    expect(row).toEqual(signed.signatures[0]);
    expect(VERIFIERS.EdDSA!(keys.sender.public_key, jwsSigningInput(eventRow(payload.credentialSubject), row), detachedSignature(row))).toBe(true);
  });

  it("refuses a kid that is not a verification method of the issuer", () => {
    expect(() => signCredential(credential, keys.other.privateKey, "did:web:example.com#key-1")).toThrow("not a verification method of the issuer");
    expect(() => signCredential(credential, keys.other.privateKey, ISSUER)).toThrow("not a verification method of the issuer");
  });
});

describe("REQ-SPEC-008 a passport credential is secured the same way", () => {
  it("signs a passport credential as vc+jwt under the issuer key", () => {
    const passport = { "@context": ["https://loopledger.org/schema/v0.1/context.jsonld"], "@type": "Passport", passport_id: "psp_x" };
    const credential = buildCredential("Passport", passport, "did:web:example.org", "2026-11-08T10:00:00Z");
    const [h, p, s] = signCredential(credential, keys.other.privateKey, "did:web:example.org#key-1").split(".") as [string, string, string];
    expect(JSON.parse(Buffer.from(p, "base64url").toString()).type).toEqual(["VerifiableCredential", "Passport"]);
    expect(verify(null, Buffer.from(`${h}.${p}`), createPublicKey({ key: Buffer.from(keys.other.public_key, "base64"), format: "der", type: "spki" }), Buffer.from(s, "base64url"))).toBe(true);
  });
});

describe("REQ-SPEC-009 the issuer is a did:web, never an event signer", () => {
  it("refuses a credential whose issuer is not a did:web", () => {
    expect(() => buildCredential("Event", {}, "did:key:z6Mkabc", "2026-11-08T10:00:00Z")).toThrow("not a did:web");
  });
});
