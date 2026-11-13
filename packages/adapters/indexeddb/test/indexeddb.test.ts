import { describe, expect, it } from "vitest";
import { MemoryKeyResolver } from "../../memory/src/index";
import { Ledger, WEBCRYPTO_VERIFIERS, signEventWebCrypto } from "../../../ledger/src/index";
import type { EventRow, EvidenceStore, SignatureRow } from "../../../ports/src/index";
import { IndexedDbEventStore, IndexedDbEvidenceStore, generateDeviceTestKey } from "../src/index";
import { FakeIndexedDb, fakeFactory } from "./fake-indexeddb";

const TENANT = "acme-hospitality";
const ULID = "0123456789ABCDEFGHJKMNPQRS";
const evt = (n: number) => `evt_${ULID.slice(0, 24)}${String(n).padStart(2, "0")}`;
const ASSET = `ast_${ULID}`;
const SCALE = `pty_${ULID.slice(0, 24)}03`;

const weighed = (n = 1, extra: Partial<EventRow> = {}): EventRow => ({
  event_id: evt(n),
  tenant_id: TENANT,
  event_type: "weighed",
  asset_ids: [ASSET],
  occurred_at: "2026-02-02T08:00:00Z",
  recorded_at: "2026-02-02T08:00:05Z",
  payload: { note: "opaque until #6 lands" },
  ...extra,
});

/** A pilot ledger over IndexedDB stores, with one device test key for the scale party. */
const setup = async () => {
  const idb = new FakeIndexedDb();
  const events = await IndexedDbEventStore.open(fakeFactory(idb), "events", "pilot");
  const evidence = await IndexedDbEvidenceStore.open(fakeFactory(idb), "evidence", "pilot");
  const key = await generateDeviceTestKey(SCALE, new Date("2026-01-01T00:00:00Z"));
  const resolver = new MemoryKeyResolver();
  resolver.register(key.record);
  const ledger = new Ledger(events, evidence, resolver, "pilot", WEBCRYPTO_VERIFIERS);
  let n = 0;
  const sign = (event: EventRow): Promise<SignatureRow> =>
    signEventWebCrypto(event, key.privateKey, { sig_id: `sig_${++n}`, key_id: key.record.key_id, party_id: SCALE, role_at_signing: "scale", signed_at: "2026-02-02T08:00:10Z" });
  return { idb, events, evidence, key, ledger, sign };
};

describe("REQ-CAPTURE-002 the browser adapters are IndexedDB stores created as a pilot ledger", () => {
  it("opens both stores with LedgerMode pilot and a Ledger accepts them", async () => {
    const { events, evidence, ledger } = await setup();
    expect(events.mode).toBe("pilot");
    expect(evidence.mode).toBe("pilot");
    expect(ledger.mode).toBe("pilot");
  });

  it("is refused by a ledger of another mode", async () => {
    const { events, evidence, key } = await setup();
    const resolver = new MemoryKeyResolver();
    resolver.register(key.record);
    expect(() => new Ledger(events, evidence, resolver, "evidence")).toThrow(/not evidence stores/);
  });

  it("keeps the log across reopening the database", async () => {
    const { idb, events, ledger, sign } = await setup();
    const event = weighed();
    await ledger.append({ ...event, signatures: [await sign(event)] });
    const reopened = await IndexedDbEventStore.open(fakeFactory(idb), "events", "pilot");
    expect(await reopened.readAll()).toEqual([event]);
    expect(await reopened.signatures(event.event_id)).toHaveLength(1);
    expect(events.mode).toBe("pilot");
  });

  it("discards a pilot ledger whole, evidence blobs included, and refuses to discard an evidence store (REQ-LEDGER-010)", async () => {
    const { idb, events, evidence } = await setup();
    await evidence.put(new TextEncoder().encode("ticket"));
    await events.discard();
    await evidence.discard();
    expect(idb.has("events")).toBe(false);
    expect(idb.has("evidence")).toBe(false);
    const kept = await IndexedDbEventStore.open(fakeFactory(idb), "kept", "evidence");
    await expect(kept.discard()).rejects.toThrow(/only a pilot store/);
  });
});

describe("REQ-CAPTURE-003 device test keys are non-extractable WebCrypto Ed25519 keys", () => {
  it("generates a test key record whose private key can't be exported", async () => {
    const { key } = await setup();
    expect(key.record).toMatchObject({ party_id: SCALE, alg: "EdDSA", mode: "test" });
    expect(key.privateKey.extractable).toBe(false);
    expect(key.privateKey.algorithm.name).toBe("Ed25519");
    await expect(globalThis.crypto.subtle.exportKey("pkcs8", key.privateKey)).rejects.toThrow();
  });

  it("generates a different key each time", async () => {
    const a = await generateDeviceTestKey(SCALE);
    const b = await generateDeviceTestKey(SCALE);
    expect(a.record.key_id).not.toBe(b.record.key_id);
    expect(a.record.public_key).not.toBe(b.record.public_key);
  });

  it("signs an event that the ledger verifier accepts", async () => {
    const { ledger, events, sign } = await setup();
    const event = weighed();
    expect(await ledger.append({ ...event, signatures: [await sign(event)] })).toEqual({ event_id: event.event_id, held: false });
    expect(await events.signatures(event.event_id)).toHaveLength(1);
  });

  it("is refused when the event changes after signing", async () => {
    const { ledger, sign } = await setup();
    const event = weighed();
    const signature = await sign(event);
    await expect(ledger.append({ ...event, payload: { note: "changed" }, signatures: [signature] })).rejects.toThrow();
  });
});

describe("REQ-LEDGER-001 events append and are never updated (IndexedDB)", () => {
  it("appends events and reads them back with their signatures, in append order", async () => {
    const { ledger, events, sign } = await setup();
    const [first, second] = [weighed(2), weighed(1)];
    await ledger.append({ ...first, signatures: [await sign(first)] });
    await ledger.append({ ...second, signatures: [await sign(second)] });
    const read = await ledger.read(TENANT, first.event_id);
    expect(read.held).toBe(false);
    expect(read.signatures).toHaveLength(1);
    expect((await events.readAll()).map((e) => e.event_id)).toEqual([first.event_id, second.event_id]);
  });

  it("refuses a second append of an event_id and leaves the stored event unchanged", async () => {
    const { events } = await setup();
    const event = weighed();
    await events.append(event);
    await expect(events.append({ ...event, payload: { note: "rewritten" } })).rejects.toThrow(/already in the log/);
    expect((await events.read(event.event_id))?.payload).toEqual(event.payload);
    expect(await events.readAll()).toHaveLength(1);
  });

  it("refuses a signature for an unknown event or a repeated sig_id", async () => {
    const { events, sign } = await setup();
    const event = weighed();
    const row = await sign(event);
    await expect(events.appendSignature(event.event_id, row)).rejects.toThrow(/not in the log/);
    await events.append(event);
    await events.appendSignature(event.event_id, row);
    await expect(events.appendSignature(event.event_id, row)).rejects.toThrow(/already stored/);
    expect(await events.signatures(event.event_id)).toHaveLength(1);
  });

  it("does not change a stored event through a value read from or passed to it", async () => {
    const { events } = await setup();
    const event = weighed();
    await events.append(event);
    event.payload.note = "mutated after append";
    const read = await events.read(event.event_id);
    read!.payload.note = "mutated after read";
    expect((await events.read(event.event_id))?.payload.note).toBe("opaque until #6 lands");
  });

  it("returns undefined for an unknown event and no signatures", async () => {
    const { events } = await setup();
    expect(await events.read(evt(9))).toBeUndefined();
    expect(await events.signatures(evt(9))).toEqual([]);
  });
});

describe("REQ-LEDGER-003 evidence is stored by hash and checked on read (IndexedDB)", () => {
  it("stores bytes by sha256 hash and returns copies", async () => {
    const { evidence } = await setup();
    const hash = await evidence.put(new TextEncoder().encode("ticket"));
    expect(hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(await evidence.put(new TextEncoder().encode("ticket"))).toBe(hash);
    expect(new TextDecoder().decode(await evidence.get(hash))).toBe("ticket");
    expect(await evidence.get(`sha256:${"0".repeat(64)}`)).toBeUndefined();
  });

  it("an event naming evidence that is stored is accepted, and one naming evidence that is not is refused", async () => {
    const { ledger, evidence, sign } = await setup();
    const hash = await evidence.put(new TextEncoder().encode("ticket"));
    const ref = (content_hash: string) => [{ evidence_id: "ev1", kind: "photo", content_hash, storage_ref: "idb" }];
    const stored = weighed(1, { evidence: ref(hash) });
    expect(await ledger.append({ ...stored, signatures: [await sign(stored)] })).toEqual({ event_id: stored.event_id, held: false });
    const missing = weighed(2, { evidence: ref(`sha256:${"1".repeat(64)}`) });
    await expect(ledger.append({ ...missing, signatures: [await sign(missing)] })).rejects.toThrow();
  });

  it("the ledger throws when the stored bytes no longer match their hash", async () => {
    const { events, evidence, key, sign } = await setup();
    const hash = await evidence.put(new TextEncoder().encode("original"));
    const corrupt: EvidenceStore = { mode: "pilot", put: (b) => evidence.put(b), get: async () => new TextEncoder().encode("tampered") };
    const resolver = new MemoryKeyResolver();
    resolver.register(key.record);
    const ledger = new Ledger(events, corrupt, resolver, "pilot", WEBCRYPTO_VERIFIERS);
    const event = weighed(1, { evidence: [{ evidence_id: "ev1", kind: "photo", content_hash: hash, storage_ref: "idb" }] });
    await expect(ledger.append({ ...event, signatures: [await sign(event)] })).rejects.toThrow();
  });
});
