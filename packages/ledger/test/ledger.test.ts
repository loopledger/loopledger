import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { MemoryEventStore, MemoryEvidenceStore, MemoryKeyResolver } from "@loopledger/adapter-memory";
import type { EventRow, EvidenceStore, SignatureRow } from "@loopledger/ports";
import { Ledger, eventHash, merkleRoot, signingInput } from "../src/index";
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

const setup = () => {
  const resolver = new MemoryKeyResolver();
  for (const [name, k] of Object.entries(keys)) {
    resolver.register({ key_id: `key-${name}`, party_id: party(owners[name as keyof typeof keys]), alg: "Ed25519", public_key: k.public_key, valid_from: "2026-01-01T00:00:00Z", valid_until: "2027-01-01T00:00:00Z" });
  }
  const events = new MemoryEventStore();
  const evidence = new MemoryEvidenceStore();
  return { events, evidence, resolver, ledger: new Ledger(events, evidence, resolver) };
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
const sig = (event: EventRow, name: keyof typeof keys, role: string, over: Partial<SignatureRow> = {}): SignatureRow => {
  const body = { signed_hash: eventHash(event), party_id: party(owners[name]), role_at_signing: role, signed_at: "2026-02-02T08:00:10Z", ...over };
  return {
    sig_id: `sig_${++sigCount}`,
    key_id: `key-${name}`,
    alg: "Ed25519",
    ...body,
    signature: sign(null, signingInput(body), keys[name].privateKey).toString("base64"),
    ...over,
  };
};

const custody = (n = 1): EventRow => base(n, "custody_transferred");
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
    const forged = { ...sig(event, "sender", "sender"), signature: sig(event, "other", "sender").signature };
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
    const corrupt: EvidenceStore = { put: (b) => evidence.put(b), get: async () => new TextEncoder().encode("tampered") };
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
  it("accepts Ed25519 and EdDSA and refuses an unknown or missing alg", async () => {
    const { ledger, resolver } = setup();
    const event = weighed();
    expect((await ledger.append({ ...event, signatures: [sig(event, "scale", "scale")] })).held).toBe(false);
    resolver.register({ key_id: "key-eddsa", party_id: party(3), alg: "EdDSA", public_key: keys.scale.public_key, valid_from: "2026-01-01T00:00:00Z" });
    const second = weighed(6);
    expect((await ledger.append({ ...second, signatures: [sig(second, "scale", "scale", { key_id: "key-eddsa", alg: "EdDSA" })] })).held).toBe(false);
    const third = weighed(7);
    await expect(ledger.append({ ...third, signatures: [sig(third, "scale", "scale", { alg: "ML-DSA-65" })] })).rejects.toThrow(/unknown alg/);
    await expect(ledger.append({ ...third, signatures: [sig(third, "scale", "scale", { alg: "toString" })] })).rejects.toThrow(/unknown alg/);
    await expect(ledger.append({ ...third, signatures: [sig(third, "scale", "scale", { alg: undefined as never })] })).rejects.toThrow(/unknown alg/);
  });

  it("refuses a signature whose alg differs from its key's", async () => {
    const { ledger } = setup();
    const event = weighed();
    await expect(ledger.append({ ...event, signatures: [sig(event, "scale", "scale", { alg: "EdDSA" })] })).rejects.toThrow(/is not an EdDSA key/);
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
