import { describe, expect, it } from "vitest";
import { MemoryKeyRegistry, MemoryPassportStore } from "../src/index";
import type { KeyRecord, Passport } from "@loopledger/ports";

const passport = (assetId: string, tenantId = "pilot-northside"): Passport => ({
  "@context": ["https://loopledger.org/schema/v0.1/context.jsonld"],
  "@type": "Passport",
  asset_id: assetId,
  passport_id: "LL-NORTHSIDE-000001",
  tenant_id: tenantId,
  kind: "unit",
  revision: { basis: "unknown" },
  owner: { party_id: "pty_01JDPC0000000000000000SND1", record_access: "full" },
  origin: { site_id: "site-northside-01", source_event: "evt_01JDPC0000000000000000B0RN" },
});

const key = (keyId: string): KeyRecord => ({
  key_id: keyId,
  party_id: "pty_01JDPC0000000000000000SND1",
  alg: "EdDSA",
  mode: "test",
  public_key: "MCowBQYDK2VwAyEAGb9FAWthY8l70jSJQNJ0b2R4qMYgHP0n9k6CJL9PTmU=",
  valid_from: "2026-11-13T00:00:00.000Z",
});

describe("REQ-PORTS-001 the PassportStore port", () => {
  it("stores a passport, returns copies, and refuses a second passport for an asset", async () => {
    const store = new MemoryPassportStore("pilot");
    expect(store.mode).toBe("pilot");
    await store.put(passport("ast_01JDPC0000000000000000A0001"));
    const got = await store.get("ast_01JDPC0000000000000000A0001");
    expect(got?.passport_id).toBe("LL-NORTHSIDE-000001");
    if (got) got.tenant_id = "tampered";
    expect((await store.get("ast_01JDPC0000000000000000A0001"))?.tenant_id).toBe("pilot-northside");
    await expect(store.put(passport("ast_01JDPC0000000000000000A0001"))).rejects.toThrow("already has a passport");
    expect(await store.get("ast_01JDPC0000000000000000A0002")).toBeUndefined();
  });

  it("lists a tenant's passports in the order they were stored, and only theirs", async () => {
    const store = new MemoryPassportStore("pilot");
    await store.put(passport("ast_01JDPC0000000000000000A0001", "tenant-1"));
    await store.put(passport("ast_01JDPC0000000000000000A0002", "tenant-2"));
    await store.put(passport("ast_01JDPC0000000000000000A0003", "tenant-1"));
    expect((await store.list("tenant-1")).map((p) => p.asset_id)).toEqual(["ast_01JDPC0000000000000000A0001", "ast_01JDPC0000000000000000A0003"]);
    expect(await store.list("tenant-3")).toEqual([]);
  });

  it("can be discarded only when pilot (REQ-LEDGER-010)", async () => {
    const pilot = new MemoryPassportStore("pilot");
    await pilot.put(passport("ast_01JDPC0000000000000000A0001"));
    pilot.discard();
    expect(await pilot.get("ast_01JDPC0000000000000000A0001")).toBeUndefined();
    const evidence = new MemoryPassportStore("evidence");
    expect(() => evidence.discard()).toThrow("only a pilot store can be discarded");
  });
});

describe("REQ-PORTS-002 the KeyRegistry port", () => {
  it("registers a key, resolves a copy, and refuses a repeat key_id", async () => {
    const registry = new MemoryKeyRegistry();
    await registry.register(key("did:key:z6MkTest"));
    const got = await registry.resolve("did:key:z6MkTest");
    expect(got?.alg).toBe("EdDSA");
    if (got) got.party_id = "tampered";
    expect((await registry.resolve("did:key:z6MkTest"))?.party_id).toBe("pty_01JDPC0000000000000000SND1");
    await expect(registry.register(key("did:key:z6MkTest"))).rejects.toThrow("already registered");
    expect(await registry.resolve("did:key:z6MkNope")).toBeUndefined();
  });

  it("registers keys per party without interfering with each other", async () => {
    const registry = new MemoryKeyRegistry();
    await registry.register(key("did:key:z6MkSender"));
    await registry.register({ ...key("did:key:z6MkReceiver"), party_id: "pty_01JDPC0000000000000000RCV1" });
    expect((await registry.resolve("did:key:z6MkReceiver"))?.party_id).toBe("pty_01JDPC0000000000000000RCV1");
  });
});
