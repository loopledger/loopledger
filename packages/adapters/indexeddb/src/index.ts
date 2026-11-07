// IndexedDB adapters for the ledger ports, for the browser (LL-001). They are created with a mode; the crew capture app
// uses `pilot`. The factory is passed in (`globalThis.indexedDB` in a browser), so no global is read here.
import type { EventRow, EventStore, EvidenceStore, KeyRecord, LedgerMode, SignatureRow } from "../../../ports/src/index";

const EVENTS = "events";
const SIGNATURES = "signatures";
const BLOBS = "blobs";

const request = <T>(r: IDBRequest<T>): Promise<T> =>
  new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error ?? new Error("IndexedDB request failed"));
  });

const done = (tx: IDBTransaction): Promise<void> =>
  new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("IndexedDB transaction failed"));
    tx.onabort = () => reject(tx.error ?? new Error("IndexedDB transaction aborted"));
  });

const openDb = (factory: IDBFactory, name: string, stores: Record<string, string>): Promise<IDBDatabase> => {
  const open = factory.open(name, 1);
  open.onupgradeneeded = () => {
    for (const [store, keyPath] of Object.entries(stores)) open.result.createObjectStore(store, { keyPath });
  };
  return request(open);
};

/** Only a pilot ledger's stores can be dropped, and only whole (REQ-LEDGER-010). */
const dropDb = async (db: IDBDatabase, factory: IDBFactory, mode: LedgerMode): Promise<void> => {
  if (mode !== "pilot") throw new Error("only a pilot store can be discarded");
  const name = db.name;
  db.close();
  await request(factory.deleteDatabase(name) as IDBRequest<unknown>);
};

interface EventRecord {
  event_id: string;
  seq: number;
  event: EventRow;
}

interface SignatureRecord {
  sig_id: string;
  event_id: string;
  seq: number;
  row: SignatureRow;
}

export class IndexedDbEventStore implements EventStore {
  private constructor(
    readonly mode: LedgerMode,
    private readonly factory: IDBFactory,
    private readonly db: IDBDatabase,
  ) {}

  static async open(factory: IDBFactory, name: string, mode: LedgerMode): Promise<IndexedDbEventStore> {
    return new IndexedDbEventStore(mode, factory, await openDb(factory, name, { [EVENTS]: "event_id", [SIGNATURES]: "sig_id" }));
  }

  /** Deletes the whole database. Only a pilot store can be discarded, and there is no per-event delete (REQ-LEDGER-010). */
  discard(): Promise<void> {
    return dropDb(this.db, this.factory, this.mode);
  }

  async append(event: EventRow): Promise<void> {
    const tx = this.db.transaction(EVENTS, "readwrite");
    const store = tx.objectStore(EVENTS);
    const finished = done(tx).catch(() => undefined);
    if ((await request(store.get(event.event_id))) !== undefined) {
      tx.abort();
      await finished;
      throw new Error(`event ${event.event_id} is already in the log`);
    }
    const seq = await request(store.count());
    store.add({ event_id: event.event_id, seq, event: structuredClone(event) } satisfies EventRecord);
    await done(tx);
  }

  async appendSignature(eventId: string, row: SignatureRow): Promise<void> {
    const tx = this.db.transaction([EVENTS, SIGNATURES], "readwrite");
    const sigs = tx.objectStore(SIGNATURES);
    const finished = done(tx).catch(() => undefined);
    const refuse = async (message: string): Promise<never> => {
      tx.abort();
      await finished;
      throw new Error(message);
    };
    if ((await request(tx.objectStore(EVENTS).get(eventId))) === undefined) return refuse(`event ${eventId} is not in the log`);
    if ((await request(sigs.get(row.sig_id))) !== undefined) return refuse(`signature ${row.sig_id} is already stored`);
    const seq = await request(sigs.count());
    sigs.add({ sig_id: row.sig_id, event_id: eventId, seq, row: structuredClone(row) } satisfies SignatureRecord);
    await done(tx);
  }

  async read(eventId: string): Promise<EventRow | undefined> {
    const record = (await request(this.db.transaction(EVENTS).objectStore(EVENTS).get(eventId))) as EventRecord | undefined;
    return record?.event;
  }

  async readAll(): Promise<EventRow[]> {
    const records = (await request(this.db.transaction(EVENTS).objectStore(EVENTS).getAll())) as EventRecord[];
    return records.sort((a, b) => a.seq - b.seq).map((r) => r.event);
  }

  async signatures(eventId: string): Promise<SignatureRow[]> {
    const records = (await request(this.db.transaction(SIGNATURES).objectStore(SIGNATURES).getAll())) as SignatureRecord[];
    return records.filter((r) => r.event_id === eventId).sort((a, b) => a.seq - b.seq).map((r) => r.row);
  }
}

const hex = (bytes: ArrayBuffer): string => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");

export class IndexedDbEvidenceStore implements EvidenceStore {
  private constructor(
    readonly mode: LedgerMode,
    private readonly factory: IDBFactory,
    private readonly db: IDBDatabase,
  ) {}

  static async open(factory: IDBFactory, name: string, mode: LedgerMode): Promise<IndexedDbEvidenceStore> {
    return new IndexedDbEvidenceStore(mode, factory, await openDb(factory, name, { [BLOBS]: "hash" }));
  }

  /** Deletes every blob; pilot photos are test data too (REQ-LEDGER-010). */
  discard(): Promise<void> {
    return dropDb(this.db, this.factory, this.mode);
  }

  async put(bytes: Uint8Array): Promise<string> {
    const hash = `sha256:${hex(await globalThis.crypto.subtle.digest("SHA-256", new Uint8Array(bytes)))}`;
    const tx = this.db.transaction(BLOBS, "readwrite");
    const store = tx.objectStore(BLOBS);
    if ((await request(store.get(hash))) === undefined) store.add({ hash, bytes: Uint8Array.from(bytes) });
    await done(tx);
    return hash;
  }

  async get(hash: string): Promise<Uint8Array | undefined> {
    const record = (await request(this.db.transaction(BLOBS).objectStore(BLOBS).get(hash))) as { bytes: Uint8Array } | undefined;
    return record && Uint8Array.from(record.bytes);
  }
}

/** A device test key: the private half is a non-extractable WebCrypto Ed25519 key that never leaves the device. */
export interface DeviceTestKey {
  record: KeyRecord;
  privateKey: CryptoKey;
}

/** Generates a `test` key for a party (REQ-LEDGER-008: a pilot ledger takes test keys only). */
export const generateDeviceTestKey = async (partyId: string, now: Date = new Date()): Promise<DeviceTestKey> => {
  const subtle = globalThis.crypto.subtle;
  const pair = (await subtle.generateKey("Ed25519", false, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array(await subtle.exportKey("spki", pair.publicKey));
  return {
    privateKey: pair.privateKey,
    record: {
      key_id: `key-test-${globalThis.crypto.randomUUID()}`,
      party_id: partyId,
      alg: "EdDSA",
      mode: "test",
      public_key: btoa(String.fromCharCode(...spki)),
      valid_from: now.toISOString(),
    },
  };
};
