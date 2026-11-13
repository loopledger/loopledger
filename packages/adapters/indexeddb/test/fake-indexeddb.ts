// A minimal in-memory IndexedDB for Node tests: just the calls the adapter makes (open, deleteDatabase, object stores
// with a keyPath, get / getAll / count / add, transactions that commit when idle or abort). Values are structured clones.
type Rows = Map<string, Map<unknown, unknown>>;

class FakeRequest {
  result: unknown;
  error: unknown = null;
  onsuccess?: () => void;
  onerror?: () => void;
  onupgradeneeded?: () => void;
}

class FakeTransaction {
  error: unknown = null;
  oncomplete?: () => void;
  onerror?: () => void;
  onabort?: () => void;
  private pending = 0;
  private finished = false;

  constructor(private readonly rows: Rows, private readonly keyPaths: Record<string, string>, private readonly names: string[]) {
    setTimeout(() => this.settle(), 0);
  }

  objectStore(name: string): FakeStore {
    if (!this.names.includes(name)) throw new Error(`store ${name} is not in this transaction`);
    return new FakeStore(this, this.rows.get(name)!, this.keyPaths[name]!);
  }

  abort(): void {
    if (this.finished) throw new Error("the transaction is finished");
    this.finished = true;
    setTimeout(() => this.onabort?.(), 0);
  }

  run(op: () => unknown): FakeRequest {
    const request = new FakeRequest();
    this.pending++;
    setTimeout(() => {
      if (this.finished) {
        request.error = new Error("the transaction is finished");
        request.onerror?.();
      } else {
        try {
          request.result = op();
          request.onsuccess?.();
        } catch (error) {
          request.error = error;
          this.error = error;
          request.onerror?.();
          this.finished = true;
          this.onerror?.();
          this.onabort?.();
        }
      }
      this.pending--;
      setTimeout(() => this.settle(), 0);
    }, 0);
    return request;
  }

  private settle(): void {
    if (this.pending > 0 || this.finished) return;
    this.finished = true;
    this.oncomplete?.();
  }
}

class FakeStore {
  constructor(private readonly tx: FakeTransaction, private readonly data: Map<unknown, unknown>, private readonly keyPath: string) {}

  get(key: unknown) {
    return this.tx.run(() => structuredClone(this.data.get(key)));
  }

  getAll() {
    return this.tx.run(() => [...this.data.values()].map((v) => structuredClone(v)));
  }

  count() {
    return this.tx.run(() => this.data.size);
  }

  add(value: unknown) {
    return this.tx.run(() => {
      const key = (value as Record<string, unknown>)[this.keyPath];
      if (this.data.has(key)) throw new Error("ConstraintError: key already exists");
      this.data.set(key, structuredClone(value));
      return key;
    });
  }
}

class FakeDatabase {
  constructor(readonly name: string, private readonly rows: Rows, private readonly keyPaths: Record<string, string>) {}

  createObjectStore(name: string, options: { keyPath: string }): void {
    this.rows.set(name, new Map());
    this.keyPaths[name] = options.keyPath;
  }

  transaction(names: string | string[]): FakeTransaction {
    return new FakeTransaction(this.rows, this.keyPaths, [names].flat());
  }

  close(): void {}
}

export class FakeIndexedDb {
  private readonly databases = new Map<string, { rows: Rows; keyPaths: Record<string, string> }>();

  open(name: string, _version?: number): IDBOpenDBRequest {
    const request = new FakeRequest();
    setTimeout(() => {
      let entry = this.databases.get(name);
      const upgrade = !entry;
      if (!entry) this.databases.set(name, (entry = { rows: new Map(), keyPaths: {} }));
      const db = new FakeDatabase(name, entry.rows, entry.keyPaths);
      request.result = db;
      if (upgrade) request.onupgradeneeded?.();
      request.onsuccess?.();
    }, 0);
    return request as unknown as IDBOpenDBRequest;
  }

  deleteDatabase(name: string): IDBOpenDBRequest {
    const request = new FakeRequest();
    setTimeout(() => {
      this.databases.delete(name);
      request.onsuccess?.();
    }, 0);
    return request as unknown as IDBOpenDBRequest;
  }

  has(name: string): boolean {
    return this.databases.has(name);
  }
}

export const fakeFactory = (db: FakeIndexedDb): IDBFactory => db as unknown as IDBFactory;
