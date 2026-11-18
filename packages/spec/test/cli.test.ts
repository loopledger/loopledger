// The validator CLI: paths in, one line per violation out, exit codes, --expect-invalid. Runs the real CLI module
// against the published examples and the fixtures it plants.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { run } from "../src/cli";

type Json = Record<string, unknown>;

const examples = (): Json[] => JSON.parse(readFileSync("packages/spec/examples/booth-2s-g4.events.json", "utf8")) as Json[];
const first = (events: readonly Json[]): Json => {
  const head = events[0];
  if (head === undefined) throw new Error("no events");
  return head;
};

let scratch: string | undefined;
const scratchPath = (): string => {
  if (!scratch) scratch = mkdtempSync(join(tmpdir(), "loopledger-validate-"));
  return scratch;
};
const write = (name: string, value: unknown): string => {
  const file = join(scratchPath(), name);
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
  return file;
};

afterAll(() => {
  if (scratch) rmSync(scratch, { recursive: true, force: true });
});

describe("@REQ-VALIDATE-001 pnpm validate validates passports and event sets, one line per violation", () => {
  it("is silent and green for the published examples", () => {
    const result = run(["packages/spec/examples"]);
    expect(result.lines).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.exitCode).toBe(0);
  });

  it("prints <file>:<index>:<path> <message> lines and exits 1 for an invalid events file", () => {
    const file = write("not-an-array.events.json", { event_type: "nope" });
    const result = run([file]);
    expect(result.exitCode).toBe(1);
    expect(result.lines[0]).toMatch(new RegExp(`^${file}:0:/ `));
  });

  it("walks a directory and reports every violation", () => {
    write("held-false-no-signatures.events.json", [{ ...first(examples()), signatures: [] }]);
    const result = run([scratchPath()]);
    expect(result.exitCode).toBe(1);
    expect(result.lines.some((l) => l.includes("held-false-no-signatures.events.json:0:"))).toBe(true);
  });
});

describe("@REQ-VALIDATE-002 every signature verifies as an independent JWS against its did:key", () => {
  it("accepts the published examples' signatures", () => {
    expect(run(["packages/spec/examples/booth-2s-g4.events.json"]).lines).toEqual([]);
  });

  it("names the signature that stops verifying when the event is tampered with", () => {
    const tampered = structuredClone(examples());
    first(tampered)["occurred_at"] = "2019-03-14T09:00:00Z";
    const file = write("tampered.events.json", tampered);
    const result = run([file]);
    expect(result.exitCode).toBe(1);
    expect(result.lines.some((l) => l.includes(":0:/signatures/0 signature does not verify"))).toBe(true);
  });
});

describe("@REQ-VALIDATE-003 --expect-invalid fails naming any file that passes", () => {
  it("is green for every planted fixture", () => {
    const result = run(["--expect-invalid", "packages/spec/fixtures/invalid"]);
    expect(result.passed).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.exitCode).toBe(0);
  });

  it("exits 1 naming the file that produces no violation", () => {
    const file = write("valid.events.json", [first(examples())]);
    const result = run(["--expect-invalid", scratchPath()]);
    expect(result.exitCode).toBe(1);
    expect(result.passed.some((p) => p.endsWith("valid.events.json"))).toBe(true);
    expect(result.lines.some((l) => l.startsWith(`${file}:0:/ expected at least one violation`))).toBe(true);
  });
});
