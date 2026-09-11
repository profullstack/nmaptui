import { test } from "node:test";
import assert from "node:assert/strict";
import { compareAddr, diffScans, formatDiff } from "../src/diff.ts";
import { scan } from "./helpers.ts";

test("finds hosts that came and went, and ports that moved", () => {
  const diff = diffScans(scan("estate.xml"), scan("estate-after.xml"));
  assert.deepEqual(diff.summary, { added: 1, removed: 1, stateChanged: 0, opened: 1, closed: 1, serviceChanged: 1, unchanged: 2 });
  const files = diff.hosts.find((h) => h.addr === "10.0.0.5")!;
  assert.equal(files.kind, "changed");
  assert.equal(files.ports[0]?.kind, "closed");
  assert.equal(files.ports[0]?.port, 21);
  const db = diff.hosts.find((h) => h.addr === "10.0.0.7")!;
  assert.equal(db.ports[0]?.kind, "opened");
  assert.equal(db.ports[0]?.port, 5432);
  const web = diff.hosts.find((h) => h.addr === "10.0.0.12")!;
  assert.equal(web.ports[0]?.kind, "service");
  assert.match(web.ports[0]?.detail ?? "", /1\.24\.0 -> http nginx 1\.26\.1/);
  assert.equal(diff.hosts.find((h) => h.addr === "10.0.0.9")?.kind, "removed");
  assert.equal(diff.hosts.find((h) => h.addr === "10.0.0.14")?.kind, "added");
});

test("a scan diffed against itself is quiet", () => {
  const a = scan("estate.xml");
  const diff = diffScans(a, a);
  assert.equal(diff.summary.unchanged, 6);
  assert.ok(diff.hosts.every((h) => h.kind === "same"));
  assert.equal(formatDiff(diff).split("\n").length, 2);
});

test("addresses sort numerically", () => {
  assert.deepEqual(["10.0.0.10", "10.0.0.9", "10.0.0.100"].sort(compareAddr), ["10.0.0.9", "10.0.0.10", "10.0.0.100"]);
});

test("the text form reads like ndiff", () => {
  const text = formatDiff(diffScans(scan("estate.xml"), scan("estate-after.xml")));
  assert.match(text, /^hosts: \+1 added, -1 removed/);
  assert.match(text, /\+ 10\.0\.0\.14 \(new-box\.lab\.internal\) is new/);
  assert.match(text, /    - tcp\/21 no longer reported/);
});
