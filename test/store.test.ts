import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { defaultDataDir, ScanStore, targetsFromArgs } from "../src/store.ts";
import { fixture, scan } from "./helpers.ts";

function tempStore(): { store: ScanStore; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), "nmaptui-store-"));
  return { store: new ScanStore(dir), dir };
}

test("targets are what is left after the options", () => {
  assert.deepEqual(targetsFromArgs("nmap -sS -sV -O -sC --traceroute -T4 -oX - 10.0.0.0/28"), ["10.0.0.0/28"]);
  assert.deepEqual(targetsFromArgs("nmap -p 22,80 --script vuln -T4 a.example b.example"), ["a.example", "b.example"]);
  assert.deepEqual(targetsFromArgs("nmap -v --stats-every 1s -oX - -sT -F 127.0.0.1"), ["127.0.0.1"]);
});

test("saves, lists, loads, labels, removes", () => {
  const { store, dir } = tempStore();
  try {
    const record = store.save(scan("estate.xml"), fixture("estate.xml"));
    assert.match(record.id, /^\d{8}-\d{6}-10\.0\.0\.0_28$/);
    assert.equal(record.hostsUp, 5);
    assert.equal(record.openPorts, 16);
    assert.deepEqual(record.targets, ["10.0.0.0/28"]);
    assert.ok(existsSync(join(dir, record.file)));

    const second = store.save(scan("estate.xml"), fixture("estate.xml"));
    assert.notEqual(second.id, record.id, "ids do not collide");

    assert.equal(store.list().length, 2);
    const loaded = store.load(record.id)!;
    assert.equal(loaded.result.hosts.length, 6);
    assert.equal(loaded.xml, fixture("estate.xml"));

    store.relabel(record.id, "lab baseline");
    assert.equal(store.get(record.id)?.label, "lab baseline");

    assert.equal(store.remove(record.id), true);
    assert.equal(store.list().length, 1);
    assert.equal(store.load(record.id), undefined);
    assert.ok(!existsSync(join(dir, record.file)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("imports a file and reconciles strays", () => {
  const { store, dir } = tempStore();
  try {
    const path = join(dir, "outside.xml");
    writeFileSync(path, fixture("localhost.xml"));
    const record = store.import(path, "laptop");
    assert.equal(record.label, "laptop");
    assert.equal(record.hostsUp, 1);
    // A file dropped straight into scans/ is adopted; a vanished index entry is dropped.
    writeFileSync(join(dir, "scans", "stray.xml"), fixture("estate.xml"));
    rmSync(join(dir, record.file));
    const delta = store.reconcile();
    assert.equal(delta, 0);
    const ids = store.list().map((r) => r.id);
    assert.deepEqual(ids, ["stray"]);
    const index = JSON.parse(readFileSync(join(dir, "index.json"), "utf8")) as { version: number };
    assert.equal(index.version, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the data dir honours the environment", () => {
  assert.equal(defaultDataDir({ NMAPTUI_DATA_DIR: "/x" }), "/x");
  assert.equal(defaultDataDir({ XDG_DATA_HOME: "/y" }), join("/y", "nmaptui"));
  assert.equal(defaultDataDir({}), join(homedir(), ".local", "share", "nmaptui"));
});
