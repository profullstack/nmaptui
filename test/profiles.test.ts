import { test } from "node:test";
import assert from "node:assert/strict";
import { applyProfile, commandLine, defaultConfig, needsRoot, PROFILES, profileById, splitArgs, summarizeArgs, toArgs } from "../src/profiles.ts";

test("the default config is a SYN scan with versions at T4", () => {
  const c = { ...defaultConfig(), targets: "10.0.0.0/24" };
  assert.deepEqual(toArgs(c), ["-sS", "-T4", "-sV", "10.0.0.0/24"]);
  assert.equal(needsRoot(c), true);
});

test("every profile builds a command and has a unique id", () => {
  const ids = new Set<string>();
  for (const p of PROFILES) {
    assert.ok(!ids.has(p.id), p.id);
    ids.add(p.id);
    const c = applyProfile({ ...defaultConfig(), targets: "example.com" }, p);
    const args = toArgs(c);
    assert.equal(args[args.length - 1], "example.com", p.id);
    assert.ok(args.length >= 3, p.id);
  }
});

test("aggressive replaces the individual detection flags", () => {
  const c = applyProfile({ ...defaultConfig(), targets: "h" }, profileById("intense")!);
  const args = toArgs(c);
  assert.ok(args.includes("-A"));
  assert.ok(!args.includes("-sV"));
  assert.ok(!args.includes("-O"));
});

test("ping sweeps drop port and version flags", () => {
  const c = applyProfile({ ...defaultConfig(), targets: "h", ports: "80" }, profileById("ping")!);
  assert.deepEqual(toArgs(c), ["-sn", "-T4", "h"]);
  assert.equal(needsRoot(c), false);
});

test("ports beat fast beat top-ports", () => {
  const base = { ...defaultConfig(), targets: "h", fast: true, topPorts: 50 };
  assert.ok(toArgs(base).includes("-F"));
  assert.ok(toArgs({ ...base, ports: "1-100" }).includes("-p"));
  assert.ok(toArgs({ ...base, fast: false }).includes("--top-ports"));
});

test("connect scans do not need root unless OS detection is on", () => {
  const c = { ...defaultConfig(), targets: "h", technique: "connect" as const };
  assert.equal(needsRoot(c), false);
  assert.equal(needsRoot({ ...c, osDetect: true }), true);
  assert.equal(needsRoot({ ...c, traceroute: true }), true);
});

test("extra arguments respect quotes and land before the targets", () => {
  const c = { ...defaultConfig(), targets: "a b", extra: `--script-args 'http.useragent=Mozilla 5' -D RND:3` };
  const args = toArgs(c);
  assert.deepEqual(args.slice(-6), ["--script-args", "http.useragent=Mozilla 5", "-D", "RND:3", "a", "b"]);
  assert.deepEqual(splitArgs(`a "b c" d\\ e 'f'`), ["a", "b c", "d e", "f"]);
});

test("command lines quote what needs quoting", () => {
  const c = { ...defaultConfig(), targets: "h", scripts: "default or safe" };
  assert.equal(commandLine(c), "nmap -sS -T4 -sV --script 'default or safe' h");
  assert.equal(summarizeArgs("nmap -v --stats-every 1s -oX - -sS -T4 -sV 10.0.0.0/24"), "-sS -T4 -sV");
});
