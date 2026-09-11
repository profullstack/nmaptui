import { test } from "node:test";
import assert from "node:assert/strict";
import { describeTarget, formatCount, parseTargetFile, summarizeTargets } from "../src/targets.ts";

test("classifies target specs the way nmap reads them", () => {
  assert.deepEqual(describeTarget("10.0.0.1"), { spec: "10.0.0.1", kind: "ipv4", count: 1 });
  assert.deepEqual(describeTarget("10.0.0.0/24"), { spec: "10.0.0.0/24", kind: "ipv4-cidr", count: 256 });
  assert.deepEqual(describeTarget("192.168.1.1-50"), { spec: "192.168.1.1-50", kind: "ipv4-range", count: 50 });
  assert.deepEqual(describeTarget("192.168.0-3.*"), { spec: "192.168.0-3.*", kind: "ipv4-range", count: 1024 });
  assert.deepEqual(describeTarget("10.0.0.1,5,9"), { spec: "10.0.0.1,5,9", kind: "ipv4-range", count: 3 });
  assert.deepEqual(describeTarget("example.com"), { spec: "example.com", kind: "hostname", count: 1 });
  assert.deepEqual(describeTarget("example.com/28"), { spec: "example.com/28", kind: "ipv4-cidr", count: 16 });
  assert.deepEqual(describeTarget("2001:db8::1"), { spec: "2001:db8::1", kind: "ipv6", count: 1 });
  assert.equal(describeTarget("2001:db8::/64").kind, "ipv6-cidr");
  assert.equal(describeTarget("10.0.0.300").kind, "invalid");
  assert.equal(describeTarget("10.0.0.0/33").kind, "invalid");
  assert.equal(describeTarget("bad host").kind, "invalid");
  assert.equal(describeTarget("").kind, "invalid");
});

test("summarises a target line", () => {
  const s = summarizeTargets("10.0.0.0/24, example.com 192.168.1.1-10");
  assert.equal(s.valid, true);
  assert.equal(s.count, 267);
  const bad = summarizeTargets("10.0.0.0/24 nope!");
  assert.equal(bad.valid, false);
  assert.equal(bad.invalid[0]?.spec, "nope!");
});

test("formats counts for people", () => {
  assert.equal(formatCount(256), "256");
  assert.equal(formatCount(65536), "65.5k");
  assert.equal(formatCount(16777216), "16.8M");
  assert.equal(formatCount(Number.MAX_SAFE_INTEGER), "astronomical");
});

test("reads target files with comments", () => {
  assert.deepEqual(parseTargetFile("# lab\n10.0.0.1 10.0.0.2 # pair\n\nexample.com\n"), ["10.0.0.1", "10.0.0.2", "example.com"]);
});
