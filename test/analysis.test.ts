import { test } from "node:test";
import assert from "node:assert/strict";
import { findings, groupServices, overview, topPorts } from "../src/analysis.ts";
import { scan } from "./helpers.ts";

test("services pivot across hosts", () => {
  const groups = groupServices(scan("estate.xml"));
  const http = groups.find((g) => g.name === "http")!;
  assert.equal(http.hosts.length, 5);
  assert.deepEqual([...http.ports].sort(), ["tcp/443", "tcp/80", "tcp/8443"]);
  assert.equal(http.versions.get("nginx 1.24.0"), 3);
  assert.equal(groups[0]?.name, "http");
  assert.equal(groups.find((g) => g.name === "ssh")?.hosts.length, 2);
});

test("top ports and the overview add up", () => {
  const result = scan("estate.xml");
  const ports = topPorts(result, 3);
  assert.equal(ports[0]?.key, "tcp/80");
  assert.equal(ports[0]?.count, 3);
  const ov = overview(result);
  assert.equal(ov.hosts.up, 5);
  assert.equal(ov.hosts.down, 11);
  assert.equal(ov.hosts.total, 16);
  assert.equal(ov.ports.open, 16);
  assert.equal(ov.ports.filtered, 996);
  assert.equal(ov.withOpenPorts, 5);
  assert.deepEqual(ov.osFamilies[0], { name: "Linux", count: 3 });
});

test("findings triage the estate", () => {
  const list = findings(scan("estate.xml"));
  const ids = list.map((f) => f.id);
  assert.ok(ids.includes("10.0.0.5:tcp/21:anon-ftp"));
  assert.ok(ids.includes("10.0.0.5:tcp/21:plaintext"));
  assert.ok(ids.includes("10.0.0.5:host:smb1"));
  assert.ok(ids.includes("10.0.0.5:host:smb-signing"));
  assert.ok(ids.includes("10.0.0.5:os:eol"));
  assert.ok(ids.includes("10.0.0.7:tcp/3306:database"));
  assert.ok(ids.includes("10.0.0.7:tcp/6379:database"));
  assert.ok(ids.includes("10.0.0.7:tcp/8443:ssl-expired"));
  assert.ok(ids.includes("10.0.0.9:tcp/23:plaintext"));
  assert.ok(ids.includes("10.0.0.1:tcp/22:old-ssh"));
  assert.ok(ids.includes("10.0.0.12:tcp/80:http-no-tls"));
  // TLS-wrapped http is not "http without TLS", and a current OpenSSH is fine.
  assert.ok(!ids.includes("10.0.0.12:tcp/443:http-no-tls"));
  assert.ok(!ids.includes("10.0.0.7:tcp/22:old-ssh"));
  // Ordered by severity.
  const order = list.map((f) => f.severity);
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  for (let i = 1; i < order.length; i++) assert.ok(rank[order[i - 1]!] <= rank[order[i]!]);
  assert.equal(new Set(ids).size, ids.length, "ids are unique");
});

test("a clean scan has nothing to say beyond plain http", () => {
  const list = findings(scan("localhost.xml"));
  assert.deepEqual(list.map((f) => f.id), ["127.0.0.1:tcp/80:http-no-tls"]);
});
