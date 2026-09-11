import { test } from "node:test";
import assert from "node:assert/strict";
import { bestOs, decodeScriptText, displayName, formatDuration, openPorts, osFamily, serviceLabel } from "../src/model.ts";
import { scan } from "./helpers.ts";

test("reads hosts, ports, services and run stats", () => {
  const result = scan("estate.xml");
  assert.equal(result.version, "7.98");
  assert.equal(result.hosts.length, 6);
  assert.equal(result.partial, false);
  assert.equal(result.runStats?.up, 5);
  assert.equal(result.runStats?.elapsed, 61.2);
  assert.equal(result.tasks.length, 9);
  assert.deepEqual(result.tasks.find((t) => t.kind === "progress"), { kind: "progress", task: "SYN Stealth Scan", time: 1789078212, percent: 41.2, remaining: 14, etc: 1789078226, extrainfo: undefined });

  const gw = result.hosts[0]!;
  assert.equal(gw.addr, "10.0.0.1");
  assert.equal(gw.mac, "52:54:00:AA:BB:01");
  assert.equal(gw.vendor, "QEMU virtual NIC");
  assert.equal(displayName(gw), "10.0.0.1 (gw.lab.internal)");
  assert.equal(openPorts(gw).length, 3);
  assert.deepEqual(gw.extraPorts, [{ state: "closed", count: 997 }]);
  assert.equal(bestOs(gw)?.name, "Linux 4.15 - 5.8");
  assert.equal(osFamily(gw), "Linux");
  assert.equal(gw.uptime?.seconds, 1234567);
  assert.equal(gw.distance, 1);
  assert.equal(gw.trace.hops.length, 1);
  assert.equal(gw.srtt, 412);

  const ssh = gw.ports.find((p) => p.port === 22)!;
  assert.equal(ssh.state, "open");
  assert.equal(ssh.reason, "syn-ack");
  assert.equal(serviceLabel(ssh), "OpenSSH 7.4 (protocol 2.0)");
  assert.deepEqual(ssh.service?.cpe, ["cpe:/a:openbsd:openssh:7.4"]);
  assert.equal(ssh.scripts[0]?.id, "ssh-hostkey");
  assert.deepEqual(ssh.scripts[0]?.elems.map((e) => e.key), ["type", "bits", "fingerprint"]);
});

test("nested script tables flatten with dotted keys", () => {
  const db = scan("estate.xml").hosts.find((h) => h.addr === "10.0.0.7")!;
  const cert = db.ports.find((p) => p.port === 8443)!.scripts.find((s) => s.id === "ssl-cert")!;
  assert.equal(cert.elems.find((e) => e.key === "validity.notAfter")?.value, "2024-01-01T00:00:00");
  assert.equal(db.ports.find((p) => p.port === 8443)?.service?.tunnel, "ssl");
});

test("host scripts and a down host parse", () => {
  const result = scan("estate.xml");
  const files = result.hosts.find((h) => h.addr === "10.0.0.5")!;
  assert.equal(files.hostScripts.length, 3);
  assert.equal(osFamily(files), "Windows");
  const down = result.hosts.find((h) => h.addr === "10.0.0.13")!;
  assert.equal(down.state, "down");
  assert.equal(down.ports.length, 0);
});

test("os family falls back to the service ostype", () => {
  const result = scan("localhost.xml");
  assert.equal(result.hosts[0]!.os.length, 0);
  assert.equal(osFamily(result.hosts[0]!), "Linux");
});

test("script output byte escapes decode as UTF-8", () => {
  assert.equal(decodeScriptText("Profullstack, Inc. \\xE2\\x80\\x94 Web"), "Profullstack, Inc. \u2014 Web");
  assert.equal(decodeScriptText("NetBIOS name: FILES\\x00"), "NetBIOS name: FILES\u0000");
  assert.equal(decodeScriptText("bad \\xFF\\xFE run"), "bad \\xFF\\xFE run");
  assert.equal(decodeScriptText("plain"), "plain");
});

test("durations read well", () => {
  assert.equal(formatDuration(3.456), "3.5s");
  assert.equal(formatDuration(59), "59s");
  assert.equal(formatDuration(61.2), "1m 1s");
  assert.equal(formatDuration(3700), "1h 1m");
  assert.equal(formatDuration(undefined), "");
});
