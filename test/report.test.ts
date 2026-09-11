import { test } from "node:test";
import assert from "node:assert/strict";
import { csvReport, EXPORT_FORMATS, exportScan, htmlReport, jsonReport, markdownReport, textReport } from "../src/report.ts";
import { fixture, scan } from "./helpers.ts";

test("text report lists hosts, ports, scripts, findings and a summary", () => {
  const text = textReport(scan("estate.xml"));
  assert.match(text, /Host 10\.0\.0\.1 \(gw\.lab\.internal\) is up/);
  assert.match(text, /22\/tcp {5}open {11}ssh {13}OpenSSH 7\.4/);
  assert.match(text, /\| ssh-hostkey: 2048 aa:bb/);
  assert.match(text, /Not shown: 997 closed ports/);
  assert.match(text, /Traceroute \(tcp\/445\)/);
  assert.match(text, /\[HIGH {4}\] 10\.0\.0\.5 tcp\/21: Anonymous FTP/);
  assert.match(text, /1 host not up: 10\.0\.0\.13/);
  assert.match(text, /Summary: 5 up, 11 down; 16 open ports across 5 hosts; 11 distinct services/);
});

test("csv has one row per open port and quotes commas", () => {
  const csv = csvReport(scan("estate.xml"));
  const lines = csv.trim().split("\n");
  assert.equal(lines[0], "host,hostname,host_state,protocol,port,port_state,reason,service,product,version,extrainfo,tunnel,cpe,os,os_accuracy");
  assert.equal(lines.length, 1 + 16 + 1); // header, open ports, the down host
  assert.match(csv, /10\.0\.0\.7,db\.lab\.internal,up,tcp,8443,open,syn-ack,http,nginx,1\.24\.0,,ssl,cpe:\/a:igor_sysoev:nginx:1\.24\.0,Linux 5\.4 - 6\.1,95/);
  const tricky = scan("estate.xml");
  tricky.hosts[0]!.ports[0]!.service!.product = 'Acme, "Widget" <beta>';
  const quoted = csvReport(tricky);
  assert.match(quoted, /"Acme, ""Widget"" <beta>"/);
  assert.match(htmlReport(tricky), /Acme, &quot;Widget&quot; &lt;beta&gt;/);
});

test("json is parseable and carries findings", () => {
  const json = JSON.parse(jsonReport(scan("estate.xml"))) as { hosts: unknown[]; findings: { id: string }[]; partial: boolean };
  assert.equal(json.hosts.length, 6);
  assert.equal(json.partial, false);
  assert.ok(json.findings.some((f) => f.id === "10.0.0.5:tcp/21:anon-ftp"));
});

test("markdown and html render tables", () => {
  const md = markdownReport(scan("estate.xml"));
  assert.match(md, /^# Scan report/);
  assert.match(md, /\| http \| 5 \|/);
  assert.match(md, /### 10\.0\.0\.5 \(files\.lab\.internal\)/);
  const html = htmlReport(scan("estate.xml"));
  assert.match(html, /<h2>10\.0\.0\.7 <small>db\.lab\.internal<\/small><\/h2>/);
  assert.match(html, /<td>ssh<\/td>/);
});

test("every export format produces output, and xml is verbatim", () => {
  const result = scan("estate.xml");
  for (const f of EXPORT_FORMATS) assert.ok(exportScan(result, fixture("estate.xml"), f).length > 100, f);
  assert.equal(exportScan(result, fixture("estate.xml"), "xml"), fixture("estate.xml"));
});
