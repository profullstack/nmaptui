import { test } from "node:test";
import assert from "node:assert/strict";
import { child, children, decodeEntities, parseXml, XmlStream } from "../src/xml.ts";
import { fixture } from "./helpers.ts";

test("decodes the entities nmap writes", () => {
  assert.equal(decodeEntities("a &lt;b&gt; &amp; &quot;c&quot; &#45;&#x2D; &apos;"), `a <b> & "c" -- '`);
  assert.equal(decodeEntities("no entities"), "no entities");
  assert.equal(decodeEntities("&unknown;"), "&unknown;");
});

test("parses a whole nmap document", () => {
  const root = parseXml(fixture("localhost.xml"));
  assert.equal(root.name, "nmaprun");
  assert.equal(root.attrs.scanner, "nmap");
  assert.equal(root.attrs.args, "nmap -sT -sV --top-ports 20 --stats-every 1s -oX - 127.0.0.1");
  const host = child(root, "host");
  assert.ok(host);
  assert.equal(children(child(host, "ports"), "port").length, 20);
  assert.equal(child(child(root, "runstats"), "hosts")?.attrs.up, "1");
});

test("keeps character data, including CDATA and script output with newlines", () => {
  const root = parseXml(`<a><b key="x">hello &amp; bye</b><c><![CDATA[<raw> & stuff]]></c><d output="line1&#xa;line2"/></a>`);
  assert.equal(child(root, "b")?.text, "hello & bye");
  assert.equal(child(root, "c")?.text, "<raw> & stuff");
  assert.equal(child(root, "d")?.attrs.output, "line1\nline2");
});

test("rejects mismatched tags", () => {
  assert.throws(() => parseXml("<a><b></a>"), /Mismatched/);
});

test("streams direct children of the root as they complete, at any chunk boundary", () => {
  const text = fixture("estate.xml");
  for (const size of [1, 7, 64, 1000, text.length]) {
    const seen: string[] = [];
    let ended = false;
    const stream = new XmlStream({ onElement: (el) => seen.push(el.name), onEnd: () => (ended = true) });
    for (let i = 0; i < text.length; i += size) stream.write(text.slice(i, i + size));
    assert.equal(stream.rootName, "nmaprun", `chunk ${size}`);
    assert.equal(seen.filter((n) => n === "host").length, 6, `chunk ${size}`);
    assert.ok(seen.includes("taskprogress"));
    assert.ok(seen.includes("runstats"));
    assert.equal(ended, true, `chunk ${size}`);
  }
});

test("a stream cut short keeps what it has and reports partial", () => {
  const text = fixture("estate.xml");
  const cut = text.slice(0, text.indexOf("<host starttime", text.indexOf("<host starttime") + 10) + 40);
  const stream = new XmlStream();
  stream.write(cut);
  assert.equal(stream.elements.filter((e) => e.name === "host").length, 1);
  assert.equal(stream.partial(), true);
});
