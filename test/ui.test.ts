import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToText } from "@profullstack/hqtui/testing";
import { diffScans } from "../src/diff.ts";
import { ScanStore } from "../src/store.ts";
import { Controller } from "../src/ui/controller.ts";
import { LineEditor } from "../src/ui/editor.ts";
import { renderApp } from "../src/ui/render.ts";
import type { KeyEvent } from "@profullstack/hqtui";
import { fixture, scan } from "./helpers.ts";

function controller(): Controller {
  const c = new Controller({ nmap: { path: "nmap", version: "7.98", privileged: false }, sudo: false, store: new ScanStore("/nonexistent/nmaptui-tests") });
  c.setResult(scan("estate.xml"), fixture("estate.xml"), "estate.xml");
  return c;
}

function frame(c: Controller, width = 150, height = 42): string {
  return renderToText(({ ui, theme, width: w, height: h }) => renderApp(c.state, ui, { theme, width: w, height: h }, c.actions, c.palette()), { width, height });
}

function key(name: string, extra: Partial<KeyEvent> = {}): KeyEvent {
  const char = name.length === 1 ? name : undefined;
  return { type: "key", name: name === " " ? "space" : name, ctrl: false, alt: false, shift: false, char, key: name, raw: name, ...extra };
}

test("every screen renders at a wide and a narrow size without throwing", () => {
  const c = controller();
  for (const screen of ["dashboard", "scan", "live", "hosts", "services", "findings", "history", "diff"] as const) {
    c.state.screen = screen;
    for (const [w, h] of [[150, 42], [90, 30], [60, 20]] as const) {
      const text = frame(c, w, h);
      assert.ok(text.includes("nmaptui"), `${screen} ${w}x${h}`);
    }
  }
});

test("dashboard shows the estate at a glance", () => {
  const c = controller();
  c.state.screen = "dashboard";
  const text = frame(c);
  assert.match(text, /nmap -sS -sV -O -sC --traceroute -T4 -oX - 10\.0\.0\.0\/28/);
  assert.match(text, /with open ports/);
  assert.match(text, /Most common open ports/);
  assert.match(text, /80\/tcp http/);
  assert.match(text, /Anonymous FTP/);
});

test("hosts screen lists, filters and shows detail", () => {
  const c = controller();
  c.state.screen = "hosts";
  let text = frame(c);
  assert.match(text, /10\.0\.0\.1 {2,}gw\.lab\.internal/);
  assert.match(text, /5\/6/);
  assert.match(text, /22\/tcp {5}open/);
  // Move down twice: db host.
  c.handleKey(key("j"));
  c.handleKey(key("j"));
  text = frame(c);
  assert.match(text, /db\.lab\.internal/);
  assert.match(text, /3306\/tcp/);
  assert.match(text, /\| ssl-cert/);
  // Filter to the windows box.
  c.handleKey(key("/"));
  for (const ch of "files") c.handleKey(key(ch));
  c.handleKey(key("enter"));
  text = frame(c);
  assert.match(text, /1\/6/);
  assert.match(text, /smb-os-discovery/);
  c.handleKey(key("tab"));
  c.handleKey(key("G"));
  text = frame(c);
  assert.match(text, /Traceroute \(tcp\/445\)/);
  c.handleKey(key("tab"));
  // Escape clears the filter; u shows the down host.
  c.handleKey(key("escape"));
  c.handleKey(key("u"));
  text = frame(c);
  assert.match(text, /6\/6/);
  assert.match(text, /10\.0\.0\.13/);
});

test("services pivot and jump to a host", () => {
  const c = controller();
  c.state.screen = "services";
  let text = frame(c);
  assert.match(text, /http\s+5\s+█/);
  assert.match(text, /nginx 1\.24\.0/);
  c.handleKey(key("j"));
  c.handleKey(key("j"));
  text = frame(c);
  c.handleKey(key("enter"));
  assert.equal(c.state.screen, "hosts");
  assert.ok(c.state.hosts.filter.length > 0);
});

test("findings filter by severity and open the host", () => {
  const c = controller();
  c.state.screen = "findings";
  let text = frame(c);
  assert.match(text, /SMBv1 enabled/);
  assert.match(text, /HTTP without TLS/);
  c.handleKey(key("f")); // -> critical only... cycles from info to critical
  text = frame(c);
  assert.match(text, /min critical/);
  assert.match(text, /nothing at this severity/);
  c.handleKey(key("f"));
  text = frame(c);
  assert.match(text, /min high/);
  assert.doesNotMatch(text, /HTTP without TLS/);
  c.handleKey(key("enter"));
  assert.equal(c.state.screen, "hosts");
  assert.equal(c.state.hosts.filter, "10.0.0.5");
});

test("scan builder edits fields and previews the command", () => {
  const c = controller();
  c.state.screen = "scan";
  c.state.config.targets = "";
  let text = frame(c);
  assert.match(text, /no targets yet/);
  assert.match(text, /nmap -sS -F -T4/);
  // Enter edits the targets field; digits type instead of switching screens while editing.
  c.handleKey(key("enter"));
  for (const ch of "10.0.0.0/24") c.handleKey(key(ch));
  assert.equal(c.state.screen, "scan");
  c.handleKey(key("enter"));
  text = frame(c);
  assert.match(text, /~256 addresses/);
  assert.match(text, /needs root: run with sudo/);
  // Down to Technique, cycle right once: SYN -> connect.
  c.handleKey(key("j"));
  c.handleKey(key("j"));
  c.handleKey(key("j"));
  c.handleKey(key("right"));
  text = frame(c);
  assert.match(text, /nmap -sT -F -T4/);
  assert.doesNotMatch(text, /needs root: run with sudo/);
  // Profiles pane picks vuln.
  c.handleKey(key("tab"));
  while (c.state.profileIndex < 10) c.handleKey(key("j"));
  text = frame(c);
  assert.match(text, /--script vuln/);
  assert.match(text, /10\.0\.0\.0\/24/); // targets survive a profile change
});

test("history, diff and overlays", () => {
  const c = controller();
  c.state.screen = "history";
  let text = frame(c);
  assert.match(text, /No saved scans yet/);
  c.setDiff(scan("estate.xml"), scan("estate-after.xml"), "before", "after");
  assert.deepEqual(diffScans(scan("estate.xml"), scan("estate-after.xml")).summary.added, 1);
  c.state.screen = "diff";
  text = frame(c);
  assert.match(text, /hosts new/);
  assert.match(text, /10\.0\.0\.14 \(new-box\.lab\.internal\) is new/);
  assert.match(text, /tcp\/5432 open: postgresql/);
  c.handleKey(key("?"));
  text = frame(c);
  assert.match(text, /nmaptui keys/);
  c.handleKey(key("escape"));
  c.handleKey(key(":"));
  for (const ch of "vuln") c.handleKey(key(ch));
  text = frame(c);
  assert.match(text, /Profile: Vulnerability scripts/);
  c.handleKey(key("enter"));
  assert.equal(c.state.screen, "scan");
  assert.equal(c.state.config.scripts, "vuln");
  c.handleKey(key("4"));
  c.handleKey(key("e"));
  text = frame(c);
  assert.match(text, /Export/);
  assert.match(text, /nmaptui-scan\.txt/);
  c.handleKey(key("right"));
  text = frame(c);
  assert.match(text, /nmaptui-scan\.json/);
});

test("the line editor behaves like a shell line", () => {
  const e = new LineEditor("hello world");
  e.handle(key("ctrl+w"));
  assert.equal(e.value, "hello ");
  e.handle(key("ctrl+a"));
  e.handle(key("delete"));
  assert.equal(e.value, "ello ");
  e.handle(key("end"));
  e.handle(key("backspace"));
  e.handle(key("x"));
  assert.equal(e.value, "ellox");
  e.handle(key("left"));
  e.handle(key("ctrl+k"));
  assert.equal(e.value, "ello");
  e.handle(key("ctrl+u"));
  assert.equal(e.value, "");
});
