import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { historyText, parseArgs, profilesText, VERSION } from "../src/cli.ts";
import { ScanStore } from "../src/store.ts";
import { FIXTURES } from "./helpers.ts";

test("version matches package.json", async () => {
  const pkg = (await import("../package.json", { with: { type: "json" } })).default as { version: string };
  assert.equal(VERSION, pkg.version);
});

test("parses targets, options and subcommands", () => {
  const a = parseArgs(["10.0.0.0/24", "example.com", "-P", "web", "-p", "80,443", "-T3", "--sudo", "--start", "-sC", "--script", "vuln", "-Pn"]);
  assert.equal(a.command, "tui");
  assert.deepEqual(a.positional, ["10.0.0.0/24", "example.com"]);
  assert.equal(a.profile, "web");
  assert.deepEqual(a.config, { ports: "80,443", fast: false, timing: 3, defaultScripts: true, scripts: "vuln", skipPing: true });
  assert.equal(a.sudo, true);
  assert.equal(a.start, true);

  assert.equal(parseArgs(["open", "x.xml"]).command, "open");
  assert.deepEqual(parseArgs(["diff", "a.xml", "b.xml"]).positional, ["a.xml", "b.xml"]);
  assert.equal(parseArgs(["print", "x.xml", "--format", "csv"]).format, "csv");
  assert.equal(parseArgs(["--version"]).command, "version");
  assert.equal(parseArgs(["-h"]).command, "help");
  assert.throws(() => parseArgs(["--format", "docx"]), /unknown format/);
  assert.throws(() => parseArgs(["diff", "only.xml"]), /two XML files/);
  assert.throws(() => parseArgs(["--bogus"]), /unknown option/);
});

test("profiles and history print", () => {
  assert.match(profilesText(false), /quick {11}Quick scan/);
  const json = JSON.parse(profilesText(true)) as { id: string; command: string }[];
  assert.ok(json.some((p) => p.id === "vuln" && p.command.includes("--script vuln")));
  assert.match(historyText(new ScanStore("/nonexistent/nmaptui"), false), /no saved scans/);
});

const bin = join(FIXTURES, "..", "..", "src", "main.ts");
const runCli = (...args: string[]): string => execFileSync(process.execPath, ["--experimental-strip-types", "--no-warnings", bin, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

test("print and diff work end to end without a terminal", () => {
  const text = runCli("print", join(FIXTURES, "estate.xml"));
  assert.match(text, /Host 10\.0\.0\.5 \(files\.lab\.internal\) is up/);
  const csv = runCli("print", join(FIXTURES, "estate.xml"), "--format", "csv");
  assert.match(csv, /^host,hostname/);
  const diff = runCli("diff", join(FIXTURES, "estate.xml"), join(FIXTURES, "estate-after.xml"));
  assert.match(diff, /\+ 10\.0\.0\.14/);
  const version = runCli("--version");
  assert.equal(version.trim(), `nmaptui ${VERSION}`);
});
