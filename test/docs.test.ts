import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { applyProfile, commandLine, defaultConfig, PROFILES, TECHNIQUES } from "../src/profiles.ts";
import { FIXTURES } from "./helpers.ts";

const doc = readFileSync(join(FIXTURES, "..", "..", "docs", "scan-types.md"), "utf8");
const readme = readFileSync(join(FIXTURES, "..", "..", "README.md"), "utf8");

test("docs/scan-types.md names every technique and every profile with its exact command", () => {
  for (const t of TECHNIQUES) assert.ok(doc.includes(`(\`${t.id}\`)`), `technique ${t.id}`);
  for (const p of PROFILES) {
    assert.ok(doc.includes(`### ${p.name} (\`${p.id}\`)`), `profile ${p.id} heading`);
    const command = commandLine(applyProfile({ ...defaultConfig(), targets: "10.0.0.0/24" }, p));
    assert.ok(doc.includes(command), `profile ${p.id} command: ${command}`);
  }
  assert.doesNotMatch(doc, /—|–/);
});

test("the README links to the scan types page", () => {
  assert.match(readme, /docs\/scan-types\.md/);
});
