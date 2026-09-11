import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseXml } from "../src/xml.ts";
import { fromElement, type ScanResult } from "../src/model.ts";

export const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

export function fixture(name: string): string {
  return readFileSync(join(FIXTURES, name), "utf8");
}

export function scan(name: string): ScanResult {
  return fromElement(parseXml(fixture(name)));
}
