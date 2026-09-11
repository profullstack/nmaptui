/**
 * Target specifications, the way nmap reads them: hostnames, IPv4 addresses,
 * CIDR blocks and octet ranges such as 10.0.0.1-50 or 192.168.0-3.1. Used to
 * validate what the user types and to estimate how many hosts a scan covers,
 * so the builder can warn before someone sweeps a /8 by accident.
 */

export interface TargetInfo {
  spec: string;
  kind: "ipv4" | "ipv4-cidr" | "ipv4-range" | "ipv6" | "ipv6-cidr" | "hostname" | "invalid";
  /** Estimated number of addresses. Hostnames count as one. */
  count: number;
  reason?: string;
}

const HOSTNAME = /^(?=.{1,253}$)([a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?)(\.[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?)*\.?$/;

function parseOctetRange(part: string): number | null {
  if (part === "*") return 256;
  let total = 0;
  for (const piece of part.split(",")) {
    const m = /^(\d{1,3})(?:-(\d{1,3}))?$/.exec(piece);
    if (!m) return null;
    const lo = Number(m[1]);
    const hi = m[2] === undefined ? lo : Number(m[2]);
    if (lo > 255 || hi > 255 || hi < lo) return null;
    total += hi - lo + 1;
  }
  return total;
}

export function describeTarget(raw: string): TargetInfo {
  const spec = raw.trim();
  if (spec.length === 0) return { spec, kind: "invalid", count: 0, reason: "empty" };

  const cidr = /^(.*)\/(\d{1,3})$/.exec(spec);
  const base = cidr ? (cidr[1] as string) : spec;
  const prefix = cidr ? Number(cidr[2]) : undefined;

  if (base.includes(":")) {
    if (!/^[0-9a-fA-F:.]+$/.test(base) || base.split("::").length > 2) {
      return { spec, kind: "invalid", count: 0, reason: "not an IPv6 address" };
    }
    if (prefix !== undefined) {
      if (prefix > 128) return { spec, kind: "invalid", count: 0, reason: "IPv6 prefix above 128" };
      const bits = 128 - prefix;
      return { spec, kind: "ipv6-cidr", count: bits >= 53 ? Number.MAX_SAFE_INTEGER : 2 ** bits };
    }
    return { spec, kind: "ipv6", count: 1 };
  }

  const octets = base.split(".");
  const looksNumeric = octets.length === 4 && octets.every((o) => /^[\d,*-]+$/.test(o));
  if (looksNumeric) {
    const counts = octets.map(parseOctetRange);
    if (counts.some((c) => c === null)) return { spec, kind: "invalid", count: 0, reason: "octet out of range" };
    const product = (counts as number[]).reduce((a, b) => a * b, 1);
    if (prefix !== undefined) {
      if (prefix > 32) return { spec, kind: "invalid", count: 0, reason: "IPv4 prefix above 32" };
      return { spec, kind: "ipv4-cidr", count: product * 2 ** (32 - prefix) };
    }
    return product === 1 ? { spec, kind: "ipv4", count: 1 } : { spec, kind: "ipv4-range", count: product };
  }

  if (!HOSTNAME.test(base)) return { spec, kind: "invalid", count: 0, reason: "not a hostname" };
  if (prefix !== undefined) {
    if (prefix > 32) return { spec, kind: "invalid", count: 0, reason: "prefix above 32" };
    return { spec, kind: "ipv4-cidr", count: 2 ** (32 - prefix) };
  }
  return { spec, kind: "hostname", count: 1 };
}

/** Split a target line on whitespace and commas. */
export function splitTargets(line: string): string[] {
  return line
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export interface TargetSummary {
  targets: TargetInfo[];
  valid: boolean;
  /** Estimated addresses across every valid target. */
  count: number;
  invalid: TargetInfo[];
}

export function summarizeTargets(line: string): TargetSummary {
  const targets = splitTargets(line).map(describeTarget);
  const invalid = targets.filter((t) => t.kind === "invalid");
  const count = targets.reduce((sum, t) => (t.kind === "invalid" ? sum : sum + t.count), 0);
  return { targets, valid: targets.length > 0 && invalid.length === 0, count, invalid };
}

/** Human number: 1,024 or 16.8M. */
export function formatCount(n: number): string {
  if (n >= Number.MAX_SAFE_INTEGER) return "astronomical";
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1)}B`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 10_000) return `${(n / 1000).toFixed(1)}k`;
  return n.toLocaleString("en-US");
}

/** Read targets from a file: one per line, `#` comments allowed. */
export function parseTargetFile(text: string): string[] {
  const out: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const body = line.replace(/#.*$/, "").trim();
    if (body) out.push(...splitTargets(body));
  }
  return out;
}
