/**
 * What changed between two scans of the same estate: hosts that appeared or
 * vanished, ports that opened or closed, services whose banner moved. The
 * unit of identity is the address, then protocol/port.
 */
import { serviceLabel, type Host, type Port, type ScanResult } from "./model.ts";

export interface PortChange {
  protocol: string;
  port: number;
  kind: "opened" | "closed" | "state" | "service";
  before?: string;
  after?: string;
  detail: string;
}

export interface HostDiff {
  addr: string;
  name?: string;
  kind: "added" | "removed" | "state" | "changed" | "same";
  before?: Host;
  after?: Host;
  ports: PortChange[];
}

export interface ScanDiff {
  a: { args: string; start?: number; hosts: number };
  b: { args: string; start?: number; hosts: number };
  hosts: HostDiff[];
  summary: {
    added: number;
    removed: number;
    stateChanged: number;
    opened: number;
    closed: number;
    serviceChanged: number;
    unchanged: number;
  };
}

function key(p: Port): string {
  return `${p.protocol}/${p.port}`;
}

function describe(p: Port): string {
  const s = p.service;
  const label = serviceLabel(p);
  return [s?.name, label].filter(Boolean).join(" ");
}

export function diffHosts(before: Host, after: Host): PortChange[] {
  const changes: PortChange[] = [];
  const aPorts = new Map(before.ports.map((p) => [key(p), p]));
  const bPorts = new Map(after.ports.map((p) => [key(p), p]));
  const keys = new Set([...aPorts.keys(), ...bPorts.keys()]);
  const sorted = [...keys].sort((x, y) => {
    const [xp, xn] = x.split("/");
    const [yp, yn] = y.split("/");
    return xp === yp ? Number(xn) - Number(yn) : (xp as string).localeCompare(yp as string);
  });
  for (const k of sorted) {
    const a = aPorts.get(k);
    const b = bPorts.get(k);
    const [protocol, portStr] = k.split("/");
    const port = Number(portStr);
    const proto = protocol as string;
    if (a && !b) {
      if (a.state === "open") changes.push({ protocol: proto, port, kind: "closed", before: "open", after: "absent", detail: `${k} no longer reported (was ${describe(a)})` });
      continue;
    }
    if (!a && b) {
      if (b.state === "open") changes.push({ protocol: proto, port, kind: "opened", before: "absent", after: "open", detail: `${k} open: ${describe(b)}` });
      continue;
    }
    if (!a || !b) continue;
    if (a.state !== b.state) {
      const kind = b.state === "open" ? "opened" : a.state === "open" ? "closed" : "state";
      changes.push({ protocol: proto, port, kind, before: a.state, after: b.state, detail: `${k} ${a.state} -> ${b.state}${b.state === "open" ? ` (${describe(b)})` : ""}` });
      continue;
    }
    if (a.state === "open") {
      const da = describe(a);
      const db = describe(b);
      if (da !== db) changes.push({ protocol: proto, port, kind: "service", before: da, after: db, detail: `${k} service ${da || "?"} -> ${db || "?"}` });
    }
  }
  return changes;
}

export function diffScans(a: ScanResult, b: ScanResult): ScanDiff {
  const aHosts = new Map(a.hosts.filter((h) => h.addr).map((h) => [h.addr, h]));
  const bHosts = new Map(b.hosts.filter((h) => h.addr).map((h) => [h.addr, h]));
  const addrs = [...new Set([...aHosts.keys(), ...bHosts.keys()])].sort(compareAddr);
  const hosts: HostDiff[] = [];
  const summary = { added: 0, removed: 0, stateChanged: 0, opened: 0, closed: 0, serviceChanged: 0, unchanged: 0 };

  for (const addr of addrs) {
    const before = aHosts.get(addr);
    const after = bHosts.get(addr);
    const name = (after ?? before)?.hostnames[0]?.name;
    if (before && !after) {
      hosts.push({ addr, name, kind: "removed", before, ports: [] });
      summary.removed++;
      continue;
    }
    if (!before && after) {
      hosts.push({ addr, name, kind: "added", after, ports: [] });
      summary.added++;
      continue;
    }
    if (!before || !after) continue;
    const ports = diffHosts(before, after);
    for (const c of ports) {
      if (c.kind === "opened") summary.opened++;
      else if (c.kind === "closed") summary.closed++;
      else if (c.kind === "service") summary.serviceChanged++;
    }
    if (before.state !== after.state) {
      hosts.push({ addr, name, kind: "state", before, after, ports });
      summary.stateChanged++;
    } else if (ports.length > 0) {
      hosts.push({ addr, name, kind: "changed", before, after, ports });
    } else {
      hosts.push({ addr, name, kind: "same", before, after, ports });
      summary.unchanged++;
    }
  }

  return {
    a: { args: a.args, start: a.start, hosts: a.hosts.length },
    b: { args: b.args, start: b.start, hosts: b.hosts.length },
    hosts,
    summary,
  };
}

export function compareAddr(x: string, y: string): number {
  const xa = x.split(".").map(Number);
  const ya = y.split(".").map(Number);
  if (xa.length === 4 && ya.length === 4 && xa.every(Number.isFinite) && ya.every(Number.isFinite)) {
    for (let i = 0; i < 4; i++) {
      const d = (xa[i] as number) - (ya[i] as number);
      if (d !== 0) return d;
    }
    return 0;
  }
  return x.localeCompare(y);
}

/** Plain text, the way ndiff prints it, minus the unified-diff markers. */
export function formatDiff(diff: ScanDiff): string {
  const lines: string[] = [];
  const { summary } = diff;
  lines.push(`hosts: +${summary.added} added, -${summary.removed} removed, ${summary.stateChanged} changed state, ${summary.unchanged} unchanged`);
  lines.push(`ports: ${summary.opened} opened, ${summary.closed} closed, ${summary.serviceChanged} service changes`);
  for (const h of diff.hosts) {
    if (h.kind === "same") continue;
    const label = h.name ? `${h.addr} (${h.name})` : h.addr;
    if (h.kind === "added") lines.push(`+ ${label} is new (${h.after?.state}, ${h.after?.ports.filter((p) => p.state === "open").length ?? 0} open)`);
    else if (h.kind === "removed") lines.push(`- ${label} is gone (was ${h.before?.state})`);
    else if (h.kind === "state") lines.push(`~ ${label} ${h.before?.state} -> ${h.after?.state}`);
    else lines.push(`~ ${label}`);
    for (const c of h.ports) {
      const mark = c.kind === "opened" ? "+" : c.kind === "closed" ? "-" : "~";
      lines.push(`    ${mark} ${c.detail}`);
    }
  }
  return lines.join("\n");
}
