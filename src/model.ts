/**
 * The typed shape of an nmap run, and the reader that builds it from nmap's
 * XML. Everything downstream (screens, diff, reports, findings) works on
 * these types and never touches XML again.
 */
import { attr, child, children, numAttr, type XmlElement } from "./xml.ts";

export type PortState = "open" | "closed" | "filtered" | "unfiltered" | "open|filtered" | "closed|filtered" | string;

export interface Script {
  id: string;
  output: string;
  /** Structured output flattened to `key: value` lines, when nmap gave any. */
  elems: { key: string; value: string }[];
}

export interface Service {
  name: string;
  product?: string;
  version?: string;
  extrainfo?: string;
  tunnel?: string;
  ostype?: string;
  method?: string;
  conf?: number;
  cpe: string[];
}

export interface Port {
  protocol: string;
  port: number;
  state: PortState;
  reason?: string;
  reasonTtl?: number;
  service?: Service;
  scripts: Script[];
}

export interface OsMatch {
  name: string;
  accuracy: number;
  classes: { type?: string; vendor?: string; family?: string; gen?: string; accuracy?: number; cpe: string[] }[];
}

export interface Hop {
  ttl: number;
  ip?: string;
  host?: string;
  rtt?: number;
}

export interface Host {
  /** Primary address: the first IPv4/IPv6 found. */
  addr: string;
  addresses: { addr: string; type: string; vendor?: string }[];
  mac?: string;
  vendor?: string;
  hostnames: { name: string; type?: string }[];
  state: "up" | "down" | "unknown" | "skipped" | string;
  stateReason?: string;
  ports: Port[];
  /** Port states summarised with `extraports`: "999 closed". */
  extraPorts: { state: string; count: number }[];
  os: OsMatch[];
  uptime?: { seconds: number; lastBoot?: string };
  distance?: number;
  trace: { port?: number; protocol?: string; hops: Hop[] };
  hostScripts: Script[];
  startTime?: number;
  endTime?: number;
  /** Smoothed round trip time in microseconds. */
  srtt?: number;
  comment?: string;
}

export interface ScanInfo {
  type: string;
  protocol: string;
  numServices?: number;
  services?: string;
}

export interface TaskEvent {
  kind: "begin" | "progress" | "end";
  task: string;
  time: number;
  percent?: number;
  remaining?: number;
  etc?: number;
  extrainfo?: string;
}

export interface RunStats {
  finishedAt?: number;
  timeStr?: string;
  summary?: string;
  elapsed?: number;
  exit?: string;
  errorMsg?: string;
  up: number;
  down: number;
  total: number;
}

export interface ScanResult {
  scanner: string;
  args: string;
  version: string;
  start?: number;
  startStr?: string;
  scanInfo: ScanInfo[];
  verbose?: number;
  hosts: Host[];
  tasks: TaskEvent[];
  runStats?: RunStats;
  /** True when the XML ended before `</nmaprun>`: an aborted or crashed run. */
  partial: boolean;
}

export function emptyResult(): ScanResult {
  return { scanner: "nmap", args: "", version: "", scanInfo: [], hosts: [], tasks: [], partial: true };
}

/**
 * nmap writes non-ASCII bytes in script output as \xHH escapes. Turn runs of
 * them back into text so a UTF-8 page title reads as one.
 */
export function decodeScriptText(text: string): string {
  if (!text.includes("\\x")) return text;
  return text.replace(/(?:\\x[0-9A-Fa-f]{2})+/g, (run) => {
    const bytes = Uint8Array.from(run.match(/[0-9A-Fa-f]{2}/g)!.map((h) => parseInt(h, 16)));
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      return run;
    }
  });
}

function parseScript(el: XmlElement): Script {
  const elems: Script["elems"] = [];
  const walk = (node: XmlElement, prefix: string): void => {
    for (const c of node.children) {
      if (c.name === "elem") {
        const key = c.attrs.key ? `${prefix}${c.attrs.key}` : prefix.replace(/\.$/, "");
        elems.push({ key, value: decodeScriptText(c.text.trim()) });
      } else if (c.name === "table") {
        walk(c, c.attrs.key ? `${prefix}${c.attrs.key}.` : prefix);
      }
    }
  };
  walk(el, "");
  return { id: el.attrs.id ?? "", output: decodeScriptText((el.attrs.output ?? "").replace(/\r/g, "")), elems };
}

function parseService(el: XmlElement | undefined): Service | undefined {
  if (!el) return undefined;
  return {
    name: el.attrs.name ?? "",
    product: el.attrs.product,
    version: el.attrs.version,
    extrainfo: el.attrs.extrainfo,
    tunnel: el.attrs.tunnel,
    ostype: el.attrs.ostype,
    method: el.attrs.method,
    conf: numAttr(el, "conf"),
    cpe: children(el, "cpe").map((c) => c.text.trim()).filter(Boolean),
  };
}

function parsePort(el: XmlElement): Port {
  const state = child(el, "state");
  return {
    protocol: el.attrs.protocol ?? "tcp",
    port: Number(el.attrs.portid ?? 0),
    state: attr(state, "state") ?? "unknown",
    reason: attr(state, "reason"),
    reasonTtl: numAttr(state, "reason_ttl"),
    service: parseService(child(el, "service")),
    scripts: children(el, "script").map(parseScript),
  };
}

function parseOs(el: XmlElement | undefined): OsMatch[] {
  if (!el) return [];
  return children(el, "osmatch").map((m) => ({
    name: m.attrs.name ?? "",
    accuracy: numAttr(m, "accuracy") ?? 0,
    classes: children(m, "osclass").map((c) => ({
      type: c.attrs.type,
      vendor: c.attrs.vendor,
      family: c.attrs.osfamily,
      gen: c.attrs.osgen,
      accuracy: numAttr(c, "accuracy"),
      cpe: children(c, "cpe").map((x) => x.text.trim()),
    })),
  }));
}

export function parseHost(el: XmlElement): Host {
  const status = child(el, "status");
  const addresses = children(el, "address").map((a) => ({
    addr: a.attrs.addr ?? "",
    type: a.attrs.addrtype ?? "ipv4",
    vendor: a.attrs.vendor,
  }));
  const ip = addresses.find((a) => a.type === "ipv4") ?? addresses.find((a) => a.type === "ipv6");
  const mac = addresses.find((a) => a.type === "mac");
  const portsEl = child(el, "ports");
  const uptime = child(el, "uptime");
  const trace = child(el, "trace");
  const times = child(el, "times");
  return {
    addr: ip?.addr ?? addresses[0]?.addr ?? "",
    addresses,
    mac: mac?.addr,
    vendor: mac?.vendor,
    hostnames: children(child(el, "hostnames"), "hostname").map((h) => ({ name: h.attrs.name ?? "", type: h.attrs.type })),
    state: attr(status, "state") ?? "unknown",
    stateReason: attr(status, "reason"),
    ports: children(portsEl, "port").map(parsePort),
    extraPorts: children(portsEl, "extraports").map((e) => ({ state: e.attrs.state ?? "", count: numAttr(e, "count") ?? 0 })),
    os: parseOs(child(el, "os")),
    uptime: uptime ? { seconds: numAttr(uptime, "seconds") ?? 0, lastBoot: uptime.attrs.lastboot } : undefined,
    distance: numAttr(child(el, "distance"), "value"),
    trace: {
      port: numAttr(trace, "port"),
      protocol: attr(trace, "proto"),
      hops: children(trace, "hop").map((h) => ({
        ttl: numAttr(h, "ttl") ?? 0,
        ip: h.attrs.ipaddr,
        host: h.attrs.host,
        rtt: numAttr(h, "rtt"),
      })),
    },
    hostScripts: children(child(el, "hostscript"), "script").map(parseScript),
    startTime: numAttr(el, "starttime"),
    endTime: numAttr(el, "endtime"),
    srtt: numAttr(times, "srtt"),
    comment: el.attrs.comment,
  };
}

export function parseTask(el: XmlElement): TaskEvent | undefined {
  const kind = el.name === "taskbegin" ? "begin" : el.name === "taskprogress" ? "progress" : el.name === "taskend" ? "end" : undefined;
  if (!kind) return undefined;
  return {
    kind,
    task: el.attrs.task ?? "",
    time: numAttr(el, "time") ?? 0,
    percent: numAttr(el, "percent"),
    remaining: numAttr(el, "remaining"),
    etc: numAttr(el, "etc"),
    extrainfo: el.attrs.extrainfo,
  };
}

export function parseRunStats(el: XmlElement): RunStats {
  const finished = child(el, "finished");
  const hosts = child(el, "hosts");
  return {
    finishedAt: numAttr(finished, "time"),
    timeStr: attr(finished, "timestr"),
    summary: attr(finished, "summary"),
    elapsed: numAttr(finished, "elapsed"),
    exit: attr(finished, "exit"),
    errorMsg: attr(finished, "errormsg"),
    up: numAttr(hosts, "up") ?? 0,
    down: numAttr(hosts, "down") ?? 0,
    total: numAttr(hosts, "total") ?? 0,
  };
}

/** Apply the root attributes of `<nmaprun>`. */
export function applyRoot(result: ScanResult, attrs: Record<string, string>): void {
  result.scanner = attrs.scanner ?? "nmap";
  result.args = attrs.args ?? "";
  result.version = attrs.version ?? "";
  result.start = attrs.start ? Number(attrs.start) : undefined;
  result.startStr = attrs.startstr;
}

/**
 * Fold one direct child of `<nmaprun>` into the result. Returns what kind of
 * thing it was so a live view knows whether to redraw the host table or the
 * progress bars.
 */
export function applyElement(result: ScanResult, el: XmlElement): "host" | "task" | "runstats" | "scaninfo" | "other" {
  switch (el.name) {
    case "host": {
      const host = parseHost(el);
      const existing = result.hosts.findIndex((h) => h.addr === host.addr && h.addr !== "");
      if (existing >= 0) result.hosts[existing] = host;
      else result.hosts.push(host);
      return "host";
    }
    case "taskbegin":
    case "taskprogress":
    case "taskend": {
      const task = parseTask(el);
      if (task) result.tasks.push(task);
      return "task";
    }
    case "runstats":
      result.runStats = parseRunStats(el);
      result.partial = false;
      return "runstats";
    case "scaninfo":
      result.scanInfo.push({
        type: el.attrs.type ?? "",
        protocol: el.attrs.protocol ?? "",
        numServices: numAttr(el, "numservices"),
        services: el.attrs.services,
      });
      return "scaninfo";
    case "verbose":
      result.verbose = numAttr(el, "level");
      return "other";
    default:
      return "other";
  }
}

/** Build a result from a parsed `<nmaprun>` element. */
export function fromElement(root: XmlElement): ScanResult {
  if (root.name !== "nmaprun") throw new Error(`Expected <nmaprun>, found <${root.name}>`);
  const result = emptyResult();
  applyRoot(result, root.attrs);
  for (const el of root.children) applyElement(result, el);
  return result;
}

// ------------------------------------------------------------------ helpers

export function primaryName(host: Host): string {
  return host.hostnames.find((h) => h.type === "user")?.name ?? host.hostnames[0]?.name ?? "";
}

export function displayName(host: Host): string {
  const name = primaryName(host);
  return name && name !== host.addr ? `${host.addr} (${name})` : host.addr;
}

export function openPorts(host: Host): Port[] {
  return host.ports.filter((p) => p.state === "open");
}

export function serviceLabel(port: Port): string {
  const s = port.service;
  if (!s) return "";
  const parts = [s.product, s.version, s.extrainfo ? `(${s.extrainfo})` : undefined].filter(Boolean);
  return parts.join(" ");
}

export function bestOs(host: Host): OsMatch | undefined {
  return host.os.slice().sort((a, b) => b.accuracy - a.accuracy)[0];
}

export function osFamily(host: Host): string {
  const best = bestOs(host);
  const family = best?.classes.find((c) => c.family)?.family;
  if (family) return family;
  const ostype = host.ports.find((p) => p.service?.ostype)?.service?.ostype;
  return ostype ?? "";
}

/** "Sat Sep 11 09:30:34 2026" style stamp from epoch seconds. */
export function formatTime(epoch: number | undefined): string {
  if (!epoch) return "";
  const d = new Date(epoch * 1000);
  const pad = (n: number): string => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function formatDuration(seconds: number | undefined): string {
  if (seconds === undefined || !Number.isFinite(seconds)) return "";
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}
