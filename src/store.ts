/**
 * Scan history on disk. Each run keeps its raw XML next to an index entry so
 * a scan can be reopened, diffed against a later one, or exported again.
 * Default location: $XDG_DATA_HOME/nmaptui or ~/.local/share/nmaptui.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseXml } from "./xml.ts";
import { fromElement, openPorts, type ScanResult } from "./model.ts";

export interface ScanRecord {
  id: string;
  file: string;
  startedAt: number;
  finishedAt?: number;
  args: string;
  targets: string[];
  hostsUp: number;
  hostsTotal: number;
  openPorts: number;
  elapsed?: number;
  partial: boolean;
  /** Free-form label the user can set. */
  label?: string;
}

interface Index {
  version: 1;
  scans: ScanRecord[];
}

export function defaultDataDir(env: NodeJS.ProcessEnv = process.env): string {
  if (env.NMAPTUI_DATA_DIR) return env.NMAPTUI_DATA_DIR;
  const base = env.XDG_DATA_HOME && env.XDG_DATA_HOME.trim() ? env.XDG_DATA_HOME : join(homedir(), ".local", "share");
  return join(base, "nmaptui");
}

/** Targets as nmap was given them: everything after the last option. */
export function targetsFromArgs(args: string): string[] {
  const parts = args.split(/\s+/).filter(Boolean).slice(1);
  const withValue = new Set(["-p", "-oX", "-oN", "-oG", "-oA", "-oS", "--stats-every", "--script", "--script-args", "-e", "-iL", "--exclude", "--top-ports", "--version-intensity", "--host-timeout", "--max-retries", "--min-rate", "--max-rate", "--source-port", "-g", "-S", "-D", "--datadir", "--dns-servers", "--exclude-ports", "--scan-delay", "--max-scan-delay", "--min-hostgroup", "--max-hostgroup", "--min-parallelism", "--max-parallelism", "--initial-rtt-timeout", "--min-rtt-timeout", "--max-rtt-timeout", "--ttl", "--spoof-mac", "--proxies", "--data", "--data-string", "--data-length", "--ip-options", "--mtu", "--port-ratio", "--script-timeout", "-i", "--resume", "--stylesheet"]);
  const targets: string[] = [];
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i] as string;
    if (p.startsWith("-")) {
      if (withValue.has(p) || /^--[a-z-]+$/.test(p) && withValue.has(p)) i++;
      continue;
    }
    targets.push(p);
  }
  return targets;
}

export class ScanStore {
  readonly dir: string;
  private indexPath: string;

  constructor(dir: string = defaultDataDir()) {
    this.dir = dir;
    this.indexPath = join(dir, "index.json");
  }

  private ensure(): void {
    mkdirSync(join(this.dir, "scans"), { recursive: true });
  }

  private readIndex(): Index {
    if (!existsSync(this.indexPath)) return { version: 1, scans: [] };
    try {
      const parsed = JSON.parse(readFileSync(this.indexPath, "utf8")) as Index;
      return parsed.version === 1 && Array.isArray(parsed.scans) ? parsed : { version: 1, scans: [] };
    } catch {
      return { version: 1, scans: [] };
    }
  }

  private writeIndex(index: Index): void {
    this.ensure();
    const tmp = `${this.indexPath}.tmp`;
    writeFileSync(tmp, JSON.stringify(index, null, 2));
    renameSync(tmp, this.indexPath);
  }

  list(): ScanRecord[] {
    return this.readIndex().scans.slice().sort((a, b) => b.startedAt - a.startedAt);
  }

  get(id: string): ScanRecord | undefined {
    return this.readIndex().scans.find((s) => s.id === id);
  }

  static recordFor(result: ScanResult, id: string, file: string): ScanRecord {
    const startedAt = (result.start ?? Math.floor(Date.now() / 1000)) * 1000;
    return {
      id,
      file,
      startedAt,
      finishedAt: result.runStats?.finishedAt ? result.runStats.finishedAt * 1000 : undefined,
      args: result.args,
      targets: targetsFromArgs(result.args),
      hostsUp: result.runStats?.up ?? result.hosts.filter((h) => h.state === "up").length,
      hostsTotal: result.runStats?.total ?? result.hosts.length,
      openPorts: result.hosts.reduce((n, h) => n + openPorts(h).length, 0),
      elapsed: result.runStats?.elapsed,
      partial: result.partial,
    };
  }

  /** Persist a finished (or aborted) run. Returns its record. */
  save(result: ScanResult, xml: string, label?: string): ScanRecord {
    this.ensure();
    const started = new Date((result.start ?? Math.floor(Date.now() / 1000)) * 1000);
    const pad = (n: number): string => String(n).padStart(2, "0");
    const stamp = `${started.getFullYear()}${pad(started.getMonth() + 1)}${pad(started.getDate())}-${pad(started.getHours())}${pad(started.getMinutes())}${pad(started.getSeconds())}`;
    const slug = (targetsFromArgs(result.args)[0] ?? "scan").replace(/[^A-Za-z0-9.-]+/g, "_").slice(0, 40);
    let id = `${stamp}-${slug}`;
    const index = this.readIndex();
    let n = 2;
    while (index.scans.some((s) => s.id === id)) id = `${stamp}-${slug}-${n++}`;
    const file = join("scans", `${id}.xml`);
    writeFileSync(join(this.dir, file), xml);
    const record = { ...ScanStore.recordFor(result, id, file), label };
    index.scans.push(record);
    this.writeIndex(index);
    return record;
  }

  /** Register an XML file that already exists elsewhere, copying it in. */
  import(path: string, label?: string): ScanRecord {
    const xml = readFileSync(path, "utf8");
    const result = fromElement(parseXml(xml));
    return this.save(result, xml, label ?? path);
  }

  load(id: string): { record: ScanRecord; result: ScanResult; xml: string } | undefined {
    const record = this.get(id);
    if (!record) return undefined;
    const path = join(this.dir, record.file);
    if (!existsSync(path)) return undefined;
    const xml = readFileSync(path, "utf8");
    return { record, result: fromElement(parseXml(xml)), xml };
  }

  relabel(id: string, label: string): void {
    const index = this.readIndex();
    const record = index.scans.find((s) => s.id === id);
    if (!record) return;
    record.label = label;
    this.writeIndex(index);
  }

  remove(id: string): boolean {
    const index = this.readIndex();
    const record = index.scans.find((s) => s.id === id);
    if (!record) return false;
    rmSync(join(this.dir, record.file), { force: true });
    index.scans = index.scans.filter((s) => s.id !== id);
    this.writeIndex(index);
    return true;
  }

  /** Drop index entries whose XML has gone missing, and adopt stray files. */
  reconcile(): number {
    const index = this.readIndex();
    const before = index.scans.length;
    index.scans = index.scans.filter((s) => existsSync(join(this.dir, s.file)));
    const known = new Set(index.scans.map((s) => s.file));
    const scansDir = join(this.dir, "scans");
    if (existsSync(scansDir)) {
      for (const name of readdirSync(scansDir)) {
        if (!name.endsWith(".xml")) continue;
        const file = join("scans", name);
        if (known.has(file)) continue;
        try {
          const result = fromElement(parseXml(readFileSync(join(this.dir, file), "utf8")));
          index.scans.push(ScanStore.recordFor(result, name.replace(/\.xml$/, ""), file));
        } catch {
          // Not a scan; leave it alone.
        }
      }
    }
    this.writeIndex(index);
    return index.scans.length - before;
  }
}

/** Load a result from an XML file on disk (not necessarily in the store). */
export function loadXmlFile(path: string): { result: ScanResult; xml: string } {
  const xml = readFileSync(path, "utf8");
  return { result: fromElement(parseXml(xml)), xml };
}
