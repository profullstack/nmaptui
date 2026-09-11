/**
 * Argument parsing and entry point. `nmaptui --help` is the contract.
 */
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { diffScans, formatDiff } from "./diff.ts";
import { findings } from "./analysis.ts";
import { detectNmap } from "./nmap.ts";
import { PROFILES, commandLine, defaultConfig, applyProfile, type ScanConfig } from "./profiles.ts";
import { EXPORT_FORMATS, exportScan, type ExportFormat } from "./report.ts";
import { ScanStore, defaultDataDir, loadXmlFile } from "./store.ts";
import { parseTargetFile } from "./targets.ts";

export const VERSION = "0.1.0";

const USAGE = `nmaptui — an admin console for nmap

Usage
  nmaptui [targets...] [options]        open the console, targets pre-filled
  nmaptui open <scan.xml>               browse an nmap -oX file
  nmaptui diff <before.xml> <after.xml> what changed between two scans
  nmaptui print <scan.xml> [--format f] write a report to stdout and exit
  nmaptui import <scan.xml> [label]     add an nmap -oX file to the history
  nmaptui history                       list saved scans
  nmaptui profiles                      list scan profiles and their flags
  nmaptui update                        upgrade to the latest release
  nmaptui uninstall                     remove nmaptui (scans and history are kept)

Options
  -P, --profile <id>    Start from a profile (see: nmaptui profiles)
  -p, --ports <spec>    Port spec, e.g. 22,80,443 or 1-65535
      --top-ports <n>   Scan the n most common ports
  -T<0-5>               Timing template
  -sT | -sS | -sU | -sn Technique: connect, SYN, UDP, ping sweep
  -sV / --no-version    Version detection on (default) / off
  -sC, --script <expr>  Default scripts / an NSE script expression
  -O, -A, -Pn, -n       OS detection, aggressive, skip ping, no DNS
  -iL <file>            Read targets from a file
      --start           Start the scan immediately
      --sudo            Run nmap through sudo -n for raw-socket scans
      --nmap <path>     nmap binary to use
      --format <f>      print: ${EXPORT_FORMATS.join(", ")} (default text)
  -o, --output <file>   print: write to a file instead of stdout
      --data-dir <dir>  Where scans are kept (default ${defaultDataDir()})
  -t, --theme <name>    Color theme
  -c, --collapse        Merge adjacent panel borders
  -M, --no-mouse        Disable mouse tracking
      --json            history/profiles: machine-readable output
  -v, --version         Print the version
  -h, --help            Print this help

Keys
  1-8 screens · ? help · : commands · e export · q quit
  New scan: tab profiles/options, enter edit, s start
  Hosts: / filter, o open-only, u down hosts, S sort, tab detail
  History: enter open, m mark, d diff marked, i import, D delete
`;

export interface ParsedArgs {
  command: "tui" | "open" | "diff" | "print" | "import" | "history" | "profiles" | "help" | "version" | "update" | "uninstall";
  positional: string[];
  profile?: string;
  config: Partial<ScanConfig>;
  start: boolean;
  sudo: boolean;
  nmap?: string;
  format: ExportFormat;
  output?: string;
  dataDir?: string;
  theme?: string;
  collapse: boolean;
  mouse: boolean;
  json: boolean;
}

class UsageError extends Error {}

export function parseArgs(argv: string[]): ParsedArgs {
  const parsed: ParsedArgs = { command: "tui", positional: [], config: {}, start: false, sudo: false, format: "text", collapse: false, mouse: true, json: false };
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    const next = (): string => {
      const value = argv[++i];
      if (value === undefined) throw new UsageError(`${arg} needs a value`);
      return value;
    };
    if (/^-T[0-5]$/.test(arg)) {
      parsed.config.timing = Number(arg[2]) as ScanConfig["timing"];
      continue;
    }
    switch (arg) {
      case "-h":
      case "--help":
        parsed.command = "help";
        return parsed;
      case "-v":
      case "--version":
        parsed.command = "version";
        return parsed;
      case "-P":
      case "--profile":
        parsed.profile = next();
        break;
      case "-p":
      case "--ports":
        parsed.config.ports = next();
        parsed.config.fast = false;
        break;
      case "-iL":
        parsed.config.targetFile = next();
        break;
      case "--top-ports":
        parsed.config.topPorts = Number(next());
        parsed.config.fast = false;
        break;
      case "-sT":
        parsed.config.technique = "connect";
        break;
      case "-sS":
        parsed.config.technique = "syn";
        break;
      case "-sU":
        parsed.config.technique = "udp";
        break;
      case "-sn":
        parsed.config.technique = "ping";
        break;
      case "-sV":
        parsed.config.serviceVersion = true;
        break;
      case "--no-version":
        parsed.config.serviceVersion = false;
        break;
      case "-sC":
        parsed.config.defaultScripts = true;
        break;
      case "--script":
        parsed.config.scripts = next();
        break;
      case "-O":
        parsed.config.osDetect = true;
        break;
      case "-A":
        parsed.config.aggressive = true;
        break;
      case "-Pn":
        parsed.config.skipPing = true;
        break;
      case "-n":
        parsed.config.noDns = true;
        break;
      case "-F":
        parsed.config.fast = true;
        break;
      case "--start":
        parsed.start = true;
        break;
      case "--sudo":
        parsed.sudo = true;
        break;
      case "--nmap":
        parsed.nmap = next();
        break;
      case "--format": {
        const f = next();
        if (!(EXPORT_FORMATS as readonly string[]).includes(f)) throw new UsageError(`unknown format ${f}; one of ${EXPORT_FORMATS.join(", ")}`);
        parsed.format = f as ExportFormat;
        break;
      }
      case "-o":
      case "--output":
        parsed.output = next();
        break;
      case "--data-dir":
        parsed.dataDir = next();
        break;
      case "-t":
      case "--theme":
        parsed.theme = next();
        break;
      case "-c":
      case "--collapse":
        parsed.collapse = true;
        break;
      case "-M":
      case "--no-mouse":
        parsed.mouse = false;
        break;
      case "--json":
        parsed.json = true;
        break;
      case "--":
        rest.push(...argv.slice(i + 1));
        i = argv.length;
        break;
      default:
        if (arg.startsWith("-") && arg.length > 1) throw new UsageError(`unknown option ${arg}`);
        rest.push(arg);
    }
  }
  const [first, ...others] = rest;
  if (first && ["open", "diff", "print", "import", "history", "profiles", "help", "update", "uninstall"].includes(first)) {
    parsed.command = first as ParsedArgs["command"];
    parsed.positional = others;
  } else {
    parsed.positional = rest;
  }
  if (parsed.command === "open" && parsed.positional.length !== 1) throw new UsageError("open takes one XML file");
  if (parsed.command === "diff" && parsed.positional.length !== 2) throw new UsageError("diff takes two XML files");
  if (parsed.command === "print" && parsed.positional.length !== 1) throw new UsageError("print takes one XML file");
  if (parsed.command === "import" && parsed.positional.length < 1) throw new UsageError("import takes an XML file and an optional label");
  return parsed;
}

export function profilesText(json: boolean): string {
  if (json) return JSON.stringify(PROFILES.map((p) => ({ id: p.id, name: p.name, description: p.description, command: commandLine(applyProfile({ ...defaultConfig(), targets: "<targets>" }, p)) })), null, 2);
  const width = Math.max(...PROFILES.map((p) => p.id.length));
  return PROFILES.map((p) => `${p.id.padEnd(width)}  ${p.name}\n${" ".repeat(width + 2)}${p.description}\n${" ".repeat(width + 2)}${commandLine(applyProfile({ ...defaultConfig(), targets: "<targets>" }, p))}`).join("\n\n");
}

export function historyText(store: ScanStore, json: boolean): string {
  const records = store.list();
  if (json) return JSON.stringify(records, null, 2);
  if (records.length === 0) return `no saved scans in ${store.dir}`;
  return records
    .map((r) => `${r.id}  ${new Date(r.startedAt).toISOString().slice(0, 16).replace("T", " ")}  ${r.hostsUp}/${r.hostsTotal} up  ${r.openPorts} open  ${r.partial ? "partial  " : ""}${r.label ?? r.targets.join(" ")}`)
    .join("\n");
}

/**
 * Where this copy was installed, worked out from the running module rather than
 * guessed: <prefix>/lib/node_modules/@profullstack/nmaptui/dist/cli.js for an
 * npm global install, or a bun global for `bun add -g`.
 */
export function installInfo(moduleUrl: string = import.meta.url): { manager: "npm" | "bun"; prefix: string } {
  const here = dirname(realpathSync(fileURLToPath(moduleUrl)));
  if (here.includes(`${"/"}.bun${"/"}`)) return { manager: "bun", prefix: "" };
  // dist -> package -> @profullstack -> node_modules -> lib -> prefix
  const prefix = resolve(here, "..", "..", "..", "..", "..");
  return { manager: "npm", prefix };
}

function manage(action: "update" | "uninstall"): void {
  const info = installInfo();
  const pkg = "@profullstack/nmaptui";
  const command =
    info.manager === "bun"
      ? action === "update" ? ["bun", "add", "-g", `${pkg}@latest`] : ["bun", "remove", "-g", pkg]
      : action === "update"
        ? ["npm", "install", "-g", "--prefix", info.prefix, "--no-audit", "--no-fund", `${pkg}@latest`]
        : ["npm", "uninstall", "-g", "--prefix", info.prefix, pkg];
  process.stdout.write(`${command.join(" ")}\n`);
  const res = spawnSync(command[0] as string, command.slice(1), { stdio: "inherit" });
  if (res.error) throw res.error;
  if (res.status !== 0) {
    process.exitCode = res.status ?? 1;
    return;
  }
  if (action === "uninstall") process.stdout.write(`removed. Saved scans stay in ${defaultDataDir()}; delete that directory if you want them gone too.\n`);
  else {
    const version = spawnSync(info.manager === "bun" ? "nmaptui" : resolve(info.prefix, "bin", "nmaptui"), ["--version"], { encoding: "utf8" });
    process.stdout.write(version.stdout || "updated\n");
  }
}

export async function main(argv: string[]): Promise<void> {
  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (error) {
    if (error instanceof UsageError) {
      process.stderr.write(`nmaptui: ${error.message}\n\n${USAGE}`);
      process.exitCode = 2;
      return;
    }
    throw error;
  }

  switch (args.command) {
    case "help":
      process.stdout.write(USAGE);
      return;
    case "version":
      process.stdout.write(`nmaptui ${VERSION}\n`);
      return;
    case "profiles":
      process.stdout.write(profilesText(args.json) + "\n");
      return;
    case "update":
    case "uninstall":
      manage(args.command);
      return;
    case "history":
      process.stdout.write(historyText(new ScanStore(args.dataDir), args.json) + "\n");
      return;
    case "import": {
      const [file, ...labelParts] = args.positional;
      const store = new ScanStore(args.dataDir);
      const record = store.import(file as string, labelParts.length ? labelParts.join(" ") : undefined);
      process.stdout.write(`imported ${record.id} (${record.hostsUp} up, ${record.openPorts} open ports)\n`);
      return;
    }
    case "print": {
      const { result, xml } = loadXmlFile(args.positional[0] as string);
      const out = exportScan(result, xml, args.format);
      if (args.output) {
        writeFileSync(args.output, out);
        process.stdout.write(`wrote ${args.output}\n`);
      } else process.stdout.write(out.endsWith("\n") ? out : out + "\n");
      if (!args.output && args.format === "text") {
        const count = findings(result).length;
        if (count > 0) process.stderr.write(`${count} finding${count === 1 ? "" : "s"}; open in the console for detail\n`);
      }
      return;
    }
    case "diff": {
      const [a, b] = args.positional as [string, string];
      if (!process.stdout.isTTY || args.format !== "text" || args.output) {
        const diff = diffScans(loadXmlFile(a).result, loadXmlFile(b).result);
        const text = args.format === "json" ? JSON.stringify(diff, (k, v) => (k === "before" || k === "after" ? undefined : v), 2) : formatDiff(diff);
        if (args.output) writeFileSync(args.output, text);
        else process.stdout.write(text + "\n");
        return;
      }
      const { run } = await import("./app.ts");
      await run({ diff: [a, b], theme: args.theme, mouse: args.mouse, dataDir: args.dataDir, nmapPath: args.nmap, sudo: args.sudo, collapseBorders: args.collapse });
      return;
    }
    case "open": {
      const file = args.positional[0] as string;
      if (!existsSync(file)) throw new Error(`no such file: ${file}`);
      if (!process.stdout.isTTY) {
        process.stdout.write(exportScan(loadXmlFile(file).result, "", "text") + "\n");
        return;
      }
      const { run } = await import("./app.ts");
      await run({ open: file, theme: args.theme, mouse: args.mouse, dataDir: args.dataDir, nmapPath: args.nmap, sudo: args.sudo, collapseBorders: args.collapse });
      return;
    }
    default: {
      if (!process.stdout.isTTY || !process.stdin.isTTY) {
        const info = detectNmap(args.nmap ?? "nmap");
        throw new Error(`nmaptui needs a terminal. ${info ? `nmap ${info.version} found.` : "nmap not found."} Use \`nmaptui print\` or \`nmaptui diff\` for non-interactive output.`);
      }
      const targets = args.positional.slice();
      if (args.config.targetFile && existsSync(args.config.targetFile) && targets.length === 0) {
        // Show what the file holds in the builder; nmap still reads the file itself.
        const fromFile = parseTargetFile(readFileSync(args.config.targetFile, "utf8"));
        if (fromFile.length > 0 && fromFile.length <= 8) targets.push(...fromFile), (args.config.targetFile = undefined);
      }
      const { run } = await import("./app.ts");
      await run({
        targets,
        profile: args.profile,
        config: args.config,
        theme: args.theme,
        mouse: args.mouse,
        sudo: args.sudo,
        nmapPath: args.nmap,
        dataDir: args.dataDir,
        autostart: args.start,
        collapseBorders: args.collapse,
      });
    }
  }
}
