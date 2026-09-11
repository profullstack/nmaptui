/**
 * Scan configuration: what the builder screen edits, what the profiles
 * preset, and the one place that turns it into an nmap argument vector.
 * The command line is shown to the user before it runs, so `toArgs` is the
 * contract and must stay readable.
 */

export type ScanTechnique =
  | "syn" | "connect" | "udp" | "syn+udp" | "ack" | "window" | "null" | "fin" | "xmas" | "maimon" | "ping" | "list";

export interface ScanConfig {
  targets: string;
  /** Targets read from a file, passed with -iL. */
  targetFile?: string;
  exclude?: string;
  technique: ScanTechnique;
  /** Port spec such as "22,80,443" or "1-65535". Empty means nmap's default. */
  ports: string;
  /** --top-ports N. Ignored when `ports` is set. */
  topPorts?: number;
  /** -F, the fast 100 ports. */
  fast: boolean;
  timing: 0 | 1 | 2 | 3 | 4 | 5;
  serviceVersion: boolean;
  versionIntensity?: number;
  osDetect: boolean;
  aggressive: boolean;
  defaultScripts: boolean;
  /** --script expression, e.g. "vuln" or "http-title,ssl-cert". */
  scripts: string;
  scriptArgs: string;
  traceroute: boolean;
  skipPing: boolean;
  noDns: boolean;
  ipv6: boolean;
  openOnly: boolean;
  reason: boolean;
  fragment: boolean;
  /** --source-port */
  sourcePort?: number;
  interface?: string;
  /** Host timeout like "30m". */
  hostTimeout?: string;
  maxRetries?: number;
  minRate?: number;
  maxRate?: number;
  /** Anything else, appended verbatim. */
  extra: string;
}

export interface Profile {
  id: string;
  name: string;
  description: string;
  /** Overrides applied on top of the default config. */
  config: Partial<ScanConfig>;
}

export const TECHNIQUES: { id: ScanTechnique; flag: string; label: string; root: boolean }[] = [
  { id: "syn", flag: "-sS", label: "TCP SYN (half-open)", root: true },
  { id: "connect", flag: "-sT", label: "TCP connect", root: false },
  { id: "udp", flag: "-sU", label: "UDP", root: true },
  { id: "syn+udp", flag: "-sS -sU", label: "TCP SYN + UDP", root: true },
  { id: "ack", flag: "-sA", label: "TCP ACK (firewall map)", root: true },
  { id: "window", flag: "-sW", label: "TCP window", root: true },
  { id: "null", flag: "-sN", label: "TCP NULL", root: true },
  { id: "fin", flag: "-sF", label: "TCP FIN", root: true },
  { id: "xmas", flag: "-sX", label: "TCP Xmas", root: true },
  { id: "maimon", flag: "-sM", label: "TCP Maimon", root: true },
  { id: "ping", flag: "-sn", label: "Ping sweep (no ports)", root: false },
  { id: "list", flag: "-sL", label: "List targets (no packets)", root: false },
];

export const TIMING_LABELS = ["T0 paranoid", "T1 sneaky", "T2 polite", "T3 normal", "T4 aggressive", "T5 insane"];

export function defaultConfig(): ScanConfig {
  return {
    targets: "",
    technique: "syn",
    ports: "",
    fast: false,
    timing: 4,
    serviceVersion: true,
    osDetect: false,
    aggressive: false,
    defaultScripts: false,
    scripts: "",
    scriptArgs: "",
    traceroute: false,
    skipPing: false,
    noDns: false,
    ipv6: false,
    openOnly: false,
    reason: false,
    fragment: false,
    extra: "",
  };
}

export const PROFILES: Profile[] = [
  { id: "quick", name: "Quick scan", description: "Top 100 TCP ports, fast timing, no version probes.", config: { fast: true, serviceVersion: false, timing: 4 } },
  { id: "quick-plus", name: "Quick scan plus", description: "Top 100 ports with light version detection and OS fingerprinting.", config: { fast: true, serviceVersion: true, versionIntensity: 2, osDetect: true, timing: 4 } },
  { id: "regular", name: "Regular", description: "nmap's defaults: top 1000 TCP ports, SYN scan, no extras.", config: { serviceVersion: false, timing: 3 } },
  { id: "intense", name: "Intense", description: "Top 1000 ports, versions, OS, default scripts and traceroute.", config: { aggressive: true, serviceVersion: true, timing: 4 } },
  { id: "intense-udp", name: "Intense + UDP", description: "Intense, plus the top UDP ports. Slow.", config: { technique: "syn+udp", aggressive: true, timing: 4 } },
  { id: "intense-all", name: "Intense, all TCP ports", description: "Every TCP port with versions, OS and scripts.", config: { aggressive: true, ports: "1-65535", timing: 4 } },
  { id: "intense-noping", name: "Intense, no ping", description: "Intense against hosts that drop ping probes.", config: { aggressive: true, skipPing: true, timing: 4 } },
  { id: "ping", name: "Ping sweep", description: "Which hosts are up. No ports.", config: { technique: "ping", serviceVersion: false } },
  { id: "traceroute", name: "Quick traceroute", description: "Ping sweep with a route to each host.", config: { technique: "ping", traceroute: true, serviceVersion: false } },
  { id: "safe-scripts", name: "Safe default scripts", description: "Versions plus the default NSE script set.", config: { serviceVersion: true, defaultScripts: true, timing: 4 } },
  { id: "vuln", name: "Vulnerability scripts", description: "Versions plus the NSE vuln category. Noisy, can crash fragile services.", config: { serviceVersion: true, scripts: "vuln", timing: 4 } },
  { id: "discovery", name: "Discovery scripts", description: "Versions plus the NSE discovery category.", config: { serviceVersion: true, scripts: "discovery", timing: 4 } },
  { id: "web", name: "Web services", description: "Common HTTP ports with titles, headers and certificates.", config: { ports: "80,443,8000,8008,8080,8443,8888", serviceVersion: true, scripts: "http-title,http-headers,http-server-header,ssl-cert", timing: 4 } },
  { id: "smb", name: "Windows / SMB", description: "SMB, RDP and WinRM with OS discovery and share enumeration.", config: { ports: "135,139,445,3389,5985,5986", serviceVersion: true, scripts: "smb-os-discovery,smb-security-mode,smb2-security-mode,smb-enum-shares,rdp-ntlm-info", timing: 4 } },
  { id: "databases", name: "Databases", description: "Database ports with version probes.", config: { ports: "1433,1521,3306,5432,5984,6379,7474,8086,9042,9200,11211,27017", serviceVersion: true, timing: 4 } },
  { id: "udp-top", name: "Top 100 UDP", description: "The 100 most common UDP ports with versions.", config: { technique: "udp", topPorts: 100, serviceVersion: true, timing: 4 } },
  { id: "slow", name: "Slow comprehensive", description: "SYN + UDP, all scripts that are safe, every evasion off. Very slow.", config: { technique: "syn+udp", aggressive: true, skipPing: true, scripts: "default or (discovery and safe)", timing: 4, extra: "-PE -PP -PS80,443 -PA3389 -PU40125 -PY" } },
  { id: "connect", name: "Unprivileged", description: "TCP connect scan with versions. Works without root.", config: { technique: "connect", serviceVersion: true, timing: 4 } },
];

export function profileById(id: string): Profile | undefined {
  return PROFILES.find((p) => p.id === id);
}

export function applyProfile(base: ScanConfig, profile: Profile): ScanConfig {
  const fresh = defaultConfig();
  return { ...fresh, ...profile.config, targets: base.targets, targetFile: base.targetFile, exclude: base.exclude };
}

/** Does this configuration need raw sockets? */
export function needsRoot(config: ScanConfig): boolean {
  const technique = TECHNIQUES.find((t) => t.id === config.technique);
  if (technique?.root) return true;
  if (config.osDetect || config.aggressive || config.traceroute || config.fragment) return true;
  return false;
}

/** Split a raw argument string the way a shell would, minus globbing. */
export function splitArgs(text: string): string[] {
  const out: string[] = [];
  let current = "";
  let quote: string | null = null;
  let has = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i] as string;
    if (quote) {
      if (c === quote) quote = null;
      else if (c === "\\" && quote === '"' && i + 1 < text.length) current += text[++i];
      else current += c;
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      has = true;
    } else if (c === "\\" && i + 1 < text.length) {
      current += text[++i];
      has = true;
    } else if (/\s/.test(c)) {
      if (has) out.push(current);
      current = "";
      has = false;
    } else {
      current += c;
      has = true;
    }
  }
  if (has) out.push(current);
  return out;
}

/**
 * The nmap argument vector for a configuration, without the program name and
 * without the output flags nmaptui adds for itself.
 */
export function toArgs(config: ScanConfig): string[] {
  const args: string[] = [];
  const technique = TECHNIQUES.find((t) => t.id === config.technique) ?? TECHNIQUES[0]!;
  args.push(...technique.flag.split(" "));
  const portless = config.technique === "ping" || config.technique === "list";

  if (!portless) {
    if (config.ports.trim()) args.push("-p", config.ports.trim());
    else if (config.fast) args.push("-F");
    else if (config.topPorts) args.push("--top-ports", String(config.topPorts));
  }
  args.push(`-T${config.timing}`);

  if (config.aggressive) args.push("-A");
  else {
    if (config.serviceVersion && !portless) args.push("-sV");
    if (config.osDetect) args.push("-O");
    if (config.defaultScripts && !portless) args.push("-sC");
    if (config.traceroute) args.push("--traceroute");
  }
  if (config.serviceVersion && config.versionIntensity !== undefined && !portless) {
    args.push("--version-intensity", String(config.versionIntensity));
  }
  if (config.scripts.trim()) args.push("--script", config.scripts.trim());
  if (config.scriptArgs.trim()) args.push("--script-args", config.scriptArgs.trim());
  if (config.skipPing) args.push("-Pn");
  if (config.noDns) args.push("-n");
  if (config.ipv6) args.push("-6");
  if (config.openOnly) args.push("--open");
  if (config.reason) args.push("--reason");
  if (config.fragment) args.push("-f");
  if (config.sourcePort) args.push("--source-port", String(config.sourcePort));
  if (config.interface) args.push("-e", config.interface);
  if (config.hostTimeout) args.push("--host-timeout", config.hostTimeout);
  if (config.maxRetries !== undefined) args.push("--max-retries", String(config.maxRetries));
  if (config.minRate) args.push("--min-rate", String(config.minRate));
  if (config.maxRate) args.push("--max-rate", String(config.maxRate));
  if (config.exclude?.trim()) args.push("--exclude", config.exclude.trim());
  if (config.extra.trim()) args.push(...splitArgs(config.extra));
  if (config.targetFile) args.push("-iL", config.targetFile);
  const targets = config.targets.split(/[\s,]+/).filter(Boolean);
  args.push(...targets);
  return args;
}

/** Quote for display. */
export function shellQuote(arg: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(arg) ? arg : `'${arg.replace(/'/g, `'\\''`)}'`;
}

export function commandLine(config: ScanConfig, program = "nmap"): string {
  return [program, ...toArgs(config)].map(shellQuote).join(" ");
}

/** Recognise a profile from its argument shape, for the history list. */
export function summarizeArgs(args: string): string {
  const parts = args.split(/\s+/);
  const flags = parts.filter((p) => p.startsWith("-") && !/^-o[XNGAS]$/.test(p) && p !== "--stats-every" && p !== "-v");
  return flags.join(" ");
}
