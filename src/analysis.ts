/**
 * Views across a whole scan that an administrator actually wants: which
 * services are exposed where, which ports are most common, and a triage
 * list of things worth looking at before anything else.
 */
import { bestOs, openPorts, osFamily, primaryName, type Host, type Port, type ScanResult } from "./model.ts";

export interface ServiceGroup {
  /** "ssh", "http", or "tcp/8443" when nmap could not name it. */
  name: string;
  hosts: { host: Host; port: Port }[];
  /** Distinct product/version strings seen. */
  versions: Map<string, number>;
  ports: Set<string>;
}

export function groupServices(result: ScanResult): ServiceGroup[] {
  const groups = new Map<string, ServiceGroup>();
  for (const host of result.hosts) {
    for (const port of openPorts(host)) {
      const name = port.service?.name && port.service.name !== "unknown" ? port.service.name : `${port.protocol}/${port.port}`;
      let group = groups.get(name);
      if (!group) {
        group = { name, hosts: [], versions: new Map(), ports: new Set() };
        groups.set(name, group);
      }
      group.hosts.push({ host, port });
      group.ports.add(`${port.protocol}/${port.port}`);
      const version = [port.service?.product, port.service?.version].filter(Boolean).join(" ") || "(no banner)";
      group.versions.set(version, (group.versions.get(version) ?? 0) + 1);
    }
  }
  return [...groups.values()].sort((a, b) => b.hosts.length - a.hosts.length || a.name.localeCompare(b.name));
}

export interface PortCount {
  key: string;
  protocol: string;
  port: number;
  count: number;
  service: string;
}

export function topPorts(result: ScanResult, limit = 10): PortCount[] {
  const counts = new Map<string, PortCount>();
  for (const host of result.hosts) {
    for (const port of openPorts(host)) {
      const key = `${port.protocol}/${port.port}`;
      const entry = counts.get(key) ?? { key, protocol: port.protocol, port: port.port, count: 0, service: port.service?.name ?? "" };
      entry.count++;
      if (!entry.service && port.service?.name) entry.service = port.service.name;
      counts.set(key, entry);
    }
  }
  return [...counts.values()].sort((a, b) => b.count - a.count || a.port - b.port).slice(0, limit);
}

export interface Overview {
  hosts: { up: number; down: number; other: number; total: number };
  ports: { open: number; closed: number; filtered: number; other: number };
  services: number;
  osFamilies: { name: string; count: number }[];
  withOpenPorts: number;
  elapsed?: number;
}

export function overview(result: ScanResult): Overview {
  const hosts = { up: 0, down: 0, other: 0, total: result.hosts.length };
  const ports = { open: 0, closed: 0, filtered: 0, other: 0 };
  const families = new Map<string, number>();
  let withOpen = 0;
  for (const host of result.hosts) {
    if (host.state === "up") hosts.up++;
    else if (host.state === "down") hosts.down++;
    else hosts.other++;
    let open = 0;
    for (const p of host.ports) {
      if (p.state === "open") {
        ports.open++;
        open++;
      } else if (p.state === "closed") ports.closed++;
      else if (p.state.includes("filtered")) ports.filtered++;
      else ports.other++;
    }
    for (const extra of host.extraPorts) {
      if (extra.state === "closed") ports.closed += extra.count;
      else if (extra.state.includes("filtered")) ports.filtered += extra.count;
      else ports.other += extra.count;
    }
    if (open > 0) withOpen++;
    if (host.state === "up") {
      const family = osFamily(host) || "unknown";
      families.set(family, (families.get(family) ?? 0) + 1);
    }
  }
  if (result.runStats) {
    hosts.up = Math.max(hosts.up, result.runStats.up);
    hosts.down = Math.max(hosts.down, result.runStats.down);
    hosts.total = Math.max(hosts.total, result.runStats.total);
  }
  return {
    hosts,
    ports,
    services: groupServices(result).length,
    osFamilies: [...families.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count),
    withOpenPorts: withOpen,
    elapsed: result.runStats?.elapsed,
  };
}

// ------------------------------------------------------------------ findings

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  severity: Severity;
  host: Host;
  port?: Port;
  title: string;
  detail: string;
  /** Stable id for de-duplication and export: "<addr>:<proto>/<port>:<rule>". */
  id: string;
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

interface Rule {
  id: string;
  severity: Severity;
  title: string;
  /** Match on the open port; return a detail string to raise a finding. */
  match: (port: Port, host: Host) => string | null;
}

const PLAINTEXT: Record<string, string> = {
  telnet: "Telnet sends credentials in clear text",
  ftp: "FTP sends credentials in clear text",
  rlogin: "rlogin trusts the client and sends everything in clear",
  shell: "rsh trusts the client and sends everything in clear",
  exec: "rexec sends credentials in clear text",
  tftp: "TFTP has no authentication at all",
  pop3: "POP3 without TLS sends the mailbox password in clear",
  imap: "IMAP without TLS sends the mailbox password in clear",
  "x11": "X11 open to the network allows keylogging and screen capture",
  vnc: "VNC is exposed; check it needs a password and is not version 3.3",
};

const DATABASES: Record<string, string> = {
  mysql: "MySQL", postgresql: "PostgreSQL", redis: "Redis", mongodb: "MongoDB", "ms-sql-s": "Microsoft SQL Server",
  oracle: "Oracle", "oracle-tns": "Oracle TNS", memcached: "memcached", couchdb: "CouchDB", cassandra: "Cassandra",
  elasticsearch: "Elasticsearch", "wap-wsp": "Elasticsearch (9200)", influxdb: "InfluxDB", neo4j: "Neo4j",
};

const REMOTE_ADMIN: Record<string, string> = {
  "ms-wbt-server": "RDP", "microsoft-ds": "SMB", "netbios-ssn": "NetBIOS session", "msrpc": "MSRPC",
  winrm: "WinRM", "wsman": "WinRM (WS-Management)", "wsmans": "WinRM over TLS", ipmi: "IPMI", "asf-rmcp": "IPMI/BMC",
  snmp: "SNMP", "docker": "Docker API", "kubernetes": "Kubernetes API", "etcd-client": "etcd",
};

const RULES: Rule[] = [
  {
    id: "vuln-script",
    severity: "critical",
    title: "NSE reports a vulnerability",
    match: (port) => {
      const hit = port.scripts.find((s) => /\bVULNERABLE\b/.test(s.output) && !/NOT VULNERABLE/.test(s.output));
      return hit ? `${hit.id}: ${firstLine(hit.output)}` : null;
    },
  },
  {
    id: "plaintext",
    severity: "high",
    title: "Clear-text or unauthenticated protocol",
    match: (port) => {
      const name = port.service?.name ?? "";
      if (!PLAINTEXT[name]) return null;
      if ((name === "pop3" || name === "imap") && port.service?.tunnel === "ssl") return null;
      return PLAINTEXT[name] as string;
    },
  },
  {
    id: "database",
    severity: "high",
    title: "Database reachable from the network",
    match: (port) => {
      const name = port.service?.name ?? "";
      const label = DATABASES[name];
      return label ? `${label} answers on ${port.protocol}/${port.port}; databases should sit behind a firewall or a bastion` : null;
    },
  },
  {
    id: "remote-admin",
    severity: "medium",
    title: "Remote administration surface",
    match: (port) => {
      const name = port.service?.name ?? "";
      const label = REMOTE_ADMIN[name];
      return label ? `${label} is exposed on ${port.protocol}/${port.port}` : null;
    },
  },
  {
    id: "http-no-tls",
    severity: "low",
    title: "HTTP without TLS",
    match: (port) => {
      const s = port.service;
      if (!s || s.name !== "http" || s.tunnel === "ssl") return null;
      return `plain HTTP on ${port.protocol}/${port.port}${s.product ? ` (${s.product})` : ""}`;
    },
  },
  {
    id: "ssl-expired",
    severity: "medium",
    title: "TLS certificate problem",
    match: (port) => {
      const cert = port.scripts.find((s) => s.id === "ssl-cert");
      if (!cert) return null;
      const notAfter = cert.elems.find((e) => e.key === "validity.notAfter")?.value;
      if (notAfter && new Date(notAfter).getTime() < Date.now()) return `certificate expired ${notAfter}`;
      if (/self-signed|Issuer:.*commonName=localhost/i.test(cert.output)) return "self-signed certificate";
      return null;
    },
  },
  {
    id: "weak-tls",
    severity: "medium",
    title: "Weak TLS configuration",
    match: (port) => {
      const script = port.scripts.find((s) => s.id === "ssl-enum-ciphers");
      if (!script) return null;
      if (/SSLv2|SSLv3/.test(script.output)) return "SSLv2/SSLv3 offered";
      if (/TLSv1\.0/.test(script.output)) return "TLS 1.0 offered";
      const grade = /least strength: ([A-F])/.exec(script.output)?.[1];
      return grade && grade >= "C" ? `weakest cipher grade ${grade}` : null;
    },
  },
  {
    id: "old-ssh",
    severity: "medium",
    title: "Old OpenSSH",
    match: (port) => {
      const s = port.service;
      if (!s || s.name !== "ssh" || !/OpenSSH/i.test(s.product ?? "")) return null;
      const m = /^(\d+)\.(\d+)/.exec(s.version ?? "");
      if (!m) return null;
      const major = Number(m[1]);
      const minor = Number(m[2]);
      return major < 8 || (major === 8 && minor < 4) ? `OpenSSH ${s.version} predates 8.4; check vendor backports` : null;
    },
  },
  {
    id: "anon-ftp",
    severity: "high",
    title: "Anonymous FTP",
    match: (port) => {
      const hit = port.scripts.find((s) => s.id === "ftp-anon" && /Anonymous FTP login allowed/.test(s.output));
      return hit ? firstLine(hit.output) : null;
    },
  },
  {
    id: "proxy",
    severity: "medium",
    title: "Open proxy or relay",
    match: (port) => {
      const hit = port.scripts.find((s) => (s.id === "http-open-proxy" || s.id === "smtp-open-relay" || s.id === "socks-open-proxy") && /open|Potentially OPEN/i.test(s.output) && !/not open|Server is not/i.test(s.output));
      return hit ? `${hit.id}: ${firstLine(hit.output)}` : null;
    },
  },
  {
    id: "upnp",
    severity: "low",
    title: "UPnP / mDNS / discovery protocol exposed",
    match: (port) => {
      const name = port.service?.name ?? "";
      return name === "upnp" || name === "mdns" || name === "ssdp" || name === "llmnr" || name === "netbios-ns" ? `${name} on ${port.protocol}/${port.port}` : null;
    },
  },
];

function firstLine(text: string): string {
  return text.split("\n").map((l) => l.trim()).find((l) => l.length > 0) ?? "";
}

export function findings(result: ScanResult): Finding[] {
  const out: Finding[] = [];
  for (const host of result.hosts) {
    if (host.state !== "up") continue;
    for (const port of openPorts(host)) {
      for (const rule of RULES) {
        const detail = rule.match(port, host);
        if (detail) out.push({ severity: rule.severity, host, port, title: rule.title, detail, id: `${host.addr}:${port.protocol}/${port.port}:${rule.id}` });
      }
    }
    const smb = [...host.hostScripts, ...host.ports.flatMap((p) => p.scripts)].filter((s) => s.id === "smb-protocols" || s.id === "smb-security-mode" || s.id === "smb2-security-mode");
    const smb1 = smb.find((s) => /NT LM 0\.12|SMBv1/.test(s.output));
    if (smb1) out.push({ severity: "high", host, title: "SMBv1 enabled", detail: firstLine(smb1.output.split("\n").find((l) => /NT LM 0\.12|SMBv1/.test(l)) ?? smb1.output), id: `${host.addr}:host:smb1` });
    const unsigned = smb.find((s) => /message_signing: disabled/.test(s.output));
    if (unsigned) out.push({ severity: "medium", host, title: "SMB signing disabled", detail: "message signing is not required, which allows SMB relay attacks", id: `${host.addr}:host:smb-signing` });
    for (const script of host.hostScripts) {
      if (/\bVULNERABLE\b/.test(script.output) && !/NOT VULNERABLE/.test(script.output)) {
        out.push({ severity: "critical", host, title: "NSE reports a vulnerability", detail: `${script.id}: ${firstLine(script.output)}`, id: `${host.addr}:host:${script.id}` });
      }
    }
    const os = bestOs(host);
    if (os && /Windows (XP|2000|2003|7|Server 2008|Vista)|Windows Server 2012\b/.test(os.name) && os.accuracy >= 90) {
      out.push({ severity: "high", host, title: "End-of-life operating system", detail: `${os.name} (${os.accuracy}%)`, id: `${host.addr}:os:eol` });
    }
    const wideOpen = openPorts(host).length;
    if (wideOpen >= 25) {
      out.push({ severity: "info", host, title: "Many open ports", detail: `${wideOpen} open ports; check whether this host is a jump box, a NAT, or simply unmanaged`, id: `${host.addr}:host:wide` });
    }
  }
  return out.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || a.host.addr.localeCompare(b.host.addr));
}

export function hostLabel(host: Host): string {
  const name = primaryName(host);
  return name ? `${host.addr} ${name}` : host.addr;
}
