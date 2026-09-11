/**
 * Exports: the same scan as text, JSON, CSV, Markdown or HTML, plus the raw
 * XML nmap wrote. The text form is what `nmaptui print` shows and what the
 * export dialog writes.
 */
import { findings, groupServices, overview } from "./analysis.ts";
import { bestOs, formatDuration, formatTime, openPorts, primaryName, serviceLabel, type Host, type ScanResult } from "./model.ts";

export const EXPORT_FORMATS = ["text", "json", "csv", "markdown", "html", "xml"] as const;
export type ExportFormat = (typeof EXPORT_FORMATS)[number];

export const EXPORT_EXTENSIONS: Record<ExportFormat, string> = { text: "txt", json: "json", csv: "csv", markdown: "md", html: "html", xml: "xml" };

function pad(text: string, width: number): string {
  return text.length >= width ? text : text + " ".repeat(width - text.length);
}

export function hostReport(host: Host, options: { openOnly?: boolean; scripts?: boolean } = {}): string[] {
  const lines: string[] = [];
  const name = primaryName(host);
  lines.push(`Host ${host.addr}${name ? ` (${name})` : ""} is ${host.state}${host.stateReason ? ` (${host.stateReason})` : ""}`);
  if (host.mac) lines.push(`  MAC ${host.mac}${host.vendor ? ` (${host.vendor})` : ""}`);
  const os = bestOs(host);
  if (os) lines.push(`  OS ${os.name} (${os.accuracy}%)`);
  if (host.uptime) lines.push(`  Uptime ${formatDuration(host.uptime.seconds)}${host.uptime.lastBoot ? ` since ${host.uptime.lastBoot}` : ""}`);
  if (host.distance !== undefined) lines.push(`  Distance ${host.distance} hop${host.distance === 1 ? "" : "s"}`);
  const ports = options.openOnly === false ? host.ports : host.ports.filter((p) => p.state === "open" || p.state === "open|filtered");
  if (ports.length > 0) {
    lines.push(`  ${pad("PORT", 11)}${pad("STATE", 15)}${pad("SERVICE", 16)}VERSION`);
    for (const p of ports) {
      lines.push(`  ${pad(`${p.port}/${p.protocol}`, 11)}${pad(p.state, 15)}${pad(p.service?.name ?? "", 16)}${serviceLabel(p)}`);
      if (options.scripts !== false) {
        for (const s of p.scripts) {
          const body = s.output.trim().split("\n");
          lines.push(`    | ${s.id}: ${body[0]?.trim() ?? ""}`);
          for (const extra of body.slice(1)) lines.push(`    |   ${extra.trim()}`);
        }
      }
    }
  }
  for (const extra of host.extraPorts) lines.push(`  Not shown: ${extra.count} ${extra.state} ports`);
  if (options.scripts !== false && host.hostScripts.length > 0) {
    lines.push("  Host scripts:");
    for (const s of host.hostScripts) {
      const body = s.output.trim().split("\n");
      lines.push(`    | ${s.id}: ${body[0]?.trim() ?? ""}`);
      for (const extra of body.slice(1)) lines.push(`    |   ${extra.trim()}`);
    }
  }
  if (host.trace.hops.length > 0) {
    lines.push(`  Traceroute${host.trace.port ? ` (${host.trace.protocol}/${host.trace.port})` : ""}:`);
    for (const hop of host.trace.hops) lines.push(`    ${String(hop.ttl).padStart(3)}  ${hop.rtt !== undefined ? `${hop.rtt.toFixed(2)} ms` : "..."}  ${hop.ip ?? ""}${hop.host ? ` (${hop.host})` : ""}`);
  }
  return lines;
}

export function textReport(result: ScanResult, options: { openOnly?: boolean; scripts?: boolean; findings?: boolean } = {}): string {
  const lines: string[] = [];
  lines.push(`# nmaptui report`);
  lines.push(`Command: ${result.args}`);
  if (result.start) lines.push(`Started: ${formatTime(result.start)}`);
  if (result.runStats?.summary) lines.push(`Result:  ${result.runStats.summary}`);
  if (result.partial) lines.push(`Note:    scan did not finish; results are partial`);
  lines.push("");
  const up = result.hosts.filter((h) => h.state === "up");
  const down = result.hosts.filter((h) => h.state !== "up");
  for (const host of up) {
    lines.push(...hostReport(host, options));
    lines.push("");
  }
  if (down.length > 0) lines.push(`${down.length} host${down.length === 1 ? "" : "s"} not up: ${down.map((h) => h.addr).join(", ")}`, "");
  if (options.findings !== false) {
    const list = findings(result);
    if (list.length > 0) {
      lines.push("Findings:");
      for (const f of list) lines.push(`  [${f.severity.toUpperCase().padEnd(8)}] ${f.host.addr}${f.port ? ` ${f.port.protocol}/${f.port.port}` : ""}: ${f.title}. ${f.detail}`);
      lines.push("");
    }
  }
  const ov = overview(result);
  lines.push(`Summary: ${ov.hosts.up} up, ${ov.hosts.down} down; ${ov.ports.open} open ports across ${ov.withOpenPorts} hosts; ${ov.services} distinct services`);
  return lines.join("\n");
}

export function jsonReport(result: ScanResult): string {
  const out = {
    scanner: result.scanner,
    version: result.version,
    args: result.args,
    start: result.start,
    partial: result.partial,
    runStats: result.runStats,
    hosts: result.hosts.map((h) => ({
      addr: h.addr,
      addresses: h.addresses,
      hostnames: h.hostnames,
      state: h.state,
      stateReason: h.stateReason,
      os: h.os,
      uptime: h.uptime,
      distance: h.distance,
      ports: h.ports,
      extraPorts: h.extraPorts,
      hostScripts: h.hostScripts,
      trace: h.trace,
    })),
    findings: findings(result).map((f) => ({ id: f.id, severity: f.severity, host: f.host.addr, port: f.port ? `${f.port.protocol}/${f.port.port}` : undefined, title: f.title, detail: f.detail })),
  };
  return JSON.stringify(out, null, 2);
}

function csvCell(value: unknown): string {
  const s = value === undefined || value === null ? "" : String(value);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function csvReport(result: ScanResult, options: { openOnly?: boolean } = {}): string {
  const rows: unknown[][] = [["host", "hostname", "host_state", "protocol", "port", "port_state", "reason", "service", "product", "version", "extrainfo", "tunnel", "cpe", "os", "os_accuracy"]];
  for (const h of result.hosts) {
    const os = bestOs(h);
    const ports = options.openOnly === false ? h.ports : h.ports.filter((p) => p.state === "open");
    if (ports.length === 0) {
      rows.push([h.addr, primaryName(h), h.state, "", "", "", h.stateReason, "", "", "", "", "", "", os?.name, os?.accuracy]);
      continue;
    }
    for (const p of ports) {
      rows.push([h.addr, primaryName(h), h.state, p.protocol, p.port, p.state, p.reason, p.service?.name, p.service?.product, p.service?.version, p.service?.extrainfo, p.service?.tunnel, p.service?.cpe.join(" "), os?.name, os?.accuracy]);
    }
  }
  return rows.map((r) => r.map(csvCell).join(",")).join("\n") + "\n";
}

export function markdownReport(result: ScanResult): string {
  const lines: string[] = [];
  lines.push(`# Scan report`, "", `\`${result.args}\``, "");
  if (result.start) lines.push(`Started ${formatTime(result.start)}${result.runStats?.elapsed ? `, took ${formatDuration(result.runStats.elapsed)}` : ""}.`, "");
  const ov = overview(result);
  lines.push(`**${ov.hosts.up} up**, ${ov.hosts.down} down. ${ov.ports.open} open ports on ${ov.withOpenPorts} hosts, ${ov.services} distinct services.`, "");
  const list = findings(result);
  if (list.length > 0) {
    lines.push("## Findings", "", "| Severity | Host | Port | Finding | Detail |", "|---|---|---|---|---|");
    for (const f of list) lines.push(`| ${f.severity} | ${f.host.addr} | ${f.port ? `${f.port.protocol}/${f.port.port}` : ""} | ${f.title} | ${f.detail.replace(/\|/g, "\\|")} |`);
    lines.push("");
  }
  lines.push("## Services", "", "| Service | Hosts | Ports | Versions |", "|---|---|---|---|");
  for (const g of groupServices(result)) {
    const versions = [...g.versions.entries()].map(([v, n]) => (n > 1 ? `${v} x${n}` : v)).join(", ");
    lines.push(`| ${g.name} | ${g.hosts.length} | ${[...g.ports].join(", ")} | ${versions.replace(/\|/g, "\\|")} |`);
  }
  lines.push("", "## Hosts", "");
  for (const h of result.hosts.filter((x) => x.state === "up")) {
    const name = primaryName(h);
    const os = bestOs(h);
    lines.push(`### ${h.addr}${name ? ` (${name})` : ""}`, "");
    if (os) lines.push(`OS: ${os.name} (${os.accuracy}%)`, "");
    const ports = openPorts(h);
    if (ports.length > 0) {
      lines.push("| Port | Service | Version |", "|---|---|---|");
      for (const p of ports) lines.push(`| ${p.port}/${p.protocol} | ${p.service?.name ?? ""} | ${serviceLabel(p).replace(/\|/g, "\\|")} |`);
    } else lines.push("No open ports.");
    lines.push("");
  }
  return lines.join("\n");
}

function esc(text: string): string {
  return text.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c] as string);
}

export function htmlReport(result: ScanResult): string {
  const ov = overview(result);
  const rows = result.hosts
    .filter((h) => h.state === "up")
    .map((h) => {
      const ports = openPorts(h)
        .map((p) => `<tr><td>${p.port}/${p.protocol}</td><td>${esc(p.service?.name ?? "")}</td><td>${esc(serviceLabel(p))}</td></tr>`)
        .join("");
      const os = bestOs(h);
      return `<section><h2>${esc(h.addr)}${primaryName(h) ? ` <small>${esc(primaryName(h))}</small>` : ""}</h2>${os ? `<p>OS: ${esc(os.name)} (${os.accuracy}%)</p>` : ""}${ports ? `<table><thead><tr><th>Port</th><th>Service</th><th>Version</th></tr></thead><tbody>${ports}</tbody></table>` : "<p>No open ports.</p>"}</section>`;
    })
    .join("\n");
  const list = findings(result)
    .map((f) => `<tr class="${f.severity}"><td>${f.severity}</td><td>${esc(f.host.addr)}</td><td>${f.port ? `${f.port.protocol}/${f.port.port}` : ""}</td><td>${esc(f.title)}</td><td>${esc(f.detail)}</td></tr>`)
    .join("");
  return `<!doctype html><meta charset="utf-8"><title>nmaptui report</title>
<style>body{font:14px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;color:#1f2933}code{background:#f1f5f9;padding:.1em .3em}table{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem}th,td{text-align:left;padding:.3rem .5rem;border-bottom:1px solid #e2e8f0}tr.critical td:first-child{color:#b91c1c;font-weight:600}tr.high td:first-child{color:#c2410c}tr.medium td:first-child{color:#a16207}small{color:#64748b;font-weight:400}</style>
<h1>Scan report</h1><p><code>${esc(result.args)}</code></p>
<p>${result.start ? `Started ${esc(formatTime(result.start))}. ` : ""}${ov.hosts.up} up, ${ov.hosts.down} down. ${ov.ports.open} open ports on ${ov.withOpenPorts} hosts, ${ov.services} distinct services.${result.partial ? " <strong>Partial: the scan did not finish.</strong>" : ""}</p>
${list ? `<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Host</th><th>Port</th><th>Finding</th><th>Detail</th></tr></thead><tbody>${list}</tbody></table>` : ""}
${rows}
`;
}

export function exportScan(result: ScanResult, xml: string, format: ExportFormat): string {
  switch (format) {
    case "text":
      return textReport(result);
    case "json":
      return jsonReport(result);
    case "csv":
      return csvReport(result);
    case "markdown":
      return markdownReport(result);
    case "html":
      return htmlReport(result);
    case "xml":
      return xml;
  }
}
