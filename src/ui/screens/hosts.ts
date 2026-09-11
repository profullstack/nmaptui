/**
 * Hosts: the table on the left, everything nmap knows about the selected
 * host on the right. Filter, sort, open-only, and a scrollable detail pane.
 */
import type { Container, KeyEvent, Span } from "@profullstack/hqtui";

export type DetailLine = string | Span[];
import { compareAddr } from "../../diff.ts";
import { bestOs, formatDuration, openPorts, osFamily, primaryName, serviceLabel, type Host, type Port } from "../../model.ts";
import type { Ctx } from "../actions.ts";
import { clamp, move, stateColor } from "../format.ts";
import type { HostSort, UiState } from "../state.ts";

const SORTS: HostSort[] = ["addr", "open", "name", "os"];

export function visibleHosts(state: UiState): Host[] {
  const result = state.result;
  if (!result) return [];
  const h = state.hosts;
  const needle = h.filter.trim().toLowerCase();
  let hosts = result.hosts.filter((host) => {
    if (h.upOnly && host.state !== "up") return false;
    if (h.openOnly && openPorts(host).length === 0) return false;
    if (!needle) return true;
    const hay = [
      host.addr,
      ...host.hostnames.map((n) => n.name),
      host.mac ?? "",
      host.vendor ?? "",
      bestOs(host)?.name ?? "",
      ...host.ports.filter((p) => p.state === "open").map((p) => `${p.port} ${p.service?.name ?? ""} ${serviceLabel(p)}`),
    ]
      .join(" ")
      .toLowerCase();
    return needle.split(/\s+/).every((word) => hay.includes(word));
  });
  hosts = hosts.slice().sort((a, b) => {
    switch (h.sort) {
      case "open":
        return openPorts(b).length - openPorts(a).length || compareAddr(a.addr, b.addr);
      case "name":
        return primaryName(a).localeCompare(primaryName(b)) || compareAddr(a.addr, b.addr);
      case "os":
        return osFamily(a).localeCompare(osFamily(b)) || compareAddr(a.addr, b.addr);
      default:
        return compareAddr(a.addr, b.addr);
    }
  });
  return hosts;
}

export function selectedHost(state: UiState): Host | undefined {
  const hosts = visibleHosts(state);
  return hosts[clamp(state.hosts.selected, 0, Math.max(0, hosts.length - 1))];
}

/** The lines of the detail pane, so the same text can be scrolled and tested. */
export function hostDetailLines(host: Host, theme: Ctx["theme"], width: number): DetailLine[] {
  const lines: DetailLine[] = [];
  const kv = (label: string, value: string): void => {
    if (value) lines.push([{ text: label.padEnd(11), fg: theme.muted }, { text: value }]);
  };
  kv("State", `${host.state}${host.stateReason ? ` (${host.stateReason})` : ""}`);
  kv("Names", host.hostnames.map((n) => (n.type ? `${n.name} [${n.type}]` : n.name)).join(", "));
  kv("Addresses", host.addresses.filter((a) => a.type !== "mac").map((a) => a.addr).join(", "));
  kv("MAC", host.mac ? `${host.mac}${host.vendor ? ` (${host.vendor})` : ""}` : "");
  const os = bestOs(host);
  kv("OS", os ? `${os.name} (${os.accuracy}%)` : "");
  if (host.os.length > 1) kv("", host.os.slice(1, 4).map((o) => `${o.name} ${o.accuracy}%`).join(" · "));
  kv("Uptime", host.uptime ? `${formatDuration(host.uptime.seconds)}${host.uptime.lastBoot ? ` since ${host.uptime.lastBoot}` : ""}` : "");
  kv("Distance", host.distance !== undefined ? `${host.distance} hop${host.distance === 1 ? "" : "s"}` : "");
  kv("RTT", host.srtt !== undefined ? `${(host.srtt / 1000).toFixed(1)} ms` : "");
  kv("Scanned", host.startTime && host.endTime ? formatDuration(host.endTime - host.startTime) : "");
  const shown = host.ports.filter((p) => p.state !== "closed");
  const hidden = host.ports.length - shown.length;
  lines.push("");
  lines.push([{ text: `Ports  `, fg: theme.title, bold: true }, { text: `${openPorts(host).length} open`, fg: theme.success }, { text: hidden > 0 ? `, ${hidden} closed hidden` : "", fg: theme.muted }, { text: host.extraPorts.map((e) => `, ${e.count} ${e.state} not shown`).join(""), fg: theme.muted }]);
  if (shown.length > 0) {
    lines.push([{ text: `${"PORT".padEnd(11)}${"STATE".padEnd(15)}${"SERVICE".padEnd(14)}VERSION`, fg: theme.muted }]);
  }
  for (const p of shown) {
    lines.push([
      { text: `${p.port}/${p.protocol}`.padEnd(11), fg: theme.foreground, bold: true },
      { text: p.state.padEnd(15), fg: stateColor(theme, p.state) },
      { text: (p.service?.name ?? "").padEnd(14), fg: theme.accent },
      { text: serviceLabel(p) + (p.service?.tunnel ? ` [${p.service.tunnel}]` : "") },
    ]);
    for (const s of p.scripts) pushScript(lines, s.id, s.output, theme, width, "    ");
  }
  if (host.hostScripts.length > 0) {
    lines.push("");
    lines.push([{ text: "Host scripts", fg: theme.title, bold: true }]);
    for (const s of host.hostScripts) pushScript(lines, s.id, s.output, theme, width, "  ");
  }
  if (host.trace.hops.length > 0) {
    lines.push("");
    lines.push([{ text: `Traceroute${host.trace.port ? ` (${host.trace.protocol}/${host.trace.port})` : ""}`, fg: theme.title, bold: true }]);
    for (const hop of host.trace.hops) {
      lines.push([
        { text: String(hop.ttl).padStart(4) + "  ", fg: theme.muted },
        { text: (hop.rtt !== undefined ? `${hop.rtt.toFixed(1)} ms` : "*").padEnd(11), fg: theme.foreground },
        { text: hop.ip ?? "", fg: theme.accent },
        { text: hop.host ? ` ${hop.host}` : "", fg: theme.muted },
      ]);
    }
  }
  const cpes = [...new Set(host.ports.flatMap((p) => p.service?.cpe ?? []).concat(host.os.flatMap((o) => o.classes.flatMap((c) => c.cpe))))];
  if (cpes.length > 0) {
    lines.push("");
    lines.push([{ text: "CPE", fg: theme.title, bold: true }]);
    for (const cpe of cpes.slice(0, 20)) lines.push([{ text: `  ${cpe}`, fg: theme.muted }]);
  }
  return lines;
}

function pushScript(lines: DetailLine[], id: string, output: string, theme: Ctx["theme"], width: number, indent: string): void {
  const body = output.replace(/^\n+|\n+$/g, "").split("\n");
  const first = body.shift()?.trim() ?? "";
  lines.push([{ text: `${indent}| `, fg: theme.border }, { text: id, fg: theme.secondary, bold: true }, { text: first ? `: ${first}` : "" }]);
  const max = Math.max(20, width - indent.length - 4);
  for (const raw of body) {
    const line = raw.replace(/\t/g, "  ");
    // Wrap long script lines by hand so the detail pane stays one column wide.
    for (let i = 0; i < Math.max(1, line.length); i += max) {
      lines.push([{ text: `${indent}| `, fg: theme.border }, { text: line.slice(i, i + max), fg: theme.foreground }]);
    }
  }
}

export function renderHosts(state: UiState, ui: Container, ctx: Ctx): void {
  const { theme } = ctx;
  const h = state.hosts;
  const hosts = visibleHosts(state);
  h.selected = clamp(h.selected, 0, Math.max(0, hosts.length - 1));
  const host = hosts[h.selected];
  const wide = ctx.width >= 120;
  const total = state.result?.hosts.length ?? 0;

  const listPanel = (c: Container, size?: string | number): void => {
    const filterText = h.filtering ? `/${h.editor.value}▏` : h.filter ? `/${h.filter}` : "";
    c.panel({ title: " Hosts ", size, focused: h.pane === "list", subtitle: `${hosts.length}/${total}${h.openOnly ? " open" : ""}${h.upOnly ? "" : " +down"} · sort ${h.sort}${filterText ? ` · ${filterText}` : ""}` }, (p) => {
      if (!state.result) {
        p.label("No scan loaded. Start one from New scan (2) or open one from History (7).", { wrap: true });
        return;
      }
      if (hosts.length === 0) {
        p.label(h.filter ? `nothing matches "${h.filter}"` : "no hosts to show", { wrap: true });
        return;
      }
      p.table({
        rows: hosts,
        columns: [
          { key: "addr", title: "ADDRESS", width: 16 },
          { key: "name", title: "NAME", render: (x) => primaryName(x) },
          { key: "state", title: "ST", width: 4, render: (x) => (x.state === "up" ? "up" : x.state === "down" ? "down" : "?"), color: (x) => stateColor(theme, x.state) },
          { key: "open", title: "OPEN", width: 4, align: "right", render: (x) => String(openPorts(x).length), color: (x) => (openPorts(x).length > 0 ? theme.success : theme.muted) },
          { key: "os", title: "OS", width: wide ? 12 : 8, render: (x) => osFamily(x) },
        ],
        selected: h.selected,
        followSelection: true,
        zebra: true,
        scrollbar: true,
        onSelectRow: (row) => {
          h.pane = "list";
          h.selected = clamp(row + resolveVisibleOffset(state, hosts.length), 0, hosts.length - 1);
          h.detailScroll = 0;
        },
        onScroll: (d) => {
          h.selected = move(h.selected, d, hosts.length);
          h.detailScroll = 0;
        },
        onFocus: () => (h.pane = "list"),
      });
    });
  };

  const detailPanel = (c: Container): void => {
    const title = host ? ` ${host.addr}${primaryName(host) ? `  ${primaryName(host)}` : ""} ` : " Details ";
    c.panel({ title, focused: h.pane === "detail", subtitle: host ? `${openPorts(host).length} open` : "" }, (p) => {
      if (!host) {
        p.label("select a host");
        return;
      }
      p.draw((s) => {
        const lines = hostDetailLines(host, theme, s.width);
        const max = Math.max(0, lines.length - s.height);
        h.detailScroll = clamp(h.detailScroll, 0, max);
        for (let y = 0; y < s.height; y++) {
          const line = lines[h.detailScroll + y];
          if (line === undefined) break;
          if (typeof line === "string") s.text(0, y, line.slice(0, s.width));
          else {
            let x = 0;
            for (const span of line) {
              if (x >= s.width) break;
              x += s.text(x, y, span.text.slice(0, s.width - x), { fg: span.fg, bg: span.bg, attrs: span.bold ? 1 : 0 });
            }
          }
        }
        if (max > 0) {
          const track = s.height;
          const knob = Math.max(1, Math.round((track * track) / lines.length));
          const pos = Math.round((h.detailScroll / max) * (track - knob));
          for (let y = 0; y < track; y++) s.text(s.width - 1, y, y >= pos && y < pos + knob ? "┃" : "│", { fg: y >= pos && y < pos + knob ? theme.accent : theme.border });
        }
      });
    });
  };

  if (wide) {
    ui.row({}, (row) => {
      listPanel(row, "44%");
      detailPanel(row);
    });
  } else {
    ui.column({}, (col) => {
      listPanel(col, "45%");
      detailPanel(col);
    });
  }
}

/** The list keeps its own offset through followSelection; approximate it for clicks. */
function resolveVisibleOffset(state: UiState, total: number): number {
  return Math.max(0, Math.min(state.hosts.offset, Math.max(0, total - 1)));
}

export function handleHostsKey(state: UiState, event: KeyEvent, ctx: Ctx): boolean {
  const h = state.hosts;
  const hosts = visibleHosts(state);
  const { key, name } = event;

  if (h.filtering) {
    if (key === "escape") {
      h.filtering = false;
      h.filter = "";
      h.editor.set("");
    } else if (name === "enter") {
      h.filtering = false;
    } else if (key === "up") h.selected = move(h.selected, -1, hosts.length);
    else if (key === "down") h.selected = move(h.selected, 1, hosts.length);
    else {
      h.editor.handle(event);
      h.filter = h.editor.value;
      h.selected = 0;
    }
    return true;
  }

  const step = (d: number): void => {
    if (h.pane === "detail") h.detailScroll = Math.max(0, h.detailScroll + d);
    else {
      h.selected = move(h.selected, d, hosts.length);
      h.detailScroll = 0;
    }
  };

  switch (key) {
    case "up":
    case "k":
      step(-1);
      return true;
    case "down":
    case "j":
      step(1);
      return true;
    case "pageup":
    case "b":
      step(-10);
      return true;
    case "pagedown":
    case "space":
    case "f":
      step(10);
      return true;
    case "home":
    case "g":
      if (h.pane === "detail") h.detailScroll = 0;
      else h.selected = 0;
      return true;
    case "end":
    case "G":
      if (h.pane === "detail") h.detailScroll = Number.MAX_SAFE_INTEGER;
      else h.selected = Math.max(0, hosts.length - 1);
      return true;
    case "tab":
    case "enter":
    case "right":
    case "l":
      h.pane = h.pane === "list" ? "detail" : "list";
      return true;
    case "left":
    case "h":
    case "escape":
      if (h.pane === "detail") h.pane = "list";
      return true;
    case "/":
      h.filtering = true;
      h.editor.set(h.filter);
      return true;
    case "o":
      h.openOnly = !h.openOnly;
      h.selected = 0;
      ctx.actions.toast(h.openOnly ? "only hosts with open ports" : "all hosts");
      return true;
    case "u":
      h.upOnly = !h.upOnly;
      h.selected = 0;
      ctx.actions.toast(h.upOnly ? "hiding hosts that are down" : "showing hosts that are down");
      return true;
    case "S":
      h.sort = SORTS[(SORTS.indexOf(h.sort) + 1) % SORTS.length] as HostSort;
      ctx.actions.toast(`sorted by ${h.sort}`);
      return true;
    case "y": {
      const host = hosts[h.selected];
      if (host) ctx.actions.toast(`${host.addr}: ${openPorts(host).map((p) => `${p.port}/${p.protocol}`).join(",") || "no open ports"}`);
      return true;
    }
    default:
      return false;
  }
}

export type { Port };
