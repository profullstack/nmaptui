/**
 * Dashboard: the estate at a glance. Hosts up and down, open ports, the
 * services that matter, findings by severity, and what ran recently.
 */
import type { Container, KeyEvent } from "@profullstack/hqtui";
import { findings as computeFindings, overview, SEVERITY_ORDER, topPorts, type Severity } from "../../analysis.ts";
import { formatDuration, formatTime } from "../../model.ts";
import { summarizeArgs } from "../../profiles.ts";
import type { Ctx } from "../actions.ts";
import { ago, severityColor } from "../format.ts";
import type { UiState } from "../state.ts";

export function renderDashboard(state: UiState, ui: Container, ctx: Ctx): void {
  const { theme } = ctx;
  const result = state.result;
  const wide = ctx.width >= 120;

  if (!result) {
    ui.column({}, (col) => {
      col.panel({ title: " nmaptui ", size: 11 }, (p) => {
        p.heading("An admin console for nmap.");
        p.text("");
        p.text([{ text: "2", fg: theme.accent, bold: true }, { text: "  build a scan from a profile and watch it run" }]);
        p.text([{ text: "7", fg: theme.accent, bold: true }, { text: "  reopen or diff earlier scans, or import an nmap -oX file" }]);
        p.text([{ text: "?", fg: theme.accent, bold: true }, { text: "  every key, " }, { text: ":", fg: theme.accent, bold: true }, { text: "  command palette" }]);
        p.text("");
        if (!state.nmap) p.text([{ text: "nmap was not found on PATH. ", fg: theme.danger, bold: true }, { text: "Install it (apt install nmap, brew install nmap) and restart.", fg: theme.muted }]);
        else p.text([{ text: `nmap ${state.nmap.version}`, fg: theme.success }, { text: state.nmap.privileged ? "  running as root: every technique is available" : state.sudo ? "  raw-socket scans go through sudo" : "  not root: SYN, UDP and OS detection need sudo or --sudo", fg: theme.muted }]);
      });
      col.panel({ title: " Recent scans " }, (p) => renderRecent(state, p, ctx));
    });
    return;
  }

  const ov = overview(result);
  const list = state.findings.cache ?? (state.findings.cache = computeFindings(result));
  const bySeverity = new Map<Severity, number>();
  for (const f of list) bySeverity.set(f.severity, (bySeverity.get(f.severity) ?? 0) + 1);
  const ports = topPorts(result, 12);
  const maxPort = Math.max(1, ...ports.map((p) => p.count));

  const headerPanel = (c: Container): void => {
    c.panel({ title: " Scan ", size: 4 }, (p) => {
      p.text([{ text: result.args, fg: theme.accent }]);
      p.text([
        { text: result.start ? formatTime(result.start) : "", fg: theme.muted },
        { text: ov.elapsed ? `   took ${formatDuration(ov.elapsed)}` : "", fg: theme.muted },
        { text: result.partial ? "   PARTIAL: the scan did not finish" : "", fg: theme.warning, bold: true },
        { text: state.resultSource ? `   ${state.resultSource}` : "", fg: theme.muted },
      ]);
    });
  };

  const kpis = (c: Container): void => {
    c.row({ size: 7 }, (row) => {
      row.panel({ title: " Hosts " }, (p) => {
        p.row({}, (r) => {
          r.donut({ segments: [{ value: ov.hosts.up, color: theme.success, label: "up" }, { value: Math.max(0, ov.hosts.total - ov.hosts.up), color: theme.muted, label: "down" }], size: 14 });
          r.keyValues(
            [
              { label: "up", value: String(ov.hosts.up), color: theme.success },
              { label: "down", value: String(ov.hosts.down), color: theme.muted },
              { label: "with open ports", value: String(ov.withOpenPorts) },
              { label: "total", value: String(ov.hosts.total) },
            ],
            { spread: false },
          );
        });
      });
      row.panel({ title: " Ports " }, (p) => {
        const total = Math.max(1, ov.ports.open + ov.ports.closed + ov.ports.filtered + ov.ports.other);
        p.meters(
          [
            { label: "open", value: ov.ports.open, max: total, color: theme.success, text: String(ov.ports.open) },
            { label: "filtered", value: ov.ports.filtered, max: total, color: theme.warning, text: String(ov.ports.filtered) },
            { label: "closed", value: ov.ports.closed, max: total, color: theme.muted, text: String(ov.ports.closed) },
          ],
          { labelWidth: 9, valueWidth: 7 },
        );
        p.label(`${ov.services} distinct services`);
      });
      row.panel({ title: " Findings " }, (p) => {
        for (const sev of SEVERITY_ORDER) {
          const n = bySeverity.get(sev) ?? 0;
          p.meter({ label: sev, value: n, max: Math.max(1, list.length), color: severityColor(theme, sev), text: String(n), labelWidth: 9, valueWidth: 4 });
        }
      });
    });
  };

  const portsPanel = (c: Container): void => {
    c.panel({ title: " Most common open ports " }, (p) => {
      if (ports.length === 0) {
        p.label("no open ports");
        return;
      }
      for (const port of ports) {
        p.meter({ label: `${port.port}/${port.protocol} ${port.service}`.slice(0, 20), value: port.count, max: maxPort, text: `${port.count}`, labelWidth: 21, valueWidth: 4, color: theme.primary, style: "smooth" });
      }
    });
  };

  const osPanel = (c: Container): void => {
    c.panel({ title: " Operating systems " }, (p) => {
      if (ov.osFamilies.length === 0) {
        p.label("no OS information; enable OS detection (-O) or version probes (-sV)", { wrap: true });
        return;
      }
      const max = Math.max(1, ...ov.osFamilies.map((f) => f.count));
      for (const fam of ov.osFamilies.slice(0, 10)) {
        p.meter({ label: fam.name.slice(0, 16), value: fam.count, max, text: String(fam.count), labelWidth: 17, valueWidth: 4, color: theme.secondary, style: "smooth" });
      }
    });
  };

  const findingsPanel = (c: Container): void => {
    c.panel({ title: " Top findings ", subtitle: list.length ? `${list.length} total · 6 for all` : "" }, (p) => {
      if (list.length === 0) {
        p.label("nothing flagged", { wrap: true });
        return;
      }
      p.table({
        rows: list.slice(0, 20),
        columns: [
          { key: "severity", title: "SEV", width: 8, color: (r) => severityColor(theme, r.severity) },
          { key: "host", title: "HOST", width: 15, render: (r) => r.host.addr },
          { key: "port", title: "PORT", width: 9, render: (r) => (r.port ? `${r.port.port}/${r.port.protocol}` : "") },
          { key: "title", title: "FINDING", render: (r) => r.title },
        ],
        selected: -1,
        zebra: true,
      });
    });
  };

  const recentPanel = (c: Container): void => {
    c.panel({ title: " Recent scans " }, (p) => renderRecent(state, p, ctx));
  };

  ui.column({}, (col) => {
    headerPanel(col);
    kpis(col);
    if (wide) {
      col.row({}, (row) => {
        row.column({ size: "40%" }, (left) => {
          portsPanel(left);
          osPanel(left);
        });
        row.column({}, (right) => {
          findingsPanel(right);
          recentPanel(right);
        });
      });
    } else {
      col.row({}, (row) => {
        portsPanel(row);
        findingsPanel(row);
      });
    }
  });
}

function renderRecent(state: UiState, p: Container, ctx: Ctx): void {
  const records = state.history.records.slice(0, 8);
  if (records.length === 0) {
    p.label("no saved scans yet");
    return;
  }
  p.table({
    rows: records,
    columns: [
      { key: "ago", title: "WHEN", width: 8, render: (r) => ago(r.startedAt), color: ctx.theme.muted },
      { key: "targets", title: "TARGETS", width: 22, render: (r) => r.label ?? r.targets.join(" ") },
      { key: "args", title: "OPTIONS", render: (r) => summarizeArgs(r.args) },
      { key: "up", title: "UP", width: 3, align: "right", render: (r) => String(r.hostsUp) },
      { key: "open", title: "OPEN", width: 4, align: "right", render: (r) => String(r.openPorts) },
    ],
    selected: -1,
    zebra: true,
    onSelectRow: (row) => {
      const record = records[row];
      if (record) ctx.actions.openRecord(record.id);
    },
  });
}

export function handleDashboardKey(state: UiState, event: KeyEvent, ctx: Ctx): boolean {
  if (event.key === "enter" && state.result) {
    ctx.actions.goto("hosts");
    return true;
  }
  return false;
}
