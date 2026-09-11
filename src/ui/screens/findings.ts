/**
 * Findings: the triage list. Heuristics over the scan, ordered by severity,
 * each pointing at a host and port with the reason it was raised.
 */
import type { Container, KeyEvent } from "@profullstack/hqtui";
import { findings as computeFindings, SEVERITY_ORDER, type Finding, type Severity } from "../../analysis.ts";
import { primaryName, serviceLabel } from "../../model.ts";
import type { Ctx } from "../actions.ts";
import { clamp, move, severityColor } from "../format.ts";
import type { UiState } from "../state.ts";

export function visibleFindings(state: UiState): Finding[] {
  if (!state.result) return [];
  if (!state.findings.cache) state.findings.cache = computeFindings(state.result);
  const limit = SEVERITY_ORDER.indexOf(state.findings.minSeverity);
  return state.findings.cache.filter((f) => SEVERITY_ORDER.indexOf(f.severity) <= limit);
}

export function renderFindings(state: UiState, ui: Container, ctx: Ctx): void {
  const { theme } = ctx;
  const f = state.findings;
  const list = visibleFindings(state);
  f.selected = clamp(f.selected, 0, Math.max(0, list.length - 1));
  const current = list[f.selected];
  const counts = new Map<Severity, number>();
  for (const item of f.cache ?? []) counts.set(item.severity, (counts.get(item.severity) ?? 0) + 1);

  ui.column({}, (col) => {
    col.panel({ title: " Findings ", size: "55%", subtitle: `${list.length} shown · min ${f.minSeverity} (f to change)` }, (p) => {
      if (!state.result) {
        p.label("No scan loaded.");
        return;
      }
      p.text(
        SEVERITY_ORDER.flatMap((sev) => [
          { text: ` ${sev.toUpperCase()} `, fg: theme.background, bg: severityColor(theme, sev), bold: true },
          { text: ` ${counts.get(sev) ?? 0}   ` },
        ]),
        { size: 1 },
      );
      if (list.length === 0) {
        p.label(f.cache && f.cache.length > 0 ? "nothing at this severity" : "nothing flagged. Version detection (-sV) and scripts (-sC, --script vuln) give the rules more to work with.", { wrap: true });
        return;
      }
      p.table({
        rows: list,
        columns: [
          { key: "severity", title: "SEV", width: 8, color: (r) => severityColor(theme, r.severity) },
          { key: "host", title: "HOST", width: 16, render: (r) => r.host.addr },
          { key: "port", title: "PORT", width: 9, render: (r) => (r.port ? `${r.port.port}/${r.port.protocol}` : "") },
          { key: "service", title: "SERVICE", width: 12, render: (r) => r.port?.service?.name ?? "" },
          { key: "title", title: "FINDING", render: (r) => r.title },
        ],
        selected: f.selected,
        followSelection: true,
        zebra: true,
        scrollbar: true,
        onSelectRow: (row) => (f.selected = clamp(row + f.offset, 0, list.length - 1)),
        onScroll: (d) => (f.selected = move(f.selected, d, list.length)),
      });
    });
    col.panel({ title: current ? ` ${current.title} ` : " Detail " }, (p) => {
      if (!current) {
        p.label("select a finding");
        return;
      }
      const host = current.host;
      const port = current.port;
      p.keyValues(
        [
          { label: "Severity", value: current.severity, color: severityColor(theme, current.severity) },
          { label: "Host", value: `${host.addr}${primaryName(host) ? ` (${primaryName(host)})` : ""}` },
          ...(port ? [{ label: "Port", value: `${port.port}/${port.protocol} ${port.service?.name ?? ""} ${serviceLabel(port)}`.trim() }] : []),
          { label: "Detail", value: current.detail },
        ],
        { spread: false, labelWidth: 10 },
      );
      const scripts = port?.scripts ?? host.hostScripts;
      if (scripts.length > 0) {
        p.divider({ label: "script output" });
        const text = scripts.map((s) => `${s.id}:\n${s.output.trim()}`).join("\n\n");
        p.text(text.slice(0, 4000), { wrap: true, fg: theme.foreground });
      }
    });
  });
}

export function handleFindingsKey(state: UiState, event: KeyEvent, ctx: Ctx): boolean {
  const f = state.findings;
  const list = visibleFindings(state);
  switch (event.key) {
    case "up":
    case "k":
      f.selected = move(f.selected, -1, list.length);
      return true;
    case "down":
    case "j":
      f.selected = move(f.selected, 1, list.length);
      return true;
    case "pageup":
      f.selected = move(f.selected, -10, list.length);
      return true;
    case "pagedown":
      f.selected = move(f.selected, 10, list.length);
      return true;
    case "g":
    case "home":
      f.selected = 0;
      return true;
    case "G":
    case "end":
      f.selected = Math.max(0, list.length - 1);
      return true;
    case "f": {
      const i = SEVERITY_ORDER.indexOf(f.minSeverity);
      f.minSeverity = SEVERITY_ORDER[(i + 1) % SEVERITY_ORDER.length] as Severity;
      f.selected = 0;
      ctx.actions.toast(`showing ${f.minSeverity} and above`);
      return true;
    }
    case "enter": {
      const current = list[f.selected];
      if (current) {
        state.hosts.filter = current.host.addr;
        state.hosts.editor.set(current.host.addr);
        state.hosts.selected = 0;
        ctx.actions.goto("hosts");
      }
      return true;
    }
    default:
      return false;
  }
}
