/**
 * Diff: two scans side by side, reduced to what moved.
 */
import type { Container, KeyEvent } from "@profullstack/hqtui";
import type { HostDiff } from "../../diff.ts";
import type { Ctx } from "../actions.ts";
import { clamp, move } from "../format.ts";
import type { UiState } from "../state.ts";

interface DiffRow {
  kind: "host" | "port";
  host: HostDiff;
  text: string;
  mark: string;
  color: "add" | "remove" | "change" | "same";
}

export function diffRows(state: UiState): DiffRow[] {
  const d = state.diff.diff;
  if (!d) return [];
  const rows: DiffRow[] = [];
  for (const h of d.hosts) {
    if (h.kind === "same" && !state.diff.showUnchanged) continue;
    const label = h.name ? `${h.addr} (${h.name})` : h.addr;
    if (h.kind === "added") rows.push({ kind: "host", host: h, mark: "+", text: `${label} is new: ${h.after?.state}, ${h.after?.ports.filter((p) => p.state === "open").length ?? 0} open`, color: "add" });
    else if (h.kind === "removed") rows.push({ kind: "host", host: h, mark: "-", text: `${label} is gone (was ${h.before?.state})`, color: "remove" });
    else if (h.kind === "state") rows.push({ kind: "host", host: h, mark: "~", text: `${label} ${h.before?.state} -> ${h.after?.state}`, color: "change" });
    else if (h.kind === "same") rows.push({ kind: "host", host: h, mark: " ", text: `${label} unchanged`, color: "same" });
    else rows.push({ kind: "host", host: h, mark: "~", text: label, color: "change" });
    for (const c of h.ports) {
      rows.push({ kind: "port", host: h, mark: c.kind === "opened" ? "+" : c.kind === "closed" ? "-" : "~", text: `    ${c.detail}`, color: c.kind === "opened" ? "add" : c.kind === "closed" ? "remove" : "change" });
    }
  }
  return rows;
}

export function renderDiff(state: UiState, ui: Container, ctx: Ctx): void {
  const { theme } = ctx;
  const d = state.diff;
  const diff = d.diff;
  const rows = diffRows(state);
  d.selected = clamp(d.selected, 0, Math.max(0, rows.length - 1));
  const colors = { add: theme.success, remove: theme.danger, change: theme.warning, same: theme.muted };

  ui.column({}, (col) => {
    col.panel({ title: " Diff ", size: 6 }, (p) => {
      if (!diff) {
        p.label("Mark two scans in History (m, then d), or run: nmaptui diff before.xml after.xml", { wrap: true });
        return;
      }
      p.keyValues(
        [
          { label: "A", value: d.aLabel, color: theme.muted },
          { label: "B", value: d.bLabel, color: theme.foreground },
        ],
        { spread: false, labelWidth: 3 },
      );
      const s = diff.summary;
      p.text([
        { text: ` +${s.added} `, fg: theme.background, bg: theme.success, bold: true }, { text: " hosts new   " },
        { text: ` -${s.removed} `, fg: theme.background, bg: theme.danger, bold: true }, { text: " hosts gone   " },
        { text: ` ~${s.stateChanged} `, fg: theme.background, bg: theme.warning, bold: true }, { text: " state changed   " },
        { text: ` ${s.unchanged} `, fg: theme.background, bg: theme.muted, bold: true }, { text: " unchanged" },
      ]);
      p.text([
        { text: ` +${s.opened} `, fg: theme.background, bg: theme.success, bold: true }, { text: " ports opened   " },
        { text: ` -${s.closed} `, fg: theme.background, bg: theme.danger, bold: true }, { text: " ports closed   " },
        { text: ` ~${s.serviceChanged} `, fg: theme.background, bg: theme.warning, bold: true }, { text: " service changed   " },
        { text: d.showUnchanged ? "u hides unchanged" : "u shows unchanged", fg: theme.muted },
      ]);
    });
    col.panel({ title: " Changes ", subtitle: `${rows.length} lines` }, (p) => {
      if (!diff) return;
      if (rows.length === 0) {
        p.text([{ text: "No differences. ", fg: theme.success, bold: true }, { text: "The two scans agree on every host and port.", fg: theme.muted }]);
        return;
      }
      p.table({
        rows,
        header: false,
        columns: [
          { key: "mark", title: "", width: 1, color: (r) => colors[r.color] },
          { key: "text", title: "", color: (r) => (r.kind === "host" ? colors[r.color] : theme.foreground) },
        ],
        selected: d.selected,
        followSelection: true,
        scrollbar: true,
        onSelectRow: (row) => (d.selected = clamp(row + d.offset, 0, rows.length - 1)),
        onScroll: (delta) => (d.selected = move(d.selected, delta, rows.length)),
      });
    });
  });
}

export function handleDiffKey(state: UiState, event: KeyEvent, ctx: Ctx): boolean {
  const d = state.diff;
  const rows = diffRows(state);
  switch (event.key) {
    case "up":
    case "k":
      d.selected = move(d.selected, -1, rows.length);
      return true;
    case "down":
    case "j":
      d.selected = move(d.selected, 1, rows.length);
      return true;
    case "pageup":
      d.selected = move(d.selected, -10, rows.length);
      return true;
    case "pagedown":
      d.selected = move(d.selected, 10, rows.length);
      return true;
    case "g":
    case "home":
      d.selected = 0;
      return true;
    case "G":
    case "end":
      d.selected = Math.max(0, rows.length - 1);
      return true;
    case "u":
      d.showUnchanged = !d.showUnchanged;
      d.selected = 0;
      return true;
    case "enter": {
      const row = rows[d.selected];
      if (row && state.result) {
        state.hosts.filter = row.host.addr;
        state.hosts.editor.set(row.host.addr);
        state.hosts.selected = 0;
        ctx.actions.goto("hosts");
      } else ctx.actions.toast("open scan B from History to browse its hosts");
      return true;
    }
    default:
      return false;
  }
}
