/**
 * History: every scan nmaptui has kept. Open one, mark two and diff them,
 * label, import, delete.
 */
import type { Container, KeyEvent } from "@profullstack/hqtui";
import { formatDuration } from "../../model.ts";
import { summarizeArgs } from "../../profiles.ts";
import type { Ctx } from "../actions.ts";
import { ago, clamp, dateStamp, move } from "../format.ts";
import type { UiState } from "../state.ts";

export function renderHistory(state: UiState, ui: Container, ctx: Ctx): void {
  const { theme } = ctx;
  const h = state.history;
  const records = h.records;
  h.selected = clamp(h.selected, 0, Math.max(0, records.length - 1));
  const current = records[h.selected];

  ui.column({}, (col) => {
    col.panel({ title: " History ", subtitle: `${records.length} scan${records.length === 1 ? "" : "s"}${h.marked.length ? ` · ${h.marked.length} marked for diff` : ""}` }, (p) => {
      if (records.length === 0) {
        p.label("No saved scans yet. Every scan you run here is kept; i imports an nmap -oX file.", { wrap: true });
        return;
      }
      p.table({
        rows: records,
        columns: [
          { key: "mark", title: "", width: 2, render: (r) => (h.marked.includes(r.id) ? String(h.marked.indexOf(r.id) + 1) : ""), color: theme.accent },
          { key: "when", title: "WHEN", width: 16, render: (r) => dateStamp(r.startedAt) },
          { key: "ago", title: "", width: 8, render: (r) => ago(r.startedAt), color: theme.muted },
          { key: "targets", title: "TARGETS", width: 26, render: (r) => r.label ?? r.targets.join(" ") },
          { key: "args", title: "OPTIONS", render: (r) => summarizeArgs(r.args) },
          { key: "up", title: "UP", width: 4, align: "right", render: (r) => String(r.hostsUp), color: (r) => (r.hostsUp > 0 ? theme.success : theme.muted) },
          { key: "open", title: "OPEN", width: 5, align: "right", render: (r) => String(r.openPorts) },
          { key: "elapsed", title: "TIME", width: 7, align: "right", render: (r) => (r.partial ? "partial" : formatDuration(r.elapsed)), color: (r) => (r.partial ? theme.warning : theme.muted) },
        ],
        selected: h.selected,
        followSelection: true,
        zebra: true,
        scrollbar: true,
        rowColor: (r) => (state.resultRecord?.id === r.id ? theme.accent : undefined),
        onSelectRow: (row) => (h.selected = clamp(row + h.offset, 0, records.length - 1)),
        onScroll: (d) => (h.selected = move(h.selected, d, records.length)),
      });
    });
    col.panel({ title: current ? ` ${current.id} ` : " Scan ", size: 6 }, (p) => {
      if (!current) {
        p.label("nothing selected");
        return;
      }
      p.keyValues(
        [
          { label: "Command", value: current.args },
          { label: "Hosts", value: `${current.hostsUp} up of ${current.hostsTotal}, ${current.openPorts} open ports` },
          { label: "File", value: current.file },
        ],
        { spread: false, labelWidth: 9 },
      );
      p.text([
        { text: " enter ", fg: theme.background, bg: theme.accent, bold: true }, { text: " open  " },
        { text: " m ", fg: theme.background, bg: theme.accent, bold: true }, { text: " mark  " },
        { text: " d ", fg: theme.background, bg: theme.accent, bold: true }, { text: " diff marked  " },
        { text: " L ", fg: theme.background, bg: theme.accent, bold: true }, { text: " label  " },
        { text: " i ", fg: theme.background, bg: theme.accent, bold: true }, { text: " import xml  " },
        { text: " D ", fg: theme.background, bg: theme.danger, bold: true }, { text: " delete" },
      ]);
    });
  });
}

export function handleHistoryKey(state: UiState, event: KeyEvent, ctx: Ctx): boolean {
  const h = state.history;
  const records = h.records;
  const current = records[h.selected];
  switch (event.key) {
    case "up":
    case "k":
      h.selected = move(h.selected, -1, records.length);
      return true;
    case "down":
    case "j":
      h.selected = move(h.selected, 1, records.length);
      return true;
    case "pageup":
      h.selected = move(h.selected, -10, records.length);
      return true;
    case "pagedown":
      h.selected = move(h.selected, 10, records.length);
      return true;
    case "g":
    case "home":
      h.selected = 0;
      return true;
    case "G":
    case "end":
      h.selected = Math.max(0, records.length - 1);
      return true;
    case "enter":
      if (current) ctx.actions.openRecord(current.id);
      return true;
    case "m":
      if (!current) return true;
      if (h.marked.includes(current.id)) h.marked = h.marked.filter((id) => id !== current.id);
      else {
        h.marked.push(current.id);
        if (h.marked.length > 2) h.marked.shift();
      }
      ctx.actions.toast(h.marked.length === 2 ? "two scans marked: d to diff" : `${h.marked.length} marked`);
      return true;
    case "d":
      ctx.actions.diffMarked();
      return true;
    case "D":
      if (current) ctx.actions.deleteRecord(current.id);
      return true;
    case "L":
      if (current) ctx.actions.relabelRecord(current.id);
      return true;
    case "i":
      ctx.actions.importFile();
      return true;
    case "r":
      ctx.actions.reloadHistory();
      return true;
    default:
      return false;
  }
}
