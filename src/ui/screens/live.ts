/**
 * The running scan: what nmap is doing right now, which hosts it has
 * finished, and everything it said on stderr.
 */
import type { Container, KeyEvent } from "@profullstack/hqtui";
import { formatDuration, openPorts, primaryName } from "../../model.ts";
import type { Ctx } from "../actions.ts";
import { stateColor } from "../format.ts";
import type { UiState } from "../state.ts";

export function renderLive(state: UiState, ui: Container, ctx: Ctx): void {
  const { theme } = ctx;
  const running = state.running;
  const result = running?.result ?? state.result;
  const elapsed = running ? (Date.now() - state.runStartedAt) / 1000 : result?.runStats?.elapsed;
  const finished = !running && state.tasks.length > 0;

  ui.column({}, (col) => {
    col.panel({ title: running ? " Scanning " : finished ? " Last scan " : " Live ", size: 3 }, (p) => {
      if (!running && !finished) {
        p.text([{ text: "No scan running. " }, { text: "2", fg: theme.accent, bold: true }, { text: " builds one; " }, { text: "s", fg: theme.accent, bold: true }, { text: " starts it." }]);
        return;
      }
      const cmd = running?.command.join(" ") ?? result?.args ?? "";
      p.text([
        { text: running ? "● " : "■ ", fg: running ? theme.success : theme.muted },
        { text: cmd, fg: theme.accent },
        { text: `   ${formatDuration(elapsed)}`, fg: theme.muted },
        { text: running ? "   x abort" : `   ${result?.runStats?.summary ?? (result?.partial ? "aborted" : "")}`, fg: running ? theme.warning : theme.muted },
      ]);
    });
    if (!running && !finished) {
      col.panel({ title: " Log " }, (p) => renderLog(state, p));
      return;
    }
    col.row({}, (row) => {
      row.column({ size: "45%" }, (left) => {
        left.panel({ title: " Tasks ", subtitle: `${state.tasks.filter((t) => t.endedAt !== undefined).length}/${state.tasks.length} done` }, (p) => {
          if (state.tasks.length === 0) {
            p.label("waiting for nmap…");
            return;
          }
          const now = Date.now() / 1000;
          for (const task of state.tasks.slice(-12)) {
            const done = task.endedAt !== undefined;
            const active = !done;
            const duration = (task.endedAt ?? now) - task.startedAt;
            const percent = done ? 100 : task.percent ?? (active ? Math.min(99, duration * 3) : 0);
            const text = done
              ? `${formatDuration(duration)}${task.extrainfo ? ` · ${task.extrainfo}` : ""}`
              : task.percent !== undefined
                ? `${task.percent.toFixed(1)}%${task.remaining !== undefined ? ` · ${formatDuration(task.remaining)} left` : ""}`
                : `${formatDuration(duration)} · running`;
            p.meter({ label: task.task, value: percent, max: 100, text, labelWidth: 18, valueWidth: 26, color: done ? theme.muted : theme.accent, style: "smooth" });
          }
        });
        left.panel({ title: " Log ", subtitle: state.logFromEnd > 0 ? `↑${state.logFromEnd}` : "" }, (p) => renderLog(state, p));
      });
      row.panel({ title: " Hosts ", subtitle: result ? `${result.hosts.filter((h) => h.state === "up").length} up · ${result.hosts.length} seen` : "" }, (p) => {
        const hosts = result?.hosts ?? [];
        if (hosts.length === 0) {
          p.label("no hosts reported yet; nmap reports each host when it finishes it");
          return;
        }
        p.table({
          rows: hosts.slice().reverse(),
          columns: [
            { key: "addr", title: "ADDRESS", width: 17 },
            { key: "name", title: "NAME", render: (h) => primaryName(h) },
            { key: "state", title: "STATE", width: 7, color: (h) => stateColor(theme, h.state) },
            { key: "open", title: "OPEN", width: 5, align: "right", render: (h) => String(openPorts(h).length), color: (h) => (openPorts(h).length > 0 ? theme.success : theme.muted) },
            { key: "services", title: "SERVICES", render: (h) => openPorts(h).map((p) => p.service?.name ?? String(p.port)).join(" ") },
          ],
          selected: -1,
          zebra: true,
          scrollbar: true,
        });
      });
    });
  });
}

function renderLog(state: UiState, p: Container): void {
  p.log({
    entries: state.log.map((l) => ({ time: l.time, level: l.level, message: l.message })),
    fromEnd: state.logFromEnd,
    follow: state.logFromEnd === 0,
    scrollbar: true,
    levelColors: { TASK: p.theme.accent, HOST: p.theme.success, INFO: p.theme.muted, WARN: p.theme.warning, ERROR: p.theme.danger },
    onScroll: (d) => {
      state.logFromEnd = Math.max(0, state.logFromEnd - d);
    },
  });
}

export function handleLiveKey(state: UiState, event: KeyEvent, ctx: Ctx): boolean {
  switch (event.key) {
    case "x":
      if (state.running) ctx.actions.abortScan();
      return true;
    case "up":
    case "k":
      state.logFromEnd++;
      return true;
    case "down":
    case "j":
      state.logFromEnd = Math.max(0, state.logFromEnd - 1);
      return true;
    case "pageup":
      state.logFromEnd += 10;
      return true;
    case "pagedown":
      state.logFromEnd = Math.max(0, state.logFromEnd - 10);
      return true;
    case "G":
    case "end":
      state.logFromEnd = 0;
      return true;
    case "enter":
      if (!state.running && state.result) ctx.actions.goto("hosts");
      return true;
    default:
      return false;
  }
}
