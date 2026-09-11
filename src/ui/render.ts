/**
 * The frame: header with tabs, the active screen, a status bar, and any
 * overlay. Pure: it reads state and draws.
 */
import type { Container, Theme } from "@profullstack/hqtui";
import type { Actions, Ctx } from "./actions.ts";
import type { Command } from "./commands.ts";
import { renderOverlay } from "./overlays.ts";
import { renderDashboard } from "./screens/dashboard.ts";
import { renderDiff } from "./screens/diff.ts";
import { renderFindings } from "./screens/findings.ts";
import { renderHistory } from "./screens/history.ts";
import { renderHosts } from "./screens/hosts.ts";
import { renderLive } from "./screens/live.ts";
import { renderScan } from "./screens/scan.ts";
import { renderServices } from "./screens/services.ts";
import { SCREEN_TITLES, SCREENS, type Screen, type UiState } from "./state.ts";

const STATUS_KEYS: Record<Screen, { key: string; label: string }[]> = {
  dashboard: [{ key: "2", label: "new scan" }, { key: "4", label: "hosts" }, { key: "7", label: "history" }],
  scan: [{ key: "s", label: "start" }, { key: "tab", label: "profiles" }, { key: "enter", label: "edit" }, { key: "r", label: "reset" }],
  live: [{ key: "x", label: "abort" }, { key: "↑↓", label: "log" }, { key: "enter", label: "results" }],
  hosts: [{ key: "/", label: "filter" }, { key: "o", label: "open-only" }, { key: "u", label: "down" }, { key: "S", label: "sort" }, { key: "tab", label: "detail" }],
  services: [{ key: "tab", label: "hosts" }, { key: "enter", label: "go to host" }],
  findings: [{ key: "f", label: "severity" }, { key: "enter", label: "go to host" }],
  history: [{ key: "enter", label: "open" }, { key: "m", label: "mark" }, { key: "d", label: "diff" }, { key: "i", label: "import" }, { key: "D", label: "delete" }],
  diff: [{ key: "u", label: "unchanged" }, { key: "enter", label: "go to host" }],
};

export function renderApp(state: UiState, ui: Container, args: { theme: Theme; width: number; height: number }, actions: Actions, palette: Command[]): void {
  const ctx: Ctx = { theme: args.theme, width: args.width, height: args.height, actions };
  const { theme } = ctx;
  const compact = args.width < 96;

  ui.column({}, (col) => {
    col.row({ size: 1 }, (row) => {
      row.text([{ text: " nmaptui ", fg: theme.background, bg: theme.primary, bold: true }], { size: 9 });
      row.tabs({
        tabs: SCREENS.map((s, i) => (compact ? `${i + 1} ${SCREEN_TITLES[s].slice(0, 4)}` : `${i + 1} ${SCREEN_TITLES[s]}`)),
        active: SCREENS.indexOf(state.screen),
        onSelect: (i) => actions.goto(SCREENS[i] as Screen),
      });
      const right: { text: string; fg?: typeof theme.muted; bg?: typeof theme.muted; bold?: boolean }[] = [];
      if (state.running) right.push({ text: " SCANNING ", fg: theme.background, bg: theme.success, bold: true }, { text: " " });
      if (state.nmap) right.push({ text: `nmap ${state.nmap.version} `, fg: theme.muted });
      else right.push({ text: "no nmap ", fg: theme.danger, bold: true });
      right.push(state.nmap?.privileged ? { text: "root ", fg: theme.warning } : state.sudo ? { text: "sudo ", fg: theme.warning } : { text: "user ", fg: theme.muted });
      row.text(right, { size: 32, align: "right" });
    });

    col.box({ padding: 0 }, (body) => {
      switch (state.screen) {
        case "dashboard":
          renderDashboard(state, body, ctx);
          break;
        case "scan":
          renderScan(state, body, ctx);
          break;
        case "live":
          renderLive(state, body, ctx);
          break;
        case "hosts":
          renderHosts(state, body, ctx);
          break;
        case "services":
          renderServices(state, body, ctx);
          break;
        case "findings":
          renderFindings(state, body, ctx);
          break;
        case "history":
          renderHistory(state, body, ctx);
          break;
        case "diff":
          renderDiff(state, body, ctx);
          break;
      }
    });

    const fresh = state.message && Date.now() - state.messageAt < 5000;
    col.statusBar({
      items: [...STATUS_KEYS[state.screen], { key: "?", label: "help" }, { key: ":", label: "commands" }, { key: "q", label: "quit" }],
      right: fresh
        ? [{ label: state.message, color: theme.accent, active: true }]
        : state.result
          ? [{ label: state.resultSource || (state.resultRecord ? state.resultRecord.id : ""), color: theme.muted }]
          : [],
    });
  });

  renderOverlay(state, ui, ctx, palette);
}
