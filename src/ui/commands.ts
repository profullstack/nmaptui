/** The command palette's entries. Every action reachable by key is here too. */
import { PROFILES } from "../profiles.ts";
import { EXPORT_FORMATS } from "../report.ts";
import type { Actions } from "./actions.ts";
import { selectProfile } from "./screens/scan.ts";
import { SCREEN_TITLES, SCREENS, type UiState } from "./state.ts";

export interface Command {
  label: string;
  hint?: string;
  run: () => void;
}

export function commands(state: UiState, actions: Actions, extra: { toggleCollapse(): void; cycleTheme(): void; showHelp(): void; showCommand(): void }): Command[] {
  const list: Command[] = [];
  SCREENS.forEach((screen, i) => list.push({ label: `Go to ${SCREEN_TITLES[screen]}`, hint: String(i + 1), run: () => actions.goto(screen) }));
  list.push({ label: "Start scan", hint: "s on New scan", run: () => actions.startScan() });
  if (state.running) list.push({ label: "Abort scan", hint: "x on Live", run: () => actions.abortScan() });
  for (const profile of PROFILES) {
    list.push({
      label: `Profile: ${profile.name}`,
      hint: profile.description,
      run: () => {
        selectProfile(state, PROFILES.indexOf(profile));
        actions.goto("scan");
      },
    });
  }
  if (state.result) {
    list.push({ label: "Export scan", hint: `e · ${EXPORT_FORMATS.join(", ")}`, run: () => actions.openExport() });
    list.push({ label: "Show nmap command", hint: state.result.args, run: () => extra.showCommand() });
    list.push({ label: "Hosts: toggle open-only", hint: "o", run: () => { state.hosts.openOnly = !state.hosts.openOnly; actions.goto("hosts"); } });
    list.push({ label: "Hosts: toggle down hosts", hint: "u", run: () => { state.hosts.upOnly = !state.hosts.upOnly; actions.goto("hosts"); } });
  }
  list.push({ label: "Import nmap XML", hint: "i on History", run: () => actions.importFile() });
  list.push({ label: "Diff marked scans", hint: "d on History", run: () => actions.diffMarked() });
  list.push({ label: "Reload history", hint: "r on History", run: () => actions.reloadHistory() });
  list.push({ label: "Toggle collapsed borders", hint: "c", run: () => extra.toggleCollapse() });
  list.push({ label: "Cycle theme", hint: "t", run: () => extra.cycleTheme() });
  list.push({ label: "Help", hint: "?", run: () => extra.showHelp() });
  list.push({ label: "Quit", hint: "q", run: () => actions.quit() });
  return list;
}

export function filterCommands(list: Command[], query: string): Command[] {
  const q = query.trim().toLowerCase();
  if (!q) return list;
  const words = q.split(/\s+/);
  return list.filter((c) => {
    const hay = `${c.label} ${c.hint ?? ""}`.toLowerCase();
    return words.every((w) => hay.includes(w));
  });
}
