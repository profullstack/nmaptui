/**
 * Everything the screens draw from. One plain object, mutated by the
 * controller, read by pure render functions, which is what makes the
 * screens testable headlessly.
 */
import type { ScanDiff } from "../diff.ts";
import type { Finding, Severity } from "../analysis.ts";
import type { ScanResult, TaskEvent } from "../model.ts";
import type { NmapInfo, RunningScan } from "../nmap.ts";
import { defaultConfig, PROFILES, type ScanConfig } from "../profiles.ts";
import type { ScanRecord } from "../store.ts";
import type { ExportFormat } from "../report.ts";
import { LineEditor } from "./editor.ts";

export const SCREENS = ["dashboard", "scan", "live", "hosts", "services", "findings", "history", "diff"] as const;
export type Screen = (typeof SCREENS)[number];
export const SCREEN_TITLES: Record<Screen, string> = {
  dashboard: "Dashboard",
  scan: "New scan",
  live: "Live",
  hosts: "Hosts",
  services: "Services",
  findings: "Findings",
  history: "History",
  diff: "Diff",
};

export interface LogLine {
  time: string;
  level: "INFO" | "WARN" | "ERROR" | "TASK" | "HOST";
  message: string;
}

export interface TaskRow {
  task: string;
  startedAt: number;
  endedAt?: number;
  percent?: number;
  remaining?: number;
  etc?: number;
  extrainfo?: string;
}

export type HostSort = "addr" | "open" | "name" | "os";

export type Overlay =
  | { kind: "help" }
  | { kind: "palette"; editor: LineEditor; selected: number }
  | { kind: "export"; format: ExportFormat; editor: LineEditor; error?: string }
  | { kind: "confirm"; title: string; message: string; onYes: () => void }
  | { kind: "input"; title: string; editor: LineEditor; onSubmit: (value: string) => void; hint?: string }
  | { kind: "message"; title: string; lines: string[]; scroll: number };

export interface UiState {
  screen: Screen;
  nmap: NmapInfo | null;
  sudo: boolean;
  /** Current result being browsed, whatever its origin. */
  result: ScanResult | null;
  resultXml: string;
  resultRecord?: ScanRecord;
  resultSource: string;
  running: RunningScan | null;
  runStartedAt: number;
  tasks: TaskRow[];
  log: LogLine[];
  logFromEnd: number;
  /** Builder */
  config: ScanConfig;
  profileIndex: number;
  builder: { pane: "profiles" | "form"; field: number; editing: boolean; editor: LineEditor; offset: number };
  /** Hosts */
  hosts: { selected: number; offset: number; filter: string; filtering: boolean; editor: LineEditor; sort: HostSort; openOnly: boolean; upOnly: boolean; pane: "list" | "detail"; detailScroll: number };
  services: { selected: number; offset: number; pane: "list" | "detail"; detailSelected: number };
  findings: { selected: number; offset: number; minSeverity: Severity; cache: Finding[] | null };
  history: { records: ScanRecord[]; selected: number; offset: number; marked: string[] };
  diff: { diff: ScanDiff | null; aLabel: string; bLabel: string; selected: number; offset: number; showUnchanged: boolean };
  overlay: Overlay | null;
  message: string;
  messageAt: number;
  collapse: boolean;
  themeName: string;
}

export function createState(partial: Partial<UiState> = {}): UiState {
  return {
    screen: "dashboard",
    nmap: null,
    sudo: false,
    result: null,
    resultXml: "",
    resultSource: "",
    running: null,
    runStartedAt: 0,
    tasks: [],
    log: [],
    logFromEnd: 0,
    config: defaultConfig(),
    profileIndex: PROFILES.findIndex((p) => p.id === "quick"),
    builder: { pane: "form", field: 0, editing: false, editor: new LineEditor(), offset: 0 },
    hosts: { selected: 0, offset: 0, filter: "", filtering: false, editor: new LineEditor(), sort: "addr", openOnly: false, upOnly: true, pane: "list", detailScroll: 0 },
    services: { selected: 0, offset: 0, pane: "list", detailSelected: 0 },
    findings: { selected: 0, offset: 0, minSeverity: "info", cache: null },
    history: { records: [], selected: 0, offset: 0, marked: [] },
    diff: { diff: null, aLabel: "", bLabel: "", selected: 0, offset: 0, showUnchanged: false },
    overlay: null,
    message: "",
    messageAt: 0,
    collapse: false,
    themeName: "dark",
    ...partial,
  };
}

/** Fold a task event into the live task rows. */
export function applyTaskEvent(tasks: TaskRow[], event: TaskEvent): void {
  const open = tasks.slice().reverse().find((t) => t.task === event.task && t.endedAt === undefined);
  if (event.kind === "begin" || !open) {
    if (event.kind === "end" && !open) {
      tasks.push({ task: event.task, startedAt: event.time, endedAt: event.time, extrainfo: event.extrainfo, percent: 100 });
      return;
    }
    tasks.push({ task: event.task, startedAt: event.time, percent: event.kind === "progress" ? event.percent : undefined });
    return;
  }
  if (event.kind === "progress") {
    open.percent = event.percent;
    open.remaining = event.remaining;
    open.etc = event.etc;
  } else {
    open.endedAt = event.time;
    open.percent = 100;
    open.extrainfo = event.extrainfo;
  }
}

export function timestamp(date = new Date()): string {
  const pad = (n: number): string => String(n).padStart(2, "0");
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export function pushLog(state: UiState, level: LogLine["level"], message: string): void {
  state.log.push({ time: timestamp(), level, message });
  if (state.log.length > 2000) state.log.splice(0, state.log.length - 2000);
}
