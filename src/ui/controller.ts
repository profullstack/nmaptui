/**
 * The controller owns the state and every side effect: starting and
 * aborting nmap, saving to the store, exporting, and dispatching keys to
 * whichever screen or overlay is in front.
 */
import { themeList, type KeyEvent } from "@profullstack/hqtui";
import { existsSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { diffScans } from "../diff.ts";
import { openPorts, type ScanResult } from "../model.ts";
import { privilegeProblem, runScan, type NmapInfo } from "../nmap.ts";
import { PROFILES } from "../profiles.ts";
import { EXPORT_EXTENSIONS, exportScan, type ExportFormat } from "../report.ts";
import { ScanStore, loadXmlFile, type ScanRecord } from "../store.ts";
import type { Actions } from "./actions.ts";
import { commands, type Command } from "./commands.ts";
import { LineEditor } from "./editor.ts";
import { handleOverlayKey } from "./overlays.ts";
import { handleDashboardKey } from "./screens/dashboard.ts";
import { handleDiffKey } from "./screens/diff.ts";
import { handleFindingsKey } from "./screens/findings.ts";
import { handleHistoryKey } from "./screens/history.ts";
import { handleHostsKey } from "./screens/hosts.ts";
import { handleLiveKey } from "./screens/live.ts";
import { handleScanKey, selectProfile } from "./screens/scan.ts";
import { handleServicesKey } from "./screens/services.ts";
import { applyTaskEvent, createState, pushLog, SCREENS, type Screen, type UiState } from "./state.ts";

export interface Host {
  invalidate(): void;
  redraw(): void;
  stop(): void;
  setTheme(name: string): void;
  setCollapseBorders(value: boolean): void;
}

export interface ControllerOptions {
  nmap: NmapInfo | null;
  sudo: boolean;
  store: ScanStore;
  program?: string;
  /** Where exports default to. */
  exportDir?: string;
  theme?: string;
}

export class Controller {
  readonly state: UiState;
  readonly store: ScanStore;
  readonly actions: Actions;
  host: Host = { invalidate() {}, redraw() {}, stop() {}, setTheme() {}, setCollapseBorders() {} };
  private ticker: NodeJS.Timeout | null = null;
  private options: ControllerOptions;

  constructor(options: ControllerOptions) {
    this.options = options;
    this.store = options.store;
    this.state = createState({ nmap: options.nmap, sudo: options.sudo, themeName: options.theme ?? "dark" });
    this.actions = {
      goto: (screen) => this.goto(screen),
      startScan: () => this.startScan(),
      abortScan: () => this.abortScan(),
      openRecord: (id) => this.openRecord(id),
      deleteRecord: (id) => this.deleteRecord(id),
      relabelRecord: (id) => this.relabelRecord(id),
      importFile: () => this.importFile(),
      diffMarked: () => this.diffMarked(),
      openExport: () => this.openExport(),
      toast: (message) => this.toast(message),
      reloadHistory: () => this.reloadHistory(),
      quit: () => this.quit(),
      invalidate: () => this.host.invalidate(),
    };
    this.reloadHistory();
  }

  // ------------------------------------------------------------- results

  /** Make a result the one every screen shows. */
  setResult(result: ScanResult, xml: string, source: string, record?: ScanRecord): void {
    const s = this.state;
    s.result = result;
    s.resultXml = xml;
    s.resultSource = source;
    s.resultRecord = record;
    s.findings.cache = null;
    s.hosts.selected = 0;
    s.hosts.detailScroll = 0;
    s.services.selected = 0;
    s.findings.selected = 0;
  }

  loadFile(path: string): void {
    const { result, xml } = loadXmlFile(path);
    this.setResult(result, xml, path);
    this.goto("dashboard");
  }

  openRecord(id: string): void {
    const loaded = this.store.load(id);
    if (!loaded) {
      this.toast(`scan ${id} is missing on disk`);
      this.reloadHistory();
      return;
    }
    this.setResult(loaded.result, loaded.xml, loaded.record.label ?? loaded.record.id, loaded.record);
    this.toast(`opened ${id}`);
    this.goto("dashboard");
  }

  reloadHistory(): void {
    try {
      this.state.history.records = this.store.list();
    } catch {
      this.state.history.records = [];
    }
    this.host.invalidate();
  }

  deleteRecord(id: string): void {
    this.state.overlay = {
      kind: "confirm",
      title: "Delete scan",
      message: `Delete ${id} and its XML? This cannot be undone.`,
      onYes: () => {
        this.store.remove(id);
        this.state.history.marked = this.state.history.marked.filter((m) => m !== id);
        if (this.state.resultRecord?.id === id) this.state.resultRecord = undefined;
        this.reloadHistory();
        this.toast(`deleted ${id}`);
      },
    };
  }

  relabelRecord(id: string): void {
    const record = this.store.get(id);
    this.state.overlay = {
      kind: "input",
      title: "Label",
      editor: new LineEditor(record?.label ?? ""),
      hint: "a name for this scan, shown instead of its targets",
      onSubmit: (value) => {
        this.store.relabel(id, value.trim());
        this.reloadHistory();
      },
    };
  }

  importFile(): void {
    this.state.overlay = {
      kind: "input",
      title: "Import nmap XML",
      editor: new LineEditor(""),
      hint: "path to a file written with nmap -oX",
      onSubmit: (value) => {
        const path = expand(value.trim());
        if (!path || !existsSync(path)) {
          this.toast(`no such file: ${value}`);
          return;
        }
        try {
          const record = this.store.import(path);
          this.reloadHistory();
          this.openRecord(record.id);
        } catch (error) {
          this.toast(`import failed: ${(error as Error).message}`);
        }
      },
    };
  }

  diffMarked(): void {
    const [a, b] = this.state.history.marked;
    if (!a || !b) {
      this.toast("mark two scans with m first");
      this.goto("history");
      return;
    }
    const la = this.store.load(a);
    const lb = this.store.load(b);
    if (!la || !lb) {
      this.toast("one of the marked scans is missing");
      return;
    }
    // Older first, whatever order they were marked in.
    const [first, second] = la.record.startedAt <= lb.record.startedAt ? [la, lb] : [lb, la];
    this.setDiff(first.result, second.result, first.record.label ?? first.record.id, second.record.label ?? second.record.id);
    this.goto("diff");
  }

  setDiff(a: ScanResult, b: ScanResult, aLabel: string, bLabel: string): void {
    this.state.diff.diff = diffScans(a, b);
    this.state.diff.aLabel = aLabel;
    this.state.diff.bLabel = bLabel;
    this.state.diff.selected = 0;
  }

  // -------------------------------------------------------------- export

  openExport(): void {
    if (!this.state.result) {
      this.toast("nothing to export yet");
      return;
    }
    const id = this.state.resultRecord?.id ?? "scan";
    const format: ExportFormat = "text";
    const dir = this.options.exportDir ?? process.cwd();
    this.state.overlay = { kind: "export", format, editor: new LineEditor(join(dir, `nmaptui-${id}.${EXPORT_EXTENSIONS[format]}`)) };
  }

  performExport(format: ExportFormat, rawPath: string): string | null {
    const s = this.state;
    if (!s.result) return "nothing to export";
    const path = expand(rawPath.trim());
    if (!path) return "enter a path";
    if (!existsSync(dirname(path))) return `no such directory: ${dirname(path)}`;
    try {
      writeFileSync(path, exportScan(s.result, s.resultXml, format));
    } catch (error) {
      return (error as Error).message;
    }
    this.toast(`wrote ${format} to ${path}`);
    return null;
  }

  // ---------------------------------------------------------------- scan

  startScan(): void {
    const s = this.state;
    if (s.running) {
      this.toast("a scan is already running (x on Live aborts it)");
      this.goto("live");
      return;
    }
    if (!s.config.targets.trim() && !s.config.targetFile) {
      this.toast("add at least one target");
      this.goto("scan");
      s.builder.pane = "form";
      s.builder.field = 0;
      return;
    }
    const problem = privilegeProblem(s.config, s.nmap, s.sudo);
    if (problem) {
      this.toast(problem);
      this.goto("scan");
      return;
    }
    s.tasks = [];
    s.log = [];
    s.logFromEnd = 0;
    s.runStartedAt = Date.now();
    const running = runScan(
      s.config,
      {
        onStart: (command) => pushLog(s, "INFO", command.join(" ")),
        onTask: (task) => {
          applyTaskEvent(s.tasks, task);
          if (task.kind !== "progress") pushLog(s, "TASK", `${task.task} ${task.kind === "begin" ? "started" : "finished"}${task.extrainfo ? `: ${task.extrainfo}` : ""}`);
          this.host.invalidate();
        },
        onHost: (host) => {
          pushLog(s, "HOST", `${host.addr}${host.hostnames[0] ? ` (${host.hostnames[0].name})` : ""} ${host.state}, ${openPorts(host).length} open`);
          this.host.invalidate();
        },
        onStderr: (line) => {
          pushLog(s, /warning/i.test(line) ? "WARN" : /error|failed|quitting|requires root|denied/i.test(line) ? "ERROR" : "INFO", line);
          this.host.invalidate();
        },
        onError: (error) => {
          pushLog(s, "ERROR", error.message);
          this.host.invalidate();
        },
        onDone: (result, xml, code) => this.finishScan(result, xml, code),
      },
      { program: this.options.program ?? s.nmap?.path ?? "nmap", sudo: s.sudo && !s.nmap?.privileged },
    );
    s.running = running;
    this.ticker = setInterval(() => this.host.invalidate(), 500);
    this.ticker.unref?.();
    this.toast("scan started");
    this.goto("live");
  }

  private finishScan(result: ScanResult, xml: string, code: number | null): void {
    const s = this.state;
    const running = s.running;
    s.running = null;
    if (this.ticker) clearInterval(this.ticker);
    this.ticker = null;
    const aborted = running?.aborted ?? false;
    const up = result.hosts.filter((h) => h.state === "up").length;
    if (xml.trim().length === 0 || !result.args) {
      pushLog(s, "ERROR", `nmap exited with ${code ?? "no"} status and no output`);
      this.toast(code === 1 ? "nmap failed: see the Live log" : "nmap produced no output");
      this.host.invalidate();
      return;
    }
    let record: ScanRecord | undefined;
    try {
      record = this.store.save(result, xml);
      this.reloadHistory();
    } catch (error) {
      pushLog(s, "WARN", `could not save the scan: ${(error as Error).message}`);
    }
    pushLog(s, "INFO", aborted ? `aborted with ${result.hosts.length} host${result.hosts.length === 1 ? "" : "s"} reported` : result.runStats?.summary ?? `finished with code ${code}`);
    this.setResult(result, xml, record?.id ?? "last scan", record);
    this.toast(aborted ? `aborted: ${up} up so far` : `done: ${up} up, ${result.hosts.reduce((n, h) => n + openPorts(h).length, 0)} open ports`);
    if (s.screen === "live" && !aborted && code === 0) this.goto("hosts");
    this.host.invalidate();
  }

  abortScan(): void {
    const running = this.state.running;
    if (!running) return;
    running.abort();
    pushLog(this.state, "WARN", "abort requested");
    this.toast("aborting…");
  }

  // ------------------------------------------------------------- general

  goto(screen: Screen): void {
    this.state.screen = screen;
    if (screen === "history") this.reloadHistory();
    this.host.invalidate();
  }

  toast(message: string): void {
    this.state.message = message;
    this.state.messageAt = Date.now();
    this.host.invalidate();
    setTimeout(() => this.host.invalidate(), 5100).unref?.();
  }

  quit(): void {
    if (this.state.running) {
      this.state.overlay = {
        kind: "confirm",
        title: "Quit",
        message: "A scan is running. Abort it and quit?",
        onYes: () => {
          this.state.running?.abort();
          this.host.stop();
        },
      };
      this.host.invalidate();
      return;
    }
    this.host.stop();
  }

  palette(): Command[] {
    return commands(this.state, this.actions, {
      toggleCollapse: () => this.toggleCollapse(),
      cycleTheme: () => this.cycleTheme(),
      showHelp: () => (this.state.overlay = { kind: "help" }),
      showCommand: () => {
        const r = this.state.result;
        if (r) this.state.overlay = { kind: "message", title: "nmap command", lines: [r.args, "", `nmap ${r.version}`, r.startStr ?? "", r.runStats?.summary ?? ""], scroll: 0 };
      },
    });
  }

  toggleCollapse(): void {
    this.state.collapse = !this.state.collapse;
    this.host.setCollapseBorders(this.state.collapse);
  }

  cycleTheme(): void {
    const names = themeList.map((t) => t.name);
    const next = names[(names.indexOf(this.state.themeName) + 1) % names.length] ?? "dark";
    this.state.themeName = next;
    this.host.setTheme(next);
    this.toast(`theme ${next}`);
  }

  /** Route a key. Returns true when something handled it. */
  handleKey(event: KeyEvent): boolean {
    const s = this.state;
    if (s.overlay) {
      const handled = handleOverlayKey(s, event, this.palette(), {
        performExport: (format, path) => this.performExport(format, path),
        runCommand: (command) => command.run(),
      });
      this.host.invalidate();
      return handled;
    }

    // Screens with a text field get the first look at keys.
    const typing = (s.screen === "scan" && s.builder.editing) || (s.screen === "hosts" && s.hosts.filtering);
    if (!typing) {
      const global = this.handleGlobalKey(event);
      if (global) {
        this.host.invalidate();
        return true;
      }
    }

    let handled = false;
    switch (s.screen) {
      case "dashboard":
        handled = handleDashboardKey(s, event, this.ctx());
        break;
      case "scan":
        handled = handleScanKey(s, event, this.ctx());
        break;
      case "live":
        handled = handleLiveKey(s, event, this.ctx());
        break;
      case "hosts":
        handled = handleHostsKey(s, event, this.ctx());
        break;
      case "services":
        handled = handleServicesKey(s, event, this.ctx());
        break;
      case "findings":
        handled = handleFindingsKey(s, event, this.ctx());
        break;
      case "history":
        handled = handleHistoryKey(s, event, this.ctx());
        break;
      case "diff":
        handled = handleDiffKey(s, event, this.ctx());
        break;
    }
    if (!handled && typing) handled = this.handleGlobalKey(event);
    this.host.invalidate();
    return handled;
  }

  private ctx(): { theme: import("@profullstack/hqtui").Theme; width: number; height: number; actions: Actions } {
    // Screens only need actions when handling keys; theme and size are for rendering.
    return { theme: themeList.find((t) => t.name === this.state.themeName) ?? themeList[0]!, width: 0, height: 0, actions: this.actions };
  }

  private handleGlobalKey(event: KeyEvent): boolean {
    const s = this.state;
    const { key, name } = event;
    if (/^[1-8]$/.test(key)) {
      this.goto(SCREENS[Number(key) - 1] as Screen);
      return true;
    }
    switch (key) {
      case "q":
        this.quit();
        return true;
      case "?":
      case "f1":
        s.overlay = { kind: "help" };
        return true;
      case ":":
      case "ctrl+p":
        s.overlay = { kind: "palette", editor: new LineEditor(""), selected: 0 };
        return true;
      case "[":
        this.goto(SCREENS[(SCREENS.indexOf(s.screen) - 1 + SCREENS.length) % SCREENS.length] as Screen);
        return true;
      case "]":
        this.goto(SCREENS[(SCREENS.indexOf(s.screen) + 1) % SCREENS.length] as Screen);
        return true;
      case "e":
        if (s.screen === "scan") return false;
        this.openExport();
        return true;
      case "n":
        this.goto("scan");
        return true;
      case "c":
        this.toggleCollapse();
        return true;
      case "t":
        this.cycleTheme();
        return true;
      case "ctrl+l":
        this.host.redraw();
        return true;
      case "escape":
        if (s.screen === "hosts" && s.hosts.filter) {
          s.hosts.filter = "";
          s.hosts.editor.set("");
          return true;
        }
        return false;
      default:
        break;
    }
    if (name === "f5") {
      this.reloadHistory();
      return true;
    }
    return false;
  }

  /** Pick a profile by id on startup. */
  useProfile(id: string): boolean {
    const index = PROFILES.findIndex((p) => p.id === id);
    if (index < 0) return false;
    selectProfile(this.state, index);
    return true;
  }
}

function expand(path: string): string {
  if (!path) return "";
  if (path === "~") return homedir();
  if (path.startsWith("~/")) return join(homedir(), path.slice(2));
  return isAbsolute(path) ? path : resolve(path);
}
