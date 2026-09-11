/**
 * The scan builder: profiles on the left, a form on the right, the exact
 * command it will run underneath. Nothing runs until `s`.
 */
import type { Container, KeyEvent } from "@profullstack/hqtui";
import { applyProfile, commandLine, needsRoot, PROFILES, TECHNIQUES, TIMING_LABELS, type ScanConfig, type ScanTechnique } from "../../profiles.ts";
import { formatCount, summarizeTargets } from "../../targets.ts";
import type { Ctx } from "../actions.ts";
import { clamp, elide } from "../format.ts";
import type { UiState } from "../state.ts";

type FieldKind = "text" | "toggle" | "cycle" | "number";

export interface Field {
  id: string;
  label: string;
  kind: FieldKind;
  hint: string;
  get(c: ScanConfig): string | boolean | number | undefined;
  set(c: ScanConfig, value: string): void;
  options?: string[];
  /** For numbers: step and bounds. */
  step?: number;
  min?: number;
  max?: number;
  /** Section header drawn above this field. */
  section?: string;
}

const num = (v: string): number | undefined => {
  const n = Number(v);
  return v.trim() === "" || !Number.isFinite(n) ? undefined : n;
};

export const FIELDS: Field[] = [
  { id: "targets", label: "Targets", kind: "text", section: "Targets", hint: "hosts, CIDR blocks, ranges: 10.0.0.0/24 192.168.1.1-50 example.com", get: (c) => c.targets, set: (c, v) => (c.targets = v) },
  { id: "targetFile", label: "Target file", kind: "text", hint: "-iL: a file with one target per line", get: (c) => c.targetFile ?? "", set: (c, v) => (c.targetFile = v.trim() || undefined) },
  { id: "exclude", label: "Exclude", kind: "text", hint: "--exclude: hosts to skip, comma separated", get: (c) => c.exclude ?? "", set: (c, v) => (c.exclude = v.trim() || undefined) },
  { id: "technique", label: "Technique", kind: "cycle", section: "Scan", hint: "SYN needs root; connect works for anyone", options: TECHNIQUES.map((t) => t.label), get: (c) => TECHNIQUES.findIndex((t) => t.id === c.technique), set: (c, v) => (c.technique = (TECHNIQUES[Number(v)]?.id ?? "syn") as ScanTechnique) },
  { id: "ports", label: "Ports", kind: "text", hint: "-p: 22,80,443 or 1-65535 or U:53,T:80. Empty = nmap default", get: (c) => c.ports, set: (c, v) => (c.ports = v.trim()) },
  { id: "topPorts", label: "Top ports", kind: "number", hint: "--top-ports N (ignored when Ports is set)", step: 100, min: 0, max: 65535, get: (c) => c.topPorts ?? 0, set: (c, v) => (c.topPorts = num(v) || undefined) },
  { id: "fast", label: "Fast (-F)", kind: "toggle", hint: "only the 100 most common ports", get: (c) => c.fast, set: (c, v) => (c.fast = v === "true") },
  { id: "timing", label: "Timing", kind: "cycle", hint: "-T0 hides from IDS, -T5 assumes a fast, reliable network", options: TIMING_LABELS, get: (c) => c.timing, set: (c, v) => (c.timing = clamp(Number(v), 0, 5) as ScanConfig["timing"]) },
  { id: "serviceVersion", label: "Service versions (-sV)", kind: "toggle", section: "Detection", hint: "probe open ports for product and version", get: (c) => c.serviceVersion, set: (c, v) => (c.serviceVersion = v === "true") },
  { id: "versionIntensity", label: "Version intensity", kind: "number", hint: "0 light to 9 try everything. Empty = 7", step: 1, min: 0, max: 9, get: (c) => c.versionIntensity ?? "", set: (c, v) => (c.versionIntensity = num(v)) },
  { id: "osDetect", label: "OS detection (-O)", kind: "toggle", hint: "TCP/IP fingerprinting; needs root", get: (c) => c.osDetect, set: (c, v) => (c.osDetect = v === "true") },
  { id: "aggressive", label: "Aggressive (-A)", kind: "toggle", hint: "versions + OS + default scripts + traceroute in one flag", get: (c) => c.aggressive, set: (c, v) => (c.aggressive = v === "true") },
  { id: "defaultScripts", label: "Default scripts (-sC)", kind: "toggle", hint: "the NSE default category", get: (c) => c.defaultScripts, set: (c, v) => (c.defaultScripts = v === "true") },
  { id: "scripts", label: "Scripts", kind: "text", hint: "--script: vuln, discovery, http-title,ssl-cert, \"default or safe\"", get: (c) => c.scripts, set: (c, v) => (c.scripts = v.trim()) },
  { id: "scriptArgs", label: "Script args", kind: "text", hint: "--script-args: key=value,key2=value2", get: (c) => c.scriptArgs, set: (c, v) => (c.scriptArgs = v.trim()) },
  { id: "traceroute", label: "Traceroute", kind: "toggle", hint: "--traceroute: route to each host", get: (c) => c.traceroute, set: (c, v) => (c.traceroute = v === "true") },
  { id: "skipPing", label: "Skip host discovery (-Pn)", kind: "toggle", section: "Discovery", hint: "treat every target as up; for hosts that drop ping", get: (c) => c.skipPing, set: (c, v) => (c.skipPing = v === "true") },
  { id: "noDns", label: "No DNS (-n)", kind: "toggle", hint: "skip reverse lookups; faster and quieter", get: (c) => c.noDns, set: (c, v) => (c.noDns = v === "true") },
  { id: "ipv6", label: "IPv6 (-6)", kind: "toggle", hint: "targets are IPv6", get: (c) => c.ipv6, set: (c, v) => (c.ipv6 = v === "true") },
  { id: "openOnly", label: "Open only (--open)", kind: "toggle", section: "Output", hint: "report only hosts with open ports", get: (c) => c.openOnly, set: (c, v) => (c.openOnly = v === "true") },
  { id: "reason", label: "Reason (--reason)", kind: "toggle", hint: "why each port is in its state", get: (c) => c.reason, set: (c, v) => (c.reason = v === "true") },
  { id: "fragment", label: "Fragment packets (-f)", kind: "toggle", section: "Advanced", hint: "tiny fragments to slip past simple filters; needs root", get: (c) => c.fragment, set: (c, v) => (c.fragment = v === "true") },
  { id: "hostTimeout", label: "Host timeout", kind: "text", hint: "--host-timeout: give up on a host after 30m, 2h", get: (c) => c.hostTimeout ?? "", set: (c, v) => (c.hostTimeout = v.trim() || undefined) },
  { id: "maxRetries", label: "Max retries", kind: "number", hint: "--max-retries: probe retransmissions. Empty = nmap default", step: 1, min: 0, max: 20, get: (c) => c.maxRetries ?? "", set: (c, v) => (c.maxRetries = num(v)) },
  { id: "minRate", label: "Min rate", kind: "number", hint: "--min-rate: packets per second floor", step: 100, min: 0, max: 100000, get: (c) => c.minRate ?? 0, set: (c, v) => (c.minRate = num(v) || undefined) },
  { id: "maxRate", label: "Max rate", kind: "number", hint: "--max-rate: packets per second ceiling", step: 100, min: 0, max: 100000, get: (c) => c.maxRate ?? 0, set: (c, v) => (c.maxRate = num(v) || undefined) },
  { id: "interface", label: "Interface", kind: "text", hint: "-e: eth0, wlan0, tun0", get: (c) => c.interface ?? "", set: (c, v) => (c.interface = v.trim() || undefined) },
  { id: "extra", label: "Extra arguments", kind: "text", hint: "appended verbatim, quotes respected", get: (c) => c.extra, set: (c, v) => (c.extra = v) },
];

export function fieldValue(field: Field, config: ScanConfig): string {
  const v = field.get(config);
  if (field.kind === "toggle") return v ? "on" : "off";
  if (field.kind === "cycle") return field.options?.[Number(v)] ?? "";
  if (v === undefined || v === "" || v === 0) return "";
  return String(v);
}

export function cycleField(field: Field, config: ScanConfig, delta: number): void {
  if (field.kind === "cycle") {
    const n = field.options?.length ?? 0;
    const current = Number(field.get(config));
    field.set(config, String((current + delta + n) % n));
  } else if (field.kind === "number") {
    const current = Number(field.get(config)) || 0;
    field.set(config, String(clamp(current + delta * (field.step ?? 1), field.min ?? 0, field.max ?? Number.MAX_SAFE_INTEGER)));
  } else if (field.kind === "toggle") {
    field.set(config, field.get(config) ? "false" : "true");
  }
}

/** Put the caret in the targets field, for a builder that opens empty. */
export function editTargets(state: UiState): void {
  state.builder.pane = "form";
  state.builder.field = 0;
  state.builder.editing = true;
  state.builder.editor.set(state.config.targets);
}

export function selectProfile(state: UiState, index: number): void {
  const profile = PROFILES[index];
  if (!profile) return;
  state.profileIndex = index;
  state.config = applyProfile(state.config, profile);
}

export function renderScan(state: UiState, ui: Container, ctx: Ctx): void {
  const { theme } = ctx;
  const b = state.builder;
  const config = state.config;
  const summary = summarizeTargets(config.targets);
  const wide = ctx.width >= 110;

  const profilesPanel = (c: Container, size?: number | string): void => {
    c.panel({ title: " Profiles ", size, focused: b.pane === "profiles", focusable: false, subtitle: "↑↓ pick" }, (p) => {
      p.list({
        items: PROFILES.map((profile, i) => ({ label: profile.name, color: i === state.profileIndex && b.pane !== "profiles" ? theme.accent : undefined })),
        selected: state.profileIndex,
        followSelection: true,
        onSelectRow: (row) => {
          b.pane = "profiles";
          selectProfile(state, row);
        },
        onScroll: (d) => selectProfile(state, clamp(state.profileIndex + d, 0, PROFILES.length - 1)),
      });
      const current = PROFILES[state.profileIndex];
      if (current) {
        p.divider();
        p.text(current.description, { wrap: true, fg: theme.muted });
      }
    });
  };

  const formPanel = (c: Container): void => {
    c.panel({ title: " Options ", focused: b.pane === "form", subtitle: b.editing ? "enter save · esc cancel" : "enter edit · ←→ change · space toggle" }, (p) => {
      p.draw((s) => {
        const rows: { field?: Field; section?: string }[] = [];
        for (const f of FIELDS) {
          if (f.section) rows.push({ section: f.section });
          rows.push({ field: f });
        }
        const currentRow = rows.findIndex((r) => r.field === FIELDS[b.field]);
        const capacity = s.height;
        if (currentRow < b.offset) b.offset = currentRow;
        else if (currentRow >= b.offset + capacity) b.offset = currentRow - capacity + 1;
        b.offset = clamp(b.offset, 0, Math.max(0, rows.length - capacity));
        const labelWidth = Math.min(28, Math.max(12, Math.floor(s.width * 0.4)));
        for (let y = 0; y < capacity; y++) {
          const row = rows[b.offset + y];
          if (!row) break;
          if (row.section) {
            s.text(0, y, `── ${row.section} `.padEnd(s.width, "─"), { fg: theme.border });
            continue;
          }
          const field = row.field as Field;
          const index = FIELDS.indexOf(field);
          const active = index === b.field && b.pane === "form";
          const editing = active && b.editing;
          const label = elide(field.label, labelWidth - 1).padEnd(labelWidth);
          if (active) s.fillRect(0, y, s.width, 1, { bg: theme.selection });
          s.text(0, y, label, { fg: active ? theme.selectionText : theme.muted, bg: active ? theme.selection : undefined });
          const valueWidth = Math.max(0, s.width - labelWidth);
          if (editing) {
            const value = b.editor.value;
            const cursor = b.editor.cursor;
            const start = Math.max(0, cursor - valueWidth + 2);
            const shown = value.slice(start, start + valueWidth - 1);
            s.text(labelWidth, y, shown.padEnd(valueWidth - 1), { fg: theme.foreground, bg: theme.surface });
            s.styleRect(labelWidth + (cursor - start), y, 1, 1, { bg: theme.cursor, fg: theme.background });
            continue;
          }
          const value = fieldValue(field, config);
          let shown = value;
          let color = active ? theme.selectionText : theme.foreground;
          if (field.kind === "toggle") {
            shown = field.get(config) ? "◉ on" : "○ off";
            color = field.get(config) ? theme.success : active ? theme.selectionText : theme.muted;
          } else if (field.kind === "cycle") {
            shown = `‹ ${value} ›`;
          } else if (value === "") {
            shown = field.kind === "number" ? "‹ default ›" : "…";
            color = active ? theme.selectionText : theme.muted;
          }
          s.text(labelWidth, y, elide(shown, valueWidth), { fg: color, bg: active ? theme.selection : undefined });
        }
      });
    });
  };

  const hint = FIELDS[b.field]?.hint ?? "";
  const root = needsRoot(config);
  const privileged = state.nmap?.privileged || state.sudo;
  const status: { text: string; color: string | undefined }[] = [];

  const previewPanel = (c: Container): void => {
    c.panel({ title: " Command ", size: 7 }, (p) => {
      p.text(commandLine(config, state.nmap?.path ?? "nmap"), { wrap: true, fg: theme.accent, size: 2 });
      const bits: { text: string; fg: typeof theme.muted }[] = [];
      if (config.targets.trim() === "" && !config.targetFile) bits.push({ text: "no targets yet", fg: theme.warning });
      else if (!summary.valid) bits.push({ text: `invalid: ${summary.invalid.map((t) => t.spec).join(", ")}`, fg: theme.danger });
      else bits.push({ text: `~${formatCount(summary.count)} address${summary.count === 1 ? "" : "es"}`, fg: summary.count > 65536 ? theme.warning : theme.success });
      if (!state.nmap) bits.push({ text: "nmap not found on PATH", fg: theme.danger });
      else if (root && !privileged) bits.push({ text: "needs root: run with sudo, pass --sudo, or pick the TCP connect technique", fg: theme.warning });
      else if (root) bits.push({ text: state.sudo ? "will run via sudo" : "running as root", fg: theme.success });
      p.text(bits.map((bit) => ({ text: bit.text + "   ", fg: bit.fg })), { size: 1 });
      p.label(hint, { size: 1 });
      p.text([{ text: " s ", fg: theme.background, bg: theme.success, bold: true }, { text: " start scan   " }, { text: " tab ", fg: theme.background, bg: theme.accent, bold: true }, { text: " profiles / options   " }, { text: " r ", fg: theme.background, bg: theme.accent, bold: true }, { text: " reset to profile" }], { size: 1 });
    });
  };
  void status;

  ui.column({}, (col) => {
    if (wide) {
      col.row({}, (row) => {
        profilesPanel(row, 34);
        formPanel(row);
      });
    } else {
      col.column({}, (inner) => {
        profilesPanel(inner, 9);
        formPanel(inner);
      });
    }
    previewPanel(col);
  });
}

export function handleScanKey(state: UiState, event: KeyEvent, ctx: Ctx): boolean {
  const b = state.builder;
  const field = FIELDS[b.field] as Field;
  const { key, name } = event;

  if (b.editing) {
    if (key === "escape") {
      b.editing = false;
      return true;
    }
    if (name === "enter") {
      field.set(state.config, b.editor.value);
      b.editing = false;
      return true;
    }
    if (name === "tab") return true;
    b.editor.handle(event);
    return true;
  }

  if (name === "tab") {
    b.pane = b.pane === "form" ? "profiles" : "form";
    return true;
  }
  if (b.pane === "profiles") {
    if (key === "up" || key === "k") selectProfile(state, clamp(state.profileIndex - 1, 0, PROFILES.length - 1));
    else if (key === "down" || key === "j") selectProfile(state, clamp(state.profileIndex + 1, 0, PROFILES.length - 1));
    else if (name === "enter" || key === "right" || key === "l") b.pane = "form";
    else if (key === "s") ctx.actions.startScan();
    else return false;
    return true;
  }

  switch (key) {
    case "up":
    case "k":
      b.field = clamp(b.field - 1, 0, FIELDS.length - 1);
      return true;
    case "down":
    case "j":
      b.field = clamp(b.field + 1, 0, FIELDS.length - 1);
      return true;
    case "pageup":
      b.field = clamp(b.field - 8, 0, FIELDS.length - 1);
      return true;
    case "pagedown":
      b.field = clamp(b.field + 8, 0, FIELDS.length - 1);
      return true;
    case "home":
    case "g":
      b.field = 0;
      return true;
    case "end":
    case "G":
      b.field = FIELDS.length - 1;
      return true;
    case "left":
    case "h":
      if (field.kind === "text") return true;
      cycleField(field, state.config, -1);
      return true;
    case "right":
    case "l":
      if (field.kind === "text") return true;
      cycleField(field, state.config, 1);
      return true;
    case "space":
      if (field.kind === "toggle") cycleField(field, state.config, 1);
      else if (field.kind === "cycle" || field.kind === "number") cycleField(field, state.config, 1);
      return true;
    case "enter":
      if (field.kind === "text" || field.kind === "number") {
        b.editing = true;
        b.editor.set(fieldValue(field, state.config));
      } else cycleField(field, state.config, 1);
      return true;
    case "backspace":
      if (field.kind === "text") field.set(state.config, "");
      else if (field.kind === "number") field.set(state.config, "");
      return true;
    case "s":
      ctx.actions.startScan();
      return true;
    case "r":
      selectProfile(state, state.profileIndex);
      ctx.actions.toast(`reset to ${PROFILES[state.profileIndex]?.name}`);
      return true;
    default:
      break;
  }
  return false;
}
