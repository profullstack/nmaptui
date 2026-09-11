/** Dialogs drawn above the screen: help, palette, export, confirm, input, message. */
import type { Container, KeyEvent } from "@profullstack/hqtui";
import { EXPORT_EXTENSIONS, EXPORT_FORMATS, type ExportFormat } from "../report.ts";
import type { Ctx } from "./actions.ts";
import { filterCommands, type Command } from "./commands.ts";
import { clamp } from "./format.ts";
import type { UiState } from "./state.ts";

export const HELP_LINES: [string, string][] = [
  ["1-8  [ ]", "switch screen · previous / next"],
  [": ctrl+p", "command palette"],
  ["?", "this help"],
  ["e", "export the current scan"],
  ["n", "new scan (builder)"],
  ["c  t", "collapse borders · cycle theme"],
  ["q  ctrl+c", "quit"],
  ["", ""],
  ["New scan", ""],
  ["tab", "profiles / options"],
  ["↑↓ j k", "move · enter edits or toggles · ←→ change · space toggle"],
  ["s", "start · r resets to the profile"],
  ["", ""],
  ["Live", ""],
  ["x", "abort · ↑↓ scroll the log · enter open results"],
  ["", ""],
  ["Hosts / Services / Findings", ""],
  ["↑↓ j k", "move · tab or enter switches pane · g G top / bottom"],
  ["/", "filter hosts (address, name, port, service, banner)"],
  ["o  u  S", "open-only · show down hosts · cycle sort"],
  ["f", "minimum severity (Findings)"],
  ["enter", "jump to the host (Services, Findings, Diff)"],
  ["", ""],
  ["History", ""],
  ["enter  m  d", "open · mark · diff the two marked"],
  ["L  i  D  r", "label · import xml · delete · reload"],
];

export function renderOverlay(state: UiState, ui: Container, ctx: Ctx, palette: Command[]): void {
  const o = state.overlay;
  if (!o) return;
  const { theme } = ctx;
  switch (o.kind) {
    case "help": {
      const height = Math.min(ctx.height - 2, HELP_LINES.length + 3);
      ui.modal({ title: " nmaptui keys ", width: Math.min(78, ctx.width - 4), height }, (m) => {
        for (const [keys, text] of HELP_LINES) {
          if (keys === "" && text === "") {
            m.text("", { size: 1 });
            continue;
          }
          if (text === "") {
            m.text([{ text: keys, fg: theme.title, bold: true }], { size: 1 });
            continue;
          }
          m.text([{ text: keys.padEnd(13), fg: theme.accent, bold: true }, { text }], { size: 1 });
        }
      });
      return;
    }
    case "palette": {
      const items = filterCommands(palette, o.editor.value);
      ui.commandPalette({
        query: o.editor.value,
        items: items.map((c) => ({ label: c.label, hint: c.hint })),
        selected: clamp(o.selected, 0, Math.max(0, items.length - 1)),
        width: Math.min(72, ctx.width - 4),
        height: Math.min(ctx.height - 4, items.length + 4),
        placeholder: "type a command…",
      });
      return;
    }
    case "export": {
      ui.modal({ title: " Export ", width: Math.min(76, ctx.width - 4), height: 11 }, (m) => {
        m.text(
          EXPORT_FORMATS.flatMap((f) => [
            f === o.format
              ? { text: ` ${f} `, fg: theme.background, bg: theme.accent, bold: true }
              : { text: ` ${f} `, fg: theme.muted },
            { text: " " },
          ]),
          { size: 1 },
        );
        m.label("←→ format", { size: 1 });
        m.text("", { size: 1 });
        m.textInput({ label: "Path", value: o.editor.value, cursor: o.editor.cursor, focused: true });
        m.text("", { size: 1 });
        if (o.error) m.text([{ text: o.error, fg: theme.danger }], { size: 1, wrap: true });
        else m.label("enter writes the file · esc cancels", { size: 1 });
      });
      return;
    }
    case "confirm": {
      ui.modal({ title: ` ${o.title} `, message: o.message, width: Math.min(60, ctx.width - 4), buttons: [{ label: "Yes  (y)", variant: "danger", focused: true }, { label: "No  (n)" }] });
      return;
    }
    case "input": {
      ui.modal({ title: ` ${o.title} `, width: Math.min(72, ctx.width - 4), height: 8 }, (m) => {
        m.textInput({ value: o.editor.value, cursor: o.editor.cursor, focused: true, placeholder: o.hint });
        m.text("", { size: 1 });
        m.label(o.hint ?? "", { size: 1, wrap: true });
        m.label("enter confirms · esc cancels", { size: 1 });
      });
      return;
    }
    case "message": {
      const height = Math.min(ctx.height - 2, o.lines.length + 4);
      ui.modal({ title: ` ${o.title} `, width: Math.min(100, ctx.width - 4), height }, (m) => {
        const visible = Math.max(1, height - 4);
        const max = Math.max(0, o.lines.length - visible);
        o.scroll = clamp(o.scroll, 0, max);
        for (const line of o.lines.slice(o.scroll, o.scroll + visible)) m.text(line, { size: 1 });
      });
      return;
    }
  }
}

export interface OverlayHandlers {
  performExport(format: ExportFormat, path: string): string | null;
  runCommand(command: Command): void;
}

/** Returns true when the overlay consumed the key. */
export function handleOverlayKey(state: UiState, event: KeyEvent, palette: Command[], handlers: OverlayHandlers): boolean {
  const o = state.overlay;
  if (!o) return false;
  const { key, name } = event;
  switch (o.kind) {
    case "help":
      state.overlay = null;
      return true;
    case "message":
      if (key === "up" || key === "k") o.scroll = Math.max(0, o.scroll - 1);
      else if (key === "down" || key === "j") o.scroll++;
      else if (key === "pagedown" || key === "space") o.scroll += 10;
      else if (key === "pageup") o.scroll = Math.max(0, o.scroll - 10);
      else state.overlay = null;
      return true;
    case "confirm":
      if (key === "y" || name === "enter") {
        state.overlay = null;
        o.onYes();
      } else if (key === "n" || key === "escape" || key === "q") state.overlay = null;
      return true;
    case "input":
      if (key === "escape") state.overlay = null;
      else if (name === "enter") {
        state.overlay = null;
        o.onSubmit(o.editor.value);
      } else o.editor.handle(event);
      return true;
    case "palette": {
      const items = filterCommands(palette, o.editor.value);
      if (key === "escape") state.overlay = null;
      else if (name === "enter") {
        const command = items[clamp(o.selected, 0, Math.max(0, items.length - 1))];
        state.overlay = null;
        if (command) handlers.runCommand(command);
      } else if (key === "up" || key === "ctrl+k" || key === "ctrl+p") o.selected = Math.max(0, o.selected - 1);
      else if (key === "down" || key === "ctrl+j" || key === "ctrl+n" || name === "tab") o.selected = Math.min(Math.max(0, items.length - 1), o.selected + 1);
      else {
        o.editor.handle(event);
        o.selected = 0;
      }
      return true;
    }
    case "export": {
      if (key === "escape") state.overlay = null;
      else if (key === "left" || key === "right" || name === "tab") {
        const i = EXPORT_FORMATS.indexOf(o.format);
        const next = EXPORT_FORMATS[(i + (key === "left" ? -1 : 1) + EXPORT_FORMATS.length) % EXPORT_FORMATS.length] as ExportFormat;
        const oldExt = `.${EXPORT_EXTENSIONS[o.format]}`;
        if (o.editor.value.endsWith(oldExt)) o.editor.set(o.editor.value.slice(0, -oldExt.length) + `.${EXPORT_EXTENSIONS[next]}`);
        o.format = next;
        o.error = undefined;
      } else if (name === "enter") {
        const error = handlers.performExport(o.format, o.editor.value);
        if (error) o.error = error;
        else state.overlay = null;
      } else o.editor.handle(event);
      return true;
    }
  }
}
