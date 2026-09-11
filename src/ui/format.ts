/** Small shared drawing helpers: colours for states and severities, bars. */
import type { Color, Theme } from "@profullstack/hqtui";
import type { Severity } from "../analysis.ts";

export function stateColor(theme: Theme, state: string): Color {
  if (state === "open" || state === "up") return theme.success;
  if (state === "closed" || state === "down") return theme.muted;
  if (state.includes("filtered")) return theme.warning;
  return theme.foreground;
}

export function severityColor(theme: Theme, severity: Severity): Color {
  switch (severity) {
    case "critical":
      return theme.danger;
    case "high":
      return theme.warning;
    case "medium":
      return theme.accent;
    case "low":
      return theme.primary;
    default:
      return theme.muted;
  }
}

export function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n));
}

/** Move a selection by `delta` inside a list of `total`, wrapping never. */
export function move(selected: number, delta: number, total: number): number {
  if (total <= 0) return 0;
  return clamp(selected + delta, 0, total - 1);
}

export function elide(text: string, width: number): string {
  if (width <= 0) return "";
  if (text.length <= width) return text;
  if (width <= 1) return "…";
  return text.slice(0, width - 1) + "…";
}

export function pct(n: number, of: number): string {
  if (of <= 0) return "0%";
  return `${Math.round((n / of) * 100)}%`;
}

export function ago(ms: number): string {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export function dateStamp(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number): string => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
