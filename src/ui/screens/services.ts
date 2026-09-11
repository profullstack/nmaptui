/**
 * Services: the scan pivoted by what is listening. The question an admin
 * asks is "where is SSH 7.x still running", not "what does host 42 do".
 */
import type { Container, KeyEvent } from "@profullstack/hqtui";
import { groupServices, type ServiceGroup } from "../../analysis.ts";
import { primaryName, serviceLabel } from "../../model.ts";
import type { Ctx } from "../actions.ts";
import { clamp, move } from "../format.ts";
import type { UiState } from "../state.ts";

export function serviceGroups(state: UiState): ServiceGroup[] {
  return state.result ? groupServices(state.result) : [];
}

export function renderServices(state: UiState, ui: Container, ctx: Ctx): void {
  const { theme } = ctx;
  const s = state.services;
  const groups = serviceGroups(state);
  s.selected = clamp(s.selected, 0, Math.max(0, groups.length - 1));
  const group = groups[s.selected];
  const wide = ctx.width >= 110;

  const listPanel = (c: Container, size?: string | number): void => {
    c.panel({ title: " Services ", size, focused: s.pane === "list", subtitle: `${groups.length} distinct` }, (p) => {
      if (!state.result) {
        p.label("No scan loaded.");
        return;
      }
      if (groups.length === 0) {
        p.label("no open ports in this scan");
        return;
      }
      const max = Math.max(1, ...groups.map((g) => g.hosts.length));
      p.table({
        rows: groups,
        columns: [
          { key: "name", title: "SERVICE", width: 14 },
          { key: "hosts", title: "HOSTS", width: 5, align: "right", render: (g) => String(g.hosts.length) },
          { key: "bar", title: "", width: 12, render: (g) => "█".repeat(Math.max(1, Math.round((g.hosts.length / max) * 12))), color: theme.primary },
          { key: "ports", title: "PORTS", render: (g) => [...g.ports].slice(0, 4).join(" ") + (g.ports.size > 4 ? " …" : "") },
          { key: "top", title: "MOST COMMON", render: (g) => [...g.versions.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "" },
        ],
        selected: s.selected,
        followSelection: true,
        zebra: true,
        scrollbar: true,
        onSelectRow: (row) => {
          s.pane = "list";
          s.selected = clamp(row + s.offset, 0, groups.length - 1);
          s.detailSelected = 0;
        },
        onScroll: (d) => {
          s.selected = move(s.selected, d, groups.length);
          s.detailSelected = 0;
        },
      });
    });
  };

  const detailPanel = (c: Container): void => {
    c.panel({ title: group ? ` ${group.name} ` : " Hosts ", focused: s.pane === "detail", subtitle: group ? `${group.hosts.length} host${group.hosts.length === 1 ? "" : "s"}` : "" }, (p) => {
      if (!group) {
        p.label("select a service");
        return;
      }
      const versions = [...group.versions.entries()].sort((a, b) => b[1] - a[1]);
      const shownVersions = versions.slice(0, 5);
      p.box({ size: shownVersions.length + 1, padding: 0 }, (box) => {
        box.heading("Versions", { size: 1 });
        const maxV = Math.max(1, ...shownVersions.map(([, n]) => n));
        for (const [version, count] of shownVersions) {
          box.meter({ label: version.length > 30 ? version.slice(0, 29) + "…" : version, value: count, max: maxV, text: `${count}`, labelWidth: 31, valueWidth: 4, color: theme.secondary, style: "smooth" });
        }
      });
      p.divider();
      s.detailSelected = clamp(s.detailSelected, 0, Math.max(0, group.hosts.length - 1));
      p.table({
        rows: group.hosts,
        columns: [
          { key: "host", title: "HOST", width: 16, render: (r) => r.host.addr },
          { key: "name", title: "NAME", width: 18, render: (r) => primaryName(r.host) },
          { key: "port", title: "PORT", width: 9, render: (r) => `${r.port.port}/${r.port.protocol}` },
          { key: "version", title: "VERSION", render: (r) => serviceLabel(r.port) || "(no banner)" },
        ],
        selected: s.pane === "detail" ? s.detailSelected : -1,
        followSelection: true,
        zebra: true,
        scrollbar: true,
        onSelectRow: (row) => {
          s.pane = "detail";
          s.detailSelected = clamp(row, 0, group.hosts.length - 1);
        },
        onScroll: (d) => (s.detailSelected = move(s.detailSelected, d, group.hosts.length)),
      });
    });
  };

  if (wide) {
    ui.row({}, (row) => {
      listPanel(row, "50%");
      detailPanel(row);
    });
  } else {
    ui.column({}, (col) => {
      listPanel(col, "50%");
      detailPanel(col);
    });
  }
}

export function handleServicesKey(state: UiState, event: KeyEvent, ctx: Ctx): boolean {
  const s = state.services;
  const groups = serviceGroups(state);
  const group = groups[s.selected];
  const step = (d: number): void => {
    if (s.pane === "detail" && group) s.detailSelected = move(s.detailSelected, d, group.hosts.length);
    else {
      s.selected = move(s.selected, d, groups.length);
      s.detailSelected = 0;
    }
  };
  switch (event.key) {
    case "up":
    case "k":
      step(-1);
      return true;
    case "down":
    case "j":
      step(1);
      return true;
    case "pageup":
      step(-10);
      return true;
    case "pagedown":
      step(10);
      return true;
    case "g":
    case "home":
      if (s.pane === "detail") s.detailSelected = 0;
      else s.selected = 0;
      return true;
    case "G":
    case "end":
      if (s.pane === "detail") s.detailSelected = Math.max(0, (group?.hosts.length ?? 1) - 1);
      else s.selected = Math.max(0, groups.length - 1);
      return true;
    case "tab":
    case "right":
    case "l":
      s.pane = s.pane === "list" ? "detail" : "list";
      return true;
    case "left":
    case "h":
    case "escape":
      s.pane = "list";
      return true;
    case "enter": {
      // Jump to the host in the Hosts screen.
      const entry = group?.hosts[s.pane === "detail" ? s.detailSelected : 0];
      if (entry) {
        state.hosts.filter = entry.host.addr;
        state.hosts.editor.set(entry.host.addr);
        state.hosts.selected = 0;
        ctx.actions.goto("hosts");
      }
      return true;
    }
    default:
      return false;
  }
}
