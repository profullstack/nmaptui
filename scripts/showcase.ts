/**
 * Frames for hqtui.com/apps. The capture script in the hqtui repository
 * imports this file and renders each frame through hqtui's own renderer:
 *
 *   bun apps/web/scripts/app-shots.ts ~/nmaptui
 *
 * The state is the lab fixture the tests use, so the shot is reproducible and
 * shows a real estate: a legacy Windows file server, exposed databases, a
 * switch on telnet.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Container, Theme } from "@profullstack/hqtui";
import { parseXml } from "../src/xml.ts";
import { fromElement } from "../src/model.ts";
import { ScanStore } from "../src/store.ts";
import { Controller } from "../src/ui/controller.ts";
import { renderApp } from "../src/ui/render.ts";
import type { Screen } from "../src/ui/state.ts";

const here = dirname(fileURLToPath(import.meta.url));
const xml = readFileSync(join(here, "..", "test", "fixtures", "estate.xml"), "utf8");

function controllerFor(screen: Screen): Controller {
  const c = new Controller({
    nmap: { path: "nmap", version: "7.98", privileged: true },
    sudo: false,
    store: new ScanStore(join(here, "..", ".showcase-nonexistent")),
  });
  c.setResult(fromElement(parseXml(xml)), xml, "lab 10.0.0.0/28");
  c.state.screen = screen;
  return c;
}

interface DrawArgs {
  ui: Container;
  theme: Theme;
  width: number;
  height: number;
}

function frame(name: string, screen: Screen, width = 150, height = 42) {
  const c = controllerFor(screen);
  return {
    name,
    width,
    height,
    draw: ({ ui, theme, width: w, height: h }: DrawArgs) =>
      renderApp(c.state, ui, { theme, width: w, height: h }, c.actions, c.palette()),
  };
}

export const frames = [frame("nmaptui", "dashboard")];
