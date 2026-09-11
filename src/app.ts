/**
 * Wire the controller to an hqtui app and run it.
 */
import { createApp } from "@profullstack/hqtui";
import { detectNmap, sudoAvailable } from "./nmap.ts";
import type { ScanConfig } from "./profiles.ts";
import { ScanStore } from "./store.ts";
import { Controller } from "./ui/controller.ts";
import { renderApp } from "./ui/render.ts";

export interface AppOptions {
  targets?: string[];
  profile?: string;
  /** Overrides applied to the builder config. */
  config?: Partial<ScanConfig>;
  /** Open this XML file on start. */
  open?: string;
  /** Diff these two files on start. */
  diff?: [string, string];
  theme?: string;
  mouse?: boolean;
  sudo?: boolean;
  nmapPath?: string;
  dataDir?: string;
  /** Start the scan immediately, no builder stop. */
  autostart?: boolean;
  collapseBorders?: boolean;
}

export async function run(options: AppOptions = {}): Promise<void> {
  const program = options.nmapPath ?? "nmap";
  const nmap = detectNmap(program);
  let sudo = options.sudo ?? false;
  if (sudo && nmap && !nmap.privileged && !sudoAvailable(program)) {
    throw new Error("--sudo was given but `sudo -n nmap` fails. Run `sudo -v` first, or start nmaptui with sudo.");
  }
  if (nmap?.privileged) sudo = false;

  const store = new ScanStore(options.dataDir);
  const controller = new Controller({ nmap, sudo, store, program, theme: options.theme });

  if (options.profile && !controller.useProfile(options.profile)) throw new Error(`unknown profile: ${options.profile}`);
  if (options.targets && options.targets.length > 0) controller.state.config.targets = options.targets.join(" ");
  if (options.config) Object.assign(controller.state.config, options.config);
  if (options.open) controller.loadFile(options.open);
  if (options.diff) {
    const { loadXmlFile } = await import("./store.ts");
    const a = loadXmlFile(options.diff[0]);
    const b = loadXmlFile(options.diff[1]);
    controller.setDiff(a.result, b.result, options.diff[0], options.diff[1]);
    controller.setResult(b.result, b.xml, options.diff[1]);
    controller.state.screen = "diff";
  } else if (options.targets && options.targets.length > 0) {
    controller.state.screen = "scan";
  } else if (!options.open) {
    controller.state.screen = controller.state.history.records.length > 0 ? "dashboard" : "scan";
  }

  const app = await createApp({
    theme: options.theme,
    mouse: options.mouse !== false,
    quitKeys: ["ctrl+c"],
    focusNavigation: false,
    collapseBorders: options.collapseBorders ?? false,
    title: "nmaptui",
  });
  controller.state.collapse = options.collapseBorders ?? false;
  controller.host = {
    invalidate: () => app.invalidate(),
    redraw: () => app.redraw(),
    stop: () => app.stop(),
    setTheme: (name) => app.setTheme(name),
    setCollapseBorders: (value) => app.setCollapseBorders(value),
  };

  app.render(({ ui, theme, width, height }) => renderApp(controller.state, ui, { theme, width, height }, controller.actions, controller.palette()));
  app.on("key", (event) => {
    if (event.key === "ctrl+c") return;
    controller.handleKey(event);
  });
  app.on("exit", () => {
    controller.state.running?.abort();
  });

  if (options.autostart) controller.startScan();
  await app.start();
}
