/** What a screen may ask the controller to do. Keeps screens free of the app. */
import type { Screen } from "./state.ts";

export interface Actions {
  goto(screen: Screen): void;
  startScan(): void;
  abortScan(): void;
  openRecord(id: string): void;
  deleteRecord(id: string): void;
  relabelRecord(id: string): void;
  importFile(): void;
  diffMarked(): void;
  openExport(): void;
  toast(message: string): void;
  reloadHistory(): void;
  quit(): void;
  invalidate(): void;
}

export interface Ctx {
  theme: import("@profullstack/hqtui").Theme;
  width: number;
  height: number;
  actions: Actions;
}
