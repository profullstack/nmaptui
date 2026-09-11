/**
 * A one-line text editor with a cursor, for the target field, filters and
 * the export path. Pure: feed it key events, read `value` and `cursor`.
 */
import type { KeyEvent } from "@profullstack/hqtui";

export class LineEditor {
  value: string;
  cursor: number;

  constructor(value = "") {
    this.value = value;
    this.cursor = value.length;
  }

  set(value: string): void {
    this.value = value;
    this.cursor = value.length;
  }

  insert(text: string): void {
    this.value = this.value.slice(0, this.cursor) + text + this.value.slice(this.cursor);
    this.cursor += text.length;
  }

  backspace(): void {
    if (this.cursor === 0) return;
    this.value = this.value.slice(0, this.cursor - 1) + this.value.slice(this.cursor);
    this.cursor--;
  }

  delete(): void {
    this.value = this.value.slice(0, this.cursor) + this.value.slice(this.cursor + 1);
  }

  killWord(): void {
    const before = this.value.slice(0, this.cursor).replace(/\S+\s*$/, "");
    this.value = before + this.value.slice(this.cursor);
    this.cursor = before.length;
  }

  killToStart(): void {
    this.value = this.value.slice(this.cursor);
    this.cursor = 0;
  }

  killToEnd(): void {
    this.value = this.value.slice(0, this.cursor);
  }

  /** Apply an editing key. Returns false for keys the editor does not own. */
  handle(event: KeyEvent): boolean {
    const { name, key, char } = event;
    switch (key) {
      case "left":
        this.cursor = Math.max(0, this.cursor - 1);
        return true;
      case "right":
        this.cursor = Math.min(this.value.length, this.cursor + 1);
        return true;
      case "home":
      case "ctrl+a":
        this.cursor = 0;
        return true;
      case "end":
      case "ctrl+e":
        this.cursor = this.value.length;
        return true;
      case "backspace":
      case "ctrl+h":
        this.backspace();
        return true;
      case "delete":
      case "ctrl+d":
        this.delete();
        return true;
      case "ctrl+w":
      case "alt+backspace":
        this.killWord();
        return true;
      case "ctrl+u":
        this.killToStart();
        return true;
      case "ctrl+k":
        this.killToEnd();
        return true;
      default:
        break;
    }
    if (name === "space" && !event.ctrl && !event.alt) {
      this.insert(" ");
      return true;
    }
    if (char && !event.ctrl && !event.alt && char.length > 0 && char >= " ") {
      this.insert(char);
      return true;
    }
    return false;
  }
}
