/**
 * A small XML reader, enough for nmap's output and nothing more. Two entry
 * points: `parseXml` for a whole document, and `XmlStream` for the bytes nmap
 * writes while a scan is still running, which hands over each complete child
 * of the root element as soon as its closing tag has arrived.
 *
 * No namespaces, no DTD processing, no CDATA merging beyond the literal text.
 * nmap does not use any of those.
 */

export interface XmlElement {
  name: string;
  attrs: Record<string, string>;
  children: XmlElement[];
  /** Concatenated character data directly inside this element. */
  text: string;
}

const ENTITIES: Record<string, string> = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" };

export function decodeEntities(value: string): string {
  if (value.indexOf("&") === -1) return value;
  return value.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);/g, (whole, body: string) => {
    if (body[0] === "#") {
      const code = body[1] === "x" || body[1] === "X" ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      return Number.isFinite(code) ? String.fromCodePoint(code) : whole;
    }
    return ENTITIES[body] ?? whole;
  });
}

export function element(name: string, attrs: Record<string, string> = {}, children: XmlElement[] = [], text = ""): XmlElement {
  return { name, attrs, children, text };
}

/** First child with this name, or undefined. */
export function child(el: XmlElement | undefined, name: string): XmlElement | undefined {
  return el?.children.find((c) => c.name === name);
}

/** Every child with this name. */
export function children(el: XmlElement | undefined, name: string): XmlElement[] {
  return el ? el.children.filter((c) => c.name === name) : [];
}

export function attr(el: XmlElement | undefined, name: string): string | undefined {
  return el?.attrs[name];
}

export function numAttr(el: XmlElement | undefined, name: string): number | undefined {
  const raw = el?.attrs[name];
  if (raw === undefined || raw === "") return undefined;
  const n = Number(raw);
  return Number.isFinite(n) ? n : undefined;
}

class XmlError extends Error {}

const NAME_END = /[\s/>]/;

interface Tag {
  kind: "open" | "close" | "empty" | "skip";
  name: string;
  attrs: Record<string, string>;
  /** Index just past the tag. */
  end: number;
}

/**
 * Read the tag starting at `start` (which must point at `<`). Returns null if
 * the tag is not complete within the text yet, which is how the stream knows
 * to wait for more bytes.
 */
function readTag(text: string, start: number): Tag | null {
  const empty: Record<string, string> = {};
  if (text.startsWith("<!--", start)) {
    const end = text.indexOf("-->", start + 4);
    return end === -1 ? null : { kind: "skip", name: "", attrs: empty, end: end + 3 };
  }
  if (text.startsWith("<![CDATA[", start)) {
    const end = text.indexOf("]]>", start + 9);
    return end === -1 ? null : { kind: "skip", name: "", attrs: empty, end: end + 3 };
  }
  if (text.startsWith("<?", start)) {
    const end = text.indexOf("?>", start + 2);
    return end === -1 ? null : { kind: "skip", name: "", attrs: empty, end: end + 2 };
  }
  if (text.startsWith("<!", start)) {
    // DOCTYPE, possibly with an internal subset in brackets.
    let depth = 0;
    for (let i = start + 2; i < text.length; i++) {
      const c = text[i];
      if (c === "[") depth++;
      else if (c === "]") depth--;
      else if (c === ">" && depth <= 0) return { kind: "skip", name: "", attrs: empty, end: i + 1 };
    }
    return null;
  }

  let i = start + 1;
  let kind: Tag["kind"] = "open";
  if (text[i] === "/") {
    kind = "close";
    i++;
  }
  const nameStart = i;
  while (i < text.length && !NAME_END.test(text[i] as string)) i++;
  if (i >= text.length) return null;
  const name = text.slice(nameStart, i);
  if (name.length === 0) throw new XmlError(`Empty tag name at offset ${start}`);

  const attrs: Record<string, string> = {};
  for (;;) {
    while (i < text.length && /\s/.test(text[i] as string)) i++;
    if (i >= text.length) return null;
    const c = text[i] as string;
    if (c === ">") return { kind, name, attrs, end: i + 1 };
    if (c === "/") {
      if (text[i + 1] === undefined) return null;
      if (text[i + 1] !== ">") throw new XmlError(`Expected '>' after '/' in <${name}>`);
      return { kind: kind === "close" ? "close" : "empty", name, attrs, end: i + 2 };
    }
    // attribute
    const keyStart = i;
    while (i < text.length && !/[\s=/>]/.test(text[i] as string)) i++;
    if (i >= text.length) return null;
    const key = text.slice(keyStart, i);
    while (i < text.length && /\s/.test(text[i] as string)) i++;
    if (i >= text.length) return null;
    if (text[i] !== "=") {
      // Attribute without a value (not valid XML, but be forgiving).
      attrs[key] = "";
      continue;
    }
    i++;
    while (i < text.length && /\s/.test(text[i] as string)) i++;
    if (i >= text.length) return null;
    const quote = text[i] as string;
    if (quote !== '"' && quote !== "'") throw new XmlError(`Unquoted attribute ${key} in <${name}>`);
    const valueEnd = text.indexOf(quote, i + 1);
    if (valueEnd === -1) return null;
    attrs[key] = decodeEntities(text.slice(i + 1, valueEnd));
    i = valueEnd + 1;
  }
}

/**
 * Parse one complete element starting at `start`. Returns the element and
 * the index just past its closing tag, or null when the text ends first.
 */
function parseElementAt(text: string, start: number): { el: XmlElement; end: number } | null {
  const root = readTag(text, start);
  if (!root) return null;
  if (root.kind === "skip") throw new XmlError("Expected an element");
  if (root.kind === "close") throw new XmlError(`Unexpected closing tag </${root.name}>`);
  const top = element(root.name, root.attrs);
  if (root.kind === "empty") return { el: top, end: root.end };

  const stack: XmlElement[] = [top];
  let i = root.end;
  while (stack.length > 0) {
    const lt = text.indexOf("<", i);
    if (lt === -1) return null;
    const current = stack[stack.length - 1] as XmlElement;
    if (lt > i) current.text += decodeEntities(text.slice(i, lt));
    if (text.startsWith("<![CDATA[", lt)) {
      const end = text.indexOf("]]>", lt + 9);
      if (end === -1) return null;
      current.text += text.slice(lt + 9, end);
      i = end + 3;
      continue;
    }
    const tag = readTag(text, lt);
    if (!tag) return null;
    i = tag.end;
    if (tag.kind === "skip") continue;
    if (tag.kind === "close") {
      if (tag.name !== current.name) throw new XmlError(`Mismatched </${tag.name}>, expected </${current.name}>`);
      stack.pop();
      continue;
    }
    const el = element(tag.name, tag.attrs);
    current.children.push(el);
    if (tag.kind === "open") stack.push(el);
  }
  return { el: top, end: i };
}

/** Parse a whole document and return its root element. */
export function parseXml(text: string): XmlElement {
  let i = 0;
  for (;;) {
    const lt = text.indexOf("<", i);
    if (lt === -1) throw new XmlError("No root element");
    if (text.startsWith("<?", lt) || text.startsWith("<!", lt)) {
      const tag = readTag(text, lt);
      if (!tag) throw new XmlError("Unterminated prolog");
      i = tag.end;
      continue;
    }
    const parsed = parseElementAt(text, lt);
    if (!parsed) throw new XmlError("Unterminated root element");
    return parsed.el;
  }
}

/**
 * Feed nmap's XML as it arrives. `onRoot` fires once with the root tag's
 * attributes; `onElement` fires for each completed direct child of the root.
 * When the closing root tag arrives `onEnd` fires. An nmap that is killed
 * never writes `</nmaprun>`, and that is fine: everything delivered so far
 * stays delivered, and `partial()` says whether the document was cut short.
 */
export class XmlStream {
  private buffer = "";
  private rootSeen = false;
  private ended = false;
  rootName = "";
  rootAttrs: Record<string, string> = {};
  /** Elements delivered so far, in order. */
  readonly elements: XmlElement[] = [];

  private handlers: {
    onRoot?: (name: string, attrs: Record<string, string>) => void;
    onElement?: (el: XmlElement) => void;
    onEnd?: () => void;
  };

  constructor(handlers: XmlStream["handlers"] = {}) {
    this.handlers = handlers;
  }

  get done(): boolean {
    return this.ended;
  }

  partial(): boolean {
    return !this.ended;
  }

  write(chunk: string): void {
    if (this.ended) return;
    this.buffer += chunk;
    this.drain();
  }

  /** Parse whatever is complete and drop it from the buffer. */
  private drain(): void {
    for (;;) {
      const lt = this.buffer.indexOf("<");
      if (lt === -1) {
        this.buffer = "";
        return;
      }
      if (!this.rootSeen) {
        const tag = readTag(this.buffer, lt);
        if (!tag) return;
        if (tag.kind === "skip") {
          this.buffer = this.buffer.slice(tag.end);
          continue;
        }
        if (tag.kind !== "open") throw new XmlError("Document does not start with an element");
        this.rootSeen = true;
        this.rootName = tag.name;
        this.rootAttrs = tag.attrs;
        this.buffer = this.buffer.slice(tag.end);
        this.handlers.onRoot?.(tag.name, tag.attrs);
        continue;
      }
      // Inside the root: either a child element, a comment, or the closing tag.
      if (this.buffer.startsWith("</", lt)) {
        const tag = readTag(this.buffer, lt);
        if (!tag) return;
        this.ended = true;
        this.buffer = "";
        this.handlers.onEnd?.();
        return;
      }
      if (this.buffer.startsWith("<!", lt) || this.buffer.startsWith("<?", lt)) {
        const tag = readTag(this.buffer, lt);
        if (!tag) return;
        this.buffer = this.buffer.slice(tag.end);
        continue;
      }
      const parsed = parseElementAt(this.buffer, lt);
      if (!parsed) return;
      this.buffer = this.buffer.slice(parsed.end);
      this.elements.push(parsed.el);
      this.handlers.onElement?.(parsed.el);
    }
  }
}
