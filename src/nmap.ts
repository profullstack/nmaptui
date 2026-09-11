/**
 * Running nmap. The scan writes XML to stdout with `-v --stats-every`, which
 * makes nmap flush task begin/end, progress and each finished host as it
 * goes; `XmlStream` turns that into events while the scan is still running.
 */
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { XmlStream } from "./xml.ts";
import { applyElement, applyRoot, emptyResult, type ScanResult, type Host, type TaskEvent } from "./model.ts";
import { toArgs, needsRoot, type ScanConfig } from "./profiles.ts";

export interface NmapInfo {
  path: string;
  version: string;
  /** Effective user is root, so raw-socket scans will work. */
  privileged: boolean;
}

export function isPrivileged(): boolean {
  const getuid = (process as NodeJS.Process & { getuid?: () => number }).getuid;
  return typeof getuid === "function" ? getuid.call(process) === 0 : false;
}

/** Find nmap and its version, or null when it is not installed. */
export function detectNmap(program = "nmap"): NmapInfo | null {
  const res = spawnSync(program, ["--version"], { encoding: "utf8" });
  if (res.error || res.status !== 0) return null;
  const m = /Nmap version (\S+)/.exec(res.stdout);
  return { path: program, version: m?.[1] ?? "unknown", privileged: isPrivileged() };
}

/** Can `sudo -n` run nmap without a password right now? */
export function sudoAvailable(program = "nmap"): boolean {
  const res = spawnSync("sudo", ["-n", program, "--version"], { encoding: "utf8" });
  return !res.error && res.status === 0;
}

export interface RunHandlers {
  onStart?: (command: string[]) => void;
  onHost?: (host: Host, result: ScanResult) => void;
  onTask?: (task: TaskEvent, result: ScanResult) => void;
  onStderr?: (line: string) => void;
  onDone?: (result: ScanResult, xml: string, code: number | null) => void;
  onError?: (error: Error) => void;
}

export interface RunOptions {
  program?: string;
  /** Prefix with `sudo -n`. */
  sudo?: boolean;
  statsEvery?: string;
  env?: NodeJS.ProcessEnv;
}

export interface RunningScan {
  command: string[];
  result: ScanResult;
  startedAt: number;
  /** Raw XML received so far. */
  xml(): string;
  abort(): void;
  done: Promise<{ result: ScanResult; xml: string; code: number | null }>;
  aborted: boolean;
}

/** The full argv nmaptui passes, including its own output flags. */
export function fullCommand(config: ScanConfig, options: RunOptions = {}): string[] {
  const program = options.program ?? "nmap";
  const args = [program, "-v", "--stats-every", options.statsEvery ?? "1s", "-oX", "-", ...toArgs(config)];
  return options.sudo ? ["sudo", "-n", ...args] : args;
}

export function runScan(config: ScanConfig, handlers: RunHandlers = {}, options: RunOptions = {}): RunningScan {
  const command = fullCommand(config, options);
  const result = emptyResult();
  const chunks: string[] = [];
  let child: ChildProcess;
  let aborted = false;
  let stderrTail = "";

  const stream = new XmlStream({
    onRoot: (_name, attrs) => applyRoot(result, attrs),
    onElement: (el) => {
      const kind = applyElement(result, el);
      if (kind === "host") {
        const host = result.hosts[result.hosts.length - 1];
        if (host) handlers.onHost?.(host, result);
      } else if (kind === "task") {
        const task = result.tasks[result.tasks.length - 1];
        if (task) handlers.onTask?.(task, result);
      }
    },
  });

  const done = new Promise<{ result: ScanResult; xml: string; code: number | null }>((resolve) => {
    handlers.onStart?.(command);
    try {
      child = spawn(command[0] as string, command.slice(1), { stdio: ["ignore", "pipe", "pipe"], env: options.env ?? process.env });
    } catch (error) {
      handlers.onError?.(error as Error);
      resolve({ result, xml: "", code: null });
      return;
    }
    child.on("error", (error) => {
      handlers.onError?.(error);
      resolve({ result, xml: chunks.join(""), code: null });
    });
    child.stdout?.setEncoding("utf8");
    child.stdout?.on("data", (data: string) => {
      chunks.push(data);
      try {
        stream.write(data);
      } catch (error) {
        handlers.onError?.(error as Error);
      }
    });
    child.stderr?.setEncoding("utf8");
    child.stderr?.on("data", (data: string) => {
      stderrTail += data;
      const lines = stderrTail.split(/\r?\n/);
      stderrTail = lines.pop() ?? "";
      for (const line of lines) if (line.trim()) handlers.onStderr?.(line);
    });
    child.on("close", (code) => {
      if (stderrTail.trim()) handlers.onStderr?.(stderrTail);
      const xml = chunks.join("");
      handlers.onDone?.(result, xml, code);
      resolve({ result, xml, code });
    });
  });

  return {
    command,
    result,
    startedAt: Date.now(),
    xml: () => chunks.join(""),
    abort: () => {
      aborted = true;
      child?.kill("SIGTERM");
      setTimeout(() => child?.kill("SIGKILL"), 2000).unref();
    },
    done,
    get aborted() {
      return aborted;
    },
  };
}

/** Why a configuration cannot run as this user, or null when it can. */
export function privilegeProblem(config: ScanConfig, info: NmapInfo | null, sudo: boolean): string | null {
  if (!info) return "nmap is not installed or not on PATH";
  if (!needsRoot(config) || info.privileged || sudo) return null;
  return "this scan needs raw sockets: run as root, pass --sudo, or switch to the TCP connect technique";
}
