/**
 * RunReport - turns a scenario run into a presentation-grade evidence package.
 *
 * The old harness printed a single PASS/FAIL summary line. That reads like an internal validation log.
 * This reporter instead produces the output a security-research writeup wants, all on stdout so a
 * `docker compose run --rm harness` capture is self-contained and a screen recording is self-explanatory:
 *
 *   - live, structured step lines  ([INFO ] / [STEP ] / [PASS ] / [FAIL ])   - item #10, #13
 *   - a RESULT block               (vulnerability / status / confidence)      - item #10
 *   - an EVIDENCE list of observed facts, kept separate from the CONCLUSION   - item #2
 *   - a chronological EVIDENCE TIMELINE built from timestamped events         - item #3
 *   - a RAW HTTP EVIDENCE transcript (request + response + SSE frames)        - item #4
 *   - an IOC SUMMARY (endpoints, headers, session id redacted, detections)    - item #11
 *
 * Nothing here computes a verdict the target itself reported; every line is an observation the client
 * made on the wire, or a conclusion this reporter draws FROM those observations. Timestamps are real
 * (they are evidence of chronology); the step structure is deterministic (same steps, same order,
 * every run) so the output is stable enough to record without narration.
 */

/** A structured record of one thing that happened on the wire, in order. */
type WireEntry =
  | { kind: "note"; text: string }
  | { kind: "request"; method: string; url: string; headers: Record<string, string>; body?: string }
  | { kind: "response"; status: number; headers: Record<string, string>; note?: string }
  | { kind: "sse"; event: string; data: string }
  | { kind: "rpc"; dir: "out" | "in"; text: string };

/** The subset of RunReport the SSE client records against (keeps the client decoupled from the report). */
export interface WireRecorder {
  request(method: string, url: string, headers: Record<string, string>, body?: string): void;
  response(status: number, headers: Record<string, string>, note?: string): void;
  sse(event: string, data: string): void;
  rpc(dir: "out" | "in", payload: unknown): void;
}

type Level = "INFO" | "STEP" | "PASS" | "FAIL" | "WARN";

type TimelineRow = { rel: number; clock: string; level: Level; msg: string };

export type ReportMeta = {
  module: string; // the module directory, e.g. "01-cors-session-hijack"
  title: string; // human title
  cve: string; // anchoring CVE id
  cwe: string; // primary CWE
  target: string; // the victim MCP server base url
  /**
   * Where the attacker is standing, phrased for the attack at hand: a forged browser Origin for a
   * cross-origin read, a forged Host for a rebound name. Not every transport attack has an Origin,
   * so this is a label rather than a header value.
   */
  attacker: string;
};

/** Attacker/environment indicators the report summarises as an IR-style artifact (item #11). */
export type Iocs = {
  endpoints: string[];
  methods: string[];
  headers: Record<string, string>;
  userAgent: string;
  sessionId: string | null;
  tools: string[];
  sourceHint: string;
  collector: string;
  detections: string[];
};

const PAD: Record<Level, string> = { INFO: "INFO ", STEP: "STEP ", PASS: "PASS ", FAIL: "FAIL ", WARN: "WARN " };

function two(n: number): string {
  return n < 10 ? "0" + n : String(n);
}

/** HH:MM:SS.mmm in UTC - stable across machines, and it is what a SOC timeline uses. */
function clockOf(d: Date): string {
  return `${two(d.getUTCHours())}:${two(d.getUTCMinutes())}:${two(d.getUTCSeconds())}.${String(d.getUTCMilliseconds()).padStart(3, "0")}`;
}

/** Show enough of a session id to correlate, but not the whole ephemeral secret (item #11). */
export function redactSession(id: string | null): string {
  if (!id) return "(none)";
  return id.length <= 10 ? id : `${id.slice(0, 8)}...${id.slice(-4)}`;
}

export class RunReport implements WireRecorder {
  private readonly t0 = Date.now();
  private readonly startedAt = new Date();
  private readonly timeline: TimelineRow[] = [];
  private readonly facts: string[] = [];
  private readonly wire: WireEntry[] = [];
  private readonly lines: string[] = [];
  private iocs: Iocs | null = null;

  constructor(private readonly meta: ReportMeta) {}

  // ---- lifecycle ---------------------------------------------------------------------------------

  /** Print the report header banner. Call once at the start of the scenario. */
  begin(): void {
    const b = "=".repeat(78);
    this.out(b);
    this.out(`  ${this.meta.cve}  ${this.meta.title}`);
    this.out(`  target ${this.meta.target}   attacker ${this.meta.attacker}`);
    this.out(`  started ${this.startedAt.toISOString()}   canary-only, labnet-internal`);
    this.out(b);
    this.out("");
  }

  // ---- live, structured step lines (item #10) ----------------------------------------------------

  info(msg: string): void {
    this.emit("INFO", msg);
  }
  step(msg: string): void {
    this.emit("STEP", msg);
  }
  /** A confirmed check. Optionally records `fact` in the EVIDENCE list (item #2). */
  pass(msg: string, fact?: string): void {
    this.emit("PASS", msg);
    if (fact) this.facts.push(fact);
  }
  fail(msg: string, fact?: string): void {
    this.emit("FAIL", msg);
    if (fact) this.facts.push(fact);
  }
  warn(msg: string): void {
    this.emit("WARN", msg);
  }
  /** Add an EVIDENCE fact without printing a step line. */
  fact(text: string): void {
    this.facts.push(text);
  }
  /** Add a timeline row without printing a step line (a background event on the wire). */
  mark(msg: string): void {
    this.record("INFO", msg);
  }

  private emit(level: Level, msg: string): void {
    this.record(level, msg);
    this.out(`[${PAD[level]}] ${msg}`);
  }

  private record(level: Level, msg: string): void {
    const now = new Date();
    this.timeline.push({ rel: Date.now() - this.t0, clock: clockOf(now), level, msg });
  }

  // ---- WireRecorder: raw protocol evidence (item #4) ---------------------------------------------

  request(method: string, url: string, headers: Record<string, string>, body?: string): void {
    this.wire.push({ kind: "request", method, url, headers, body });
  }
  response(status: number, headers: Record<string, string>, note?: string): void {
    this.wire.push({ kind: "response", status, headers, note });
  }
  sse(event: string, data: string): void {
    this.wire.push({ kind: "sse", event, data });
  }
  rpc(dir: "out" | "in", payload: unknown): void {
    this.wire.push({ kind: "rpc", dir, text: typeof payload === "string" ? payload : JSON.stringify(payload) });
  }
  /** A human-readable divider inside the transcript (e.g. "Phase 2 - capability invocation"). */
  wireNote(text: string): void {
    this.wire.push({ kind: "note", text });
  }

  setIocs(iocs: Iocs): void {
    this.iocs = iocs;
  }

  // ---- final render (RESULT + appendices) --------------------------------------------------------

  /**
   * Render the full evidence package after the scenario decides `ok`. `conclusion` is the one-line
   * assessment the EVIDENCE supports; `notReproducedWhy` explains a false result.
   */
  render(ok: boolean, opts: { conclusion: string; notReproducedWhy?: string }): void {
    this.section("RESULT");
    this.out(`  Vulnerability : ${this.meta.cve} (${this.meta.cwe})`);
    this.out(`  Scenario      : ${this.meta.module}`);
    this.out(`  Status        : ${ok ? "REPRODUCED" : "NOT REPRODUCED"}`);
    this.out(`  Confidence    : ${ok ? "HIGH" : "N/A"}`);
    this.out(`  Duration      : ${Date.now() - this.t0} ms`);
    if (!ok && opts.notReproducedWhy) this.out(`  Reason        : ${opts.notReproducedWhy}`);

    this.section("EVIDENCE (observed facts)");
    if (this.facts.length === 0) this.out("  (no observations recorded)");
    for (const f of this.facts) this.out(`  - ${f}`);

    this.section("CONCLUSION");
    for (const line of this.wrap(opts.conclusion, 74)) this.out(`  ${line}`);

    this.section("EVIDENCE TIMELINE");
    for (const r of this.timeline) {
      const rel = `+${String(r.rel).padStart(5, " ")}ms`;
      this.out(`  ${r.clock}  ${rel}  ${r.msg}`);
    }

    this.section("RAW HTTP EVIDENCE (replayable protocol capture)");
    this.renderWire();

    if (this.iocs) {
      this.section("IOC SUMMARY (incident-response artifact)");
      this.renderIocs(this.iocs);
    }
    this.out("");
  }

  private renderWire(): void {
    for (const e of this.wire) {
      switch (e.kind) {
        case "note":
          this.out("");
          this.out(`  # ${e.text}`);
          break;
        case "request": {
          const u = new URL(e.url);
          this.out(`  > ${e.method} ${u.pathname}${u.search} HTTP/1.1`);
          this.out(`  > Host: ${u.host}`);
          for (const [k, v] of Object.entries(e.headers)) this.out(`  > ${k}: ${v}`);
          if (e.body) this.out(`  > ${e.body}`);
          break;
        }
        case "response":
          this.out(`  < HTTP/1.1 ${e.status}${e.note ? ` (${e.note})` : ""}`);
          for (const [k, v] of Object.entries(e.headers)) this.out(`  < ${k}: ${v}`);
          break;
        case "sse":
          this.out(`  < [SSE] event: ${e.event}`);
          this.out(`  < [SSE] data: ${e.data}`);
          break;
        case "rpc":
          this.out(`  ${e.dir === "out" ? ">" : "<"} [JSON-RPC ${e.dir === "out" ? "sent" : "recv"}] ${e.text}`);
          break;
      }
    }
  }

  private renderIocs(i: Iocs): void {
    const line = (label: string, val: string) => this.out(`  ${(label + ":").padEnd(16)} ${val}`);
    line("Endpoints", i.endpoints.join("  "));
    line("Methods", i.methods.join(", "));
    for (const [k, v] of Object.entries(i.headers)) line(`Header ${k}`, v);
    line("User-Agent", i.userAgent);
    line("Session id", redactSession(i.sessionId));
    line("Tools driven", i.tools.join(", "));
    line("Source", i.sourceHint);
    line("Exfil sink", i.collector);
    line("Detections", i.detections.join("  "));
  }

  // ---- output helpers ----------------------------------------------------------------------------

  private section(title: string): void {
    this.out("");
    this.out(title);
    this.out("-".repeat(title.length));
  }

  private wrap(text: string, width: number): string[] {
    const words = text.split(/\s+/);
    const lines: string[] = [];
    let cur = "";
    for (const w of words) {
      if ((cur + " " + w).trim().length > width) {
        if (cur) lines.push(cur);
        cur = w;
      } else {
        cur = (cur + " " + w).trim();
      }
    }
    if (cur) lines.push(cur);
    return lines;
  }

  /**
   * Everything the report has printed so far, as one string.
   *
   * The report engine already builds exactly the stream that belongs in evidence/<variant>.txt, so
   * the harness writes that file itself instead of an operator pasting a terminal capture into it by
   * hand and then editing it. See evidence.ts.
   */
  transcript(): string {
    return this.lines.join("\n") + "\n";
  }

  private out(line: string): void {
    // stdout: the whole package is one capturable, recordable stream. The same lines are retained so
    // the run can be written to the module's evidence file without a second rendering path.
    this.lines.push(line);
    console.log(line);
  }
}
