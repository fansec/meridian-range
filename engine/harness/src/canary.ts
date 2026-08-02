/**
 * Benign proof-of-execution canary (SECURITY.md rule 4). Never anything destructive or data-touching.
 *
 * `$$` is left literal so the server-side shell expands it to its own pid, yielding a
 * unique-per-run marker like LAB_CANARY_63.
 *
 * The matching pattern is DERIVED from the same prefix rather than hardcoded. It used to be a literal
 * /LAB_CANARY_\d+/, which meant setting LAB_CANARY_PREFIX (a documented, forwarded knob) silently
 * broke every scenario's proof-of-execution assertion: the attack still landed, but the harness
 * reported NO-REPRO. A false negative in the definition-of-done gate is the worst failure this code
 * can have, so prefix and pattern are now built from one source.
 */
const DEFAULT_PREFIX = "LAB_CANARY";

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** The configured canary prefix (LAB_CANARY_PREFIX, else the default). */
export function canaryPrefix(): string {
  const p = (process.env.LAB_CANARY_PREFIX ?? "").trim();
  return p === "" ? DEFAULT_PREFIX : p;
}

/** The benign command a scenario asks the victim's exec tool to run. */
export function canary(): string {
  return `id; hostname; echo ${canaryPrefix()}_$$`;
}

/** Pattern matching the echoed marker; its presence in tool output is the proof exec happened. */
export function canaryRegex(): RegExp {
  return new RegExp(`${escapeRe(canaryPrefix())}_\\d+`);
}

/** True when `text` contains the proof-of-execution marker. */
export function isCanary(text: string): boolean {
  return canaryRegex().test(text);
}

/** The matched marker (e.g. "LAB_CANARY_66"), or null when the output carries none. */
export function canaryMarker(text: string): string | null {
  return text.match(canaryRegex())?.[0] ?? null;
}
