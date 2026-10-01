/**
 * A .ENV FILE, PARSED IN THE BROWSER FOR IMPORT.
 *
 * The file never leaves this tab: each entry is sealed under an environment
 * key before anything is sent. So the parser's one security rule is about its
 * OUTPUT: no error message ever repeats a value, or any part of a line that
 * might be one. Errors name a line number and, only when it is a valid
 * variable name, the name. A malformed name is not echoed either, because a
 * line that failed to parse may be a pasted value with no `=` in front of it.
 *
 * The dialect is the common subset of dotenv implementations:
 *   - `\n` and `\r\n` line endings; blank lines and `#` comment lines skipped;
 *   - an optional leading `export `;
 *   - NAME is `[A-Za-z_][A-Za-z0-9_]*`, the value is everything after the
 *     first `=`, trimmed;
 *   - "double quoted" values keep `#` and decode `\n`, `\"` and `\\`;
 *   - 'single quoted' values are literal;
 *   - unquoted values end at whitespace followed by `#` (an inline comment);
 *   - a later duplicate replaces the earlier entry, and says so.
 * Multi-line quoted values are not supported; an unterminated quote is an
 * error on its line.
 */

export interface DotenvEntry {
  readonly name: string;
  readonly value: string;
  readonly line: number;
}

export interface DotenvResult {
  readonly entries: DotenvEntry[];
  readonly errors: { line: number; message: string }[];
}

/** More than any real .env holds; enough to stop a pasted log becoming a thousand writes. */
export const MAX_DOTENV_ENTRIES = 1000;

const NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

const BAD_NAME =
  "This line's name is not a valid variable name: use letters, digits and underscores, not starting with a digit.";
const NO_EQUALS = "This line is not NAME=value.";
const UNTERMINATED = "This line's value has an opening quote and no closing quote.";
const AFTER_QUOTE = "This line has text after its closing quote.";
const TOO_MANY = `Only the first ${MAX_DOTENV_ENTRIES.toLocaleString("en-US")} entries are imported.`;

/** The value part of one line, decoded, or the reason it could not be. */
function parseValue(raw: string): { value: string } | { error: string } {
  const quote = raw[0];
  if (quote === '"' || quote === "'") {
    let value = "";
    let index = 1;
    for (; index < raw.length; index += 1) {
      const char = raw[index]!;
      if (char === quote) break;
      if (quote === '"' && char === "\\" && index + 1 < raw.length) {
        const next = raw[index + 1]!;
        if (next === "n") value += "\n";
        else if (next === '"' || next === "\\") value += next;
        // An escape this dialect does not define is kept as written.
        else value += char + next;
        index += 1;
        continue;
      }
      value += char;
    }
    if (index >= raw.length) return { error: UNTERMINATED };
    const rest = raw.slice(index + 1).trim();
    if (rest !== "" && !rest.startsWith("#")) return { error: AFTER_QUOTE };
    return { value };
  }
  const comment = raw.search(/\s#/);
  return { value: (comment === -1 ? raw : raw.slice(0, comment)).trim() };
}

export function parseDotenv(text: string): DotenvResult {
  const entries: DotenvEntry[] = [];
  const errors: { line: number; message: string }[] = [];
  const byName = new Map<string, number>();

  const lines = text.replace(/^﻿/, "").split(/\r?\n/);
  for (const [index, rawLine] of lines.entries()) {
    const line = index + 1;
    let body = rawLine.trim();
    if (body === "" || body.startsWith("#")) continue;
    if (body.startsWith("export ")) body = body.slice("export ".length).trimStart();

    const equals = body.indexOf("=");
    if (equals === -1) {
      errors.push({ line, message: NO_EQUALS });
      continue;
    }
    const name = body.slice(0, equals).trim();
    if (!NAME.test(name)) {
      errors.push({ line, message: BAD_NAME });
      continue;
    }
    const parsed = parseValue(body.slice(equals + 1).trim());
    if ("error" in parsed) {
      errors.push({ line, message: parsed.error });
      continue;
    }

    const existing = byName.get(name);
    if (existing !== undefined) {
      entries[existing] = { name, value: parsed.value, line };
      errors.push({ line, message: `${name} is set twice; the later value is used` });
      continue;
    }
    if (entries.length >= MAX_DOTENV_ENTRIES) {
      errors.push({ line, message: TOO_MANY });
      break;
    }
    byName.set(name, entries.length);
    entries.push({ name, value: parsed.value, line });
  }

  return { entries, errors };
}
