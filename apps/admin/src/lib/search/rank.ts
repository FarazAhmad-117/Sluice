/**
 * THE COMMAND PALETTE'S RANKING. Pure.
 *
 * Case-insensitive. A label that IS the query beats one that starts with it,
 * which beats one where a word starts with it (`db` finds `prod-db`, and
 * `url` finds `DATABASE_URL`), which beats one that merely contains it. Ties
 * keep the order the items were given in, so callers decide what comes first
 * among equals (pages before projects before keys).
 */

export interface Searchable {
  readonly label: string;
  /** Other words the item answers to: "keys" for Secrets. Matched one tier lower. */
  readonly keywords?: readonly string[];
}

const EXACT = 0;
const PREFIX = 1;
const WORD = 2;
const SUBSTRING = 3;

/** Word starts: after a space, `-`, `_`, `.`, `/`, or a lower-to-upper case change. */
function wordStarts(text: string): number[] {
  const starts = [0];
  for (let index = 1; index < text.length; index += 1) {
    const before = text[index - 1]!;
    const here = text[index]!;
    if (/[\s\-_./]/.test(before) || (before === before.toLowerCase() && here !== here.toLowerCase())) {
      starts.push(index);
    }
  }
  return starts;
}

/** Lower is better; `null` is no match. */
export function score(query: string, text: string): number | null {
  const needle = query.trim().toLowerCase();
  if (needle === "") return SUBSTRING;
  const haystack = text.toLowerCase();
  if (haystack === needle) return EXACT;
  if (haystack.startsWith(needle)) return PREFIX;
  if (wordStarts(text).some((start) => haystack.startsWith(needle, start))) return WORD;
  if (haystack.includes(needle)) return SUBSTRING;
  return null;
}

function best(query: string, item: Searchable): number | null {
  let result = score(query, item.label);
  for (const keyword of item.keywords ?? []) {
    const keywordScore = score(query, keyword);
    if (keywordScore === null) continue;
    // A keyword hit ranks just below the same hit on the label.
    const adjusted = keywordScore + 0.5;
    if (result === null || adjusted < result) result = adjusted;
  }
  return result;
}

/** The matches, best first, stable among equals. An empty query matches everything, in order. */
export function rank<T extends Searchable>(items: readonly T[], query: string): T[] {
  return items
    .map((item, index) => ({ item, index, score: best(query, item) }))
    .filter((entry): entry is { item: T; index: number; score: number } => entry.score !== null)
    .sort((a, b) => a.score - b.score || a.index - b.index)
    .map((entry) => entry.item);
}
