import { describe, expect, it } from "vitest";
import { MAX_DOTENV_ENTRIES, parseDotenv } from "../src/lib/dotenv";

/**
 * A .ENV FILE, PARSED FOR IMPORT.
 *
 * The file holds secret values, so the one rule that outranks every other is
 * that no error message ever repeats a value. Several tests below plant a
 * distinctive value on a bad line and assert it appears in no message.
 */

function messages(text: string): string {
  return parseDotenv(text)
    .errors.map((error) => error.message)
    .join("\n");
}

describe("parseDotenv", () => {
  it("reads simple pairs with their line numbers, on \\n and \\r\\n", () => {
    expect(parseDotenv("A=1\nB=2").entries).toEqual([
      { name: "A", value: "1", line: 1 },
      { name: "B", value: "2", line: 2 },
    ]);
    expect(parseDotenv("A=1\r\nB=2\r\n").entries).toEqual([
      { name: "A", value: "1", line: 1 },
      { name: "B", value: "2", line: 2 },
    ]);
  });

  it("skips blank lines and comments without shifting line numbers", () => {
    const result = parseDotenv("# header\n\n   \n  # indented comment\nKEY=v\n");
    expect(result.entries).toEqual([{ name: "KEY", value: "v", line: 5 }]);
    expect(result.errors).toEqual([]);
  });

  it("accepts an optional leading export", () => {
    expect(parseDotenv("export API_KEY=abc").entries).toEqual([
      { name: "API_KEY", value: "abc", line: 1 },
    ]);
  });

  it("trims around the name and the value, and splits on the first = only", () => {
    expect(parseDotenv("  NAME  =  a=b=c  ").entries).toEqual([
      { name: "NAME", value: "a=b=c", line: 1 },
    ]);
    expect(parseDotenv("EMPTY=").entries).toEqual([{ name: "EMPTY", value: "", line: 1 }]);
  });

  it("refuses a bad name without echoing the value", () => {
    const result = parseDotenv("1BAD=hunter2-secret\nGOOD=x\nBAD-NAME=hunter2-secret");
    expect(result.entries).toEqual([{ name: "GOOD", value: "x", line: 2 }]);
    expect(result.errors.map((error) => error.line)).toEqual([1, 3]);
    expect(messages("1BAD=hunter2-secret\nBAD-NAME=hunter2-secret")).not.toContain("hunter2");
  });

  it("refuses a line with no = without echoing it", () => {
    const result = parseDotenv("hunter2-secret");
    expect(result.entries).toEqual([]);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]!.line).toBe(1);
    expect(result.errors[0]!.message).not.toContain("hunter2");
  });

  it("keeps # inside double quotes and decodes \\n, \\\" and \\\\", () => {
    expect(parseDotenv('A="x # not a comment"').entries[0]!.value).toBe("x # not a comment");
    expect(parseDotenv(String.raw`A="line1\nline2"`).entries[0]!.value).toBe("line1\nline2");
    expect(parseDotenv(String.raw`A="say \"hi\""`).entries[0]!.value).toBe('say "hi"');
    expect(parseDotenv(String.raw`A="back\\slash"`).entries[0]!.value).toBe("back\\slash");
    expect(parseDotenv('A="quoted" # trailing comment').entries[0]!.value).toBe("quoted");
  });

  it("takes single-quoted values literally", () => {
    expect(parseDotenv(String.raw`A='x\ny # "z"'`).entries[0]!.value).toBe(
      String.raw`x\ny # "z"`,
    );
  });

  it("refuses an unterminated quote without echoing the value", () => {
    const result = parseDotenv('A="hunter2-secret\nB=\'hunter2-secret');
    expect(result.entries).toEqual([]);
    expect(result.errors.map((error) => error.line)).toEqual([1, 2]);
    expect(messages('A="hunter2-secret\nB=\'hunter2-secret')).not.toContain("hunter2");
  });

  it("ends an unquoted value at an inline comment", () => {
    expect(parseDotenv("A=value # comment").entries[0]!.value).toBe("value");
    // No whitespace before the #: part of the value, as in a URL fragment.
    expect(parseDotenv("A=http://x/#frag").entries[0]!.value).toBe("http://x/#frag");
  });

  it("reads a value that is only a comment as empty", () => {
    expect(parseDotenv("EMPTY= # fill me in").entries[0]!.value).toBe("");
    expect(parseDotenv("EMPTY=\t# fill me in").entries[0]!.value).toBe("");
  });

  it("keeps a # straight after the = as the value", () => {
    // dotenv convention: a comment needs whitespace before it.
    expect(parseDotenv("A=#x").entries[0]!.value).toBe("#x");
  });

  it("refuses text after a closing quote without echoing the value", () => {
    const result = parseDotenv('A="hunter2-secret" hunter2-tail');
    expect(result.entries).toEqual([]);
    expect(result.errors.map((error) => error.line)).toEqual([1]);
    expect(messages('A="hunter2-secret" hunter2-tail')).not.toContain("hunter2");
  });

  it("names a duplicate without echoing either value", () => {
    expect(messages("TOKEN=hunter2-first\nTOKEN=hunter2-second")).not.toContain("hunter2");
  });

  it("keeps the later of two duplicates and says so", () => {
    const result = parseDotenv("A=1\nB=2\nA=3");
    expect(result.entries).toEqual([
      { name: "A", value: "3", line: 3 },
      { name: "B", value: "2", line: 2 },
    ]);
    expect(result.errors).toEqual([
      { line: 3, message: "A is set twice; the later value is used" },
    ]);
  });

  it("stops at the entry limit with an error", () => {
    const lines = Array.from({ length: MAX_DOTENV_ENTRIES + 5 }, (_, i) => `K${i}=v`);
    const result = parseDotenv(lines.join("\n"));
    expect(MAX_DOTENV_ENTRIES).toBe(1000);
    expect(result.entries).toHaveLength(MAX_DOTENV_ENTRIES);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]!.line).toBe(MAX_DOTENV_ENTRIES + 1);
  });

  it("ignores a byte order mark and returns nothing for empty input", () => {
    expect(parseDotenv("\uFEFFA=1").entries).toEqual([{ name: "A", value: "1", line: 1 }]);
    expect(parseDotenv("")).toEqual({ entries: [], errors: [] });
  });
});
