import { describe, expect, it } from "vitest";
import { createdLabel, timeAgo } from "../src/lib/format/time";

const NOW = new Date(2026, 9, 2, 15, 0, 0).getTime();
const MIN = 60_000;
const HOUR = 60 * MIN;

describe("timeAgo", () => {
  it("says just now under 45 seconds, and for a time slightly in the future", () => {
    expect(timeAgo(NOW - 10_000, NOW)).toBe("just now");
    expect(timeAgo(NOW + 5_000, NOW)).toBe("just now");
  });
  it("counts minutes, singular and plural", () => {
    expect(timeAgo(NOW - MIN, NOW)).toBe("1 minute ago");
    expect(timeAgo(NOW - 9 * MIN, NOW)).toBe("9 minutes ago");
  });
  it("counts hours on the same day", () => {
    expect(timeAgo(NOW - HOUR, NOW)).toBe("1 hour ago");
    expect(timeAgo(NOW - 3 * HOUR, NOW)).toBe("3 hours ago");
  });
  it("says yesterday, then days, then a date", () => {
    expect(timeAgo(new Date(2026, 9, 1, 9).getTime(), NOW)).toBe("yesterday");
    expect(timeAgo(new Date(2026, 8, 28, 9).getTime(), NOW)).toBe("4 days ago");
    expect(timeAgo(new Date(2026, 8, 1, 9).getTime(), NOW)).toBe("Sep 1, 2026");
  });
});

describe("createdLabel", () => {
  it("reads as a phrase after 'created'", () => {
    expect(createdLabel(NOW - HOUR, NOW)).toBe("today");
    expect(createdLabel(new Date(2026, 9, 1, 23).getTime(), NOW)).toBe("yesterday");
    expect(createdLabel(new Date(2026, 8, 30).getTime(), NOW)).toBe("2 days ago");
    expect(createdLabel(new Date(2026, 0, 5).getTime(), NOW)).toBe("on Jan 5, 2026");
  });
});
