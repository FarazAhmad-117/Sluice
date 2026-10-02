import { describe, expect, it } from "vitest";
import { placeMenu } from "../src/components/ui/place-menu";

const viewport = { width: 1280, height: 800 };
const size = { width: 256, height: 120 };
/** A 44px trigger near the right of a table row. */
const trigger = (top: number, left = 1100) => ({ top, bottom: top + 44, left, right: left + 44 });

describe("placeMenu", () => {
  it("opens below the trigger, aligned to its end edge", () => {
    expect(placeMenu(trigger(200), size, viewport, "end")).toEqual({
      top: 252,
      left: 1144 - 256,
      maxHeight: 800 - 244 - 16,
    });
  });

  it("aligns to the start edge when asked", () => {
    expect(placeMenu(trigger(200, 100), size, viewport, "start").left).toBe(100);
  });

  it("flips above when it does not fit below and there is more room above", () => {
    const placed = placeMenu(trigger(700), size, viewport, "end");
    expect(placed.top).toBe(700 - 8 - 120);
    expect(placed.top + 120).toBeLessThanOrEqual(700);
  });

  it("stays below when neither side fits but below has more room, and caps its height", () => {
    const tall = { width: 256, height: 900 };
    const placed = placeMenu(trigger(100), tall, viewport, "end");
    expect(placed.top).toBe(152);
    expect(placed.maxHeight).toBe(800 - 144 - 16);
  });

  it("is kept inside the viewport horizontally", () => {
    // A start-aligned menu from a trigger at the right edge of a phone.
    const phone = { width: 390, height: 844 };
    expect(placeMenu(trigger(100, 350), size, phone, "start").left).toBe(390 - 256 - 8);
    // An end-aligned menu from a trigger at the left edge.
    expect(placeMenu(trigger(100, 0), size, phone, "end").left).toBe(8);
  });
});
