"use client";

import { useEffect, useRef } from "react";
import type { JSX } from "react";

/* ---------------------------------------------------------------------------
   Sluice particle field.

   A dot-matrix sphere that detonates and reforms. This is not decoration: the
   product's differentiator is instant signed revocation, and a coherent sphere
   of points blowing apart and settling back is that mechanic rendered rather
   than illustrated.

   Contract notes for callers:

   - The wrapper is `position: relative` and the canvas is absolutely filling
     it, so the component never contributes intrinsic height. The caller must
     size the wrapper through `className` (for example `aspect-square w-full`).
     An unsized or zero-sized wrapper paints nothing, on purpose: silence is a
     better failure than a canvas inflating the layout to its device-pixel
     height.
   - `state="scattered"` is an edge trigger, not a held pose. The rising edge
     fires one detonation whose terminal condition is the idle sphere, because
     the spec for this field is "accelerate outward, thin out, then reform".
     Holding "scattered" therefore rests on a coherent sphere once the timeline
     completes. Flipping back to "idle" mid-detonation aborts it by easing the
     burst amplitude to zero, never by cutting.
   - No colour literal appears in the drawing path. Colours are read from the
     design tokens on the root element at mount, and re-read when `data-theme`
     or `class` changes there, so a future light dashboard is a token change.
     The FALLBACK_* constants below are only used when a token is absent or
     unparseable, which would otherwise mean an invisible field with no clue
     as to why.
   --------------------------------------------------------------------------- */

export type ParticleFieldState = "idle" | "scattered";

export interface ParticleFieldProps {
  state?: ParticleFieldState;
  className?: string;
}

/* --- geometry and motion constants ---------------------------------------- */

/** Upper bound on generated points. Also the capacity of every scratch buffer. */
const MAX_POINTS = 2400;
/** Lower bound, so a small canvas still reads as a sphere and not as noise. */
const MIN_POINTS = 320;
/**
 * Points scale with the square of the sphere's CSS radius, i.e. with its
 * projected area, so perceived density stays constant across viewports.
 * Deliberately not scaled by devicePixelRatio: a retina phone should not pay
 * four times the per-point cost for the same apparent density.
 */
const POINTS_PER_AREA = 26;
/** Sphere radius as a fraction of the shorter canvas edge, in CSS pixels. */
const SPHERE_FRACTION = 0.3;
/** Retina is worth honouring, beyond 2x is fill rate spent for nothing. */
const MAX_DPR = 2;

/** Camera distance in sphere radii. Larger is a flatter, more technical read. */
const CAM = 3.2;
/** Fixed tilt about X so the point rings do not read as a flat disc. */
const TILT = 0.38;
/** Resting rotation, radians. Also the single frame painted under reduced motion. */
const INITIAL_ROT = 0.62;
/** Idle spin, radians per second. One revolution in roughly 29 seconds. */
const ROT_BASE = 0.22;
/** Extra spin at full detonation. The field spins up as it comes apart. */
const ROT_BURST = 1.5;

/**
 * Peak outward travel, multiplied by each point's own speed in [0.5, 1.65], so
 * the sphere expands to between roughly 1.5x and 2.6x its radius. Tuned against
 * a census rather than by eye: measured on a 520px square at dpr 1.25, 95% of
 * points are drawn at rest and 42% at peak, the rest having left the frame. Lit
 * pixels fall much further, to about 19%, because the dot also shrinks and
 * fades. So the field visibly comes apart without simply vanishing.
 */
const BURST_REACH = 0.95;
/** Peak tangential shear, so the burst shears rather than expanding as a shell. */
const SWIRL_REACH = 0.55;
/** Fraction of brightness lost at full burst. This is the "thin out". */
const BURST_FADE = 0.6;
/** Fraction of dot size lost at full burst. */
const BURST_SHRINK = 0.4;

/* Detonation envelope, seconds. Fast attack, brief hold, long settle. */
const ENV_ATTACK = 0.22;
const ENV_HOLD = 0.3;
const ENV_RELEASE = 1.55;
const ENV_TOTAL = ENV_ATTACK + ENV_HOLD + ENV_RELEASE;

/* Exponential smoothing time constants applied to the burst amplitude. Every
   transition runs through these, which is what makes a jump cut structurally
   impossible regardless of how the caller drives the prop. */
const TAU_RISE = 0.045;
const TAU_FALL = 0.22;

/** Dot edge in CSS pixels before perspective and burst scaling. */
const DOT_CSS = 1.15;
/** Hard cap on dot edge in device pixels. Dot matrix, not confetti. */
const DOT_MAX = 4;

/** Share of points drawn in the brand hue. A trace, not a colour scheme. */
const ACCENT_FRACTION = 0.05;

/* Shading tiers. One fillStyle assignment per tier per frame is the only
   canvas state change in the draw loop, which is what keeps it cheap. */
const NEU_TIERS = 6;
const ACC_TIERS = 2;
const BINS = NEU_TIERS + ACC_TIERS;
const NEU_ALPHA_MIN = 0.14;
const NEU_ALPHA_MAX = 0.92;
const ACC_ALPHA_MIN = 0.3;
const ACC_ALPHA_MAX = 0.85;
/** Below this the dot is invisible, so skip the fillRect entirely. */
const SHADE_FLOOR = 0.04;

/** Clamp on frame delta. A backgrounded tab resumes with a huge gap otherwise. */
const MAX_DT = 0.05;

/** Deterministic seed, so the field is reproducible across reloads and machines. */
const SEED = 0x5f1c3a7b;

/* Used only when a token is missing or unparseable. See the header note. */
type Rgb = readonly [number, number, number];
const FALLBACK_PRIMARY: Rgb = [244, 244, 245];
const FALLBACK_MUTED: Rgb = [138, 138, 147];
const FALLBACK_BRAND: Rgb = [45, 127, 249];

/* --- small helpers -------------------------------------------------------- */

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function clamp01(v: number): number {
  return v < 0 ? 0 : v > 1 ? 1 : v;
}

function toByte(v: number): number {
  const n = Math.round(v);
  return n < 0 ? 0 : n > 255 ? 255 : n;
}

/**
 * Parses the subset of CSS colour syntax the tokens actually use: hex in three,
 * four, six or eight digits, and rgb()/rgba() in comma or space form including
 * the slash-alpha variant. Anything else, including the empty string returned
 * for an undefined custom property, yields the fallback.
 */
function parseColor(raw: string, fallback: Rgb): Rgb {
  const v = raw.trim();
  if (v.length === 0) return fallback;

  if (v.charCodeAt(0) === 35 /* # */) {
    const hex = v.slice(1);
    const short = hex.length === 3 || hex.length === 4;
    const long = hex.length === 6 || hex.length === 8;
    if (!short && !long) return fallback;
    if (!/^[0-9a-fA-F]+$/.test(hex)) return fallback;
    if (short) {
      return [
        parseInt(hex[0] + hex[0], 16),
        parseInt(hex[1] + hex[1], 16),
        parseInt(hex[2] + hex[2], 16),
      ];
    }
    return [
      parseInt(hex.slice(0, 2), 16),
      parseInt(hex.slice(2, 4), 16),
      parseInt(hex.slice(4, 6), 16),
    ];
  }

  const parts = v.match(/-?\d*\.?\d+%?/g);
  if (parts === null || parts.length < 3) return fallback;
  const chan = (s: string): number => {
    const n = Number.parseFloat(s);
    if (Number.isNaN(n)) return Number.NaN;
    return s.endsWith("%") ? (n / 100) * 255 : n;
  };
  const r = chan(parts[0]);
  const g = chan(parts[1]);
  const b = chan(parts[2]);
  if (Number.isNaN(r) || Number.isNaN(g) || Number.isNaN(b)) return fallback;
  return [toByte(r), toByte(g), toByte(b)];
}

function mixRgb(a: Rgb, b: Rgb, t: number): Rgb {
  return [
    a[0] + (b[0] - a[0]) * t,
    a[1] + (b[1] - a[1]) * t,
    a[2] + (b[2] - a[2]) * t,
  ];
}

function rgbaStyle(c: Rgb, alpha: number): string {
  return `rgba(${toByte(c[0])},${toByte(c[1])},${toByte(c[2])},${alpha.toFixed(3)})`;
}

function easeOutCubic(t: number): number {
  const u = 1 - t;
  return 1 - u * u * u;
}

function easeInOutCubic(t: number): number {
  return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
}

/** Detonation amplitude over the timeline. Continuous, and zero at both ends. */
function envelope(t: number): number {
  if (t <= 0) return 0;
  if (t < ENV_ATTACK) return easeOutCubic(t / ENV_ATTACK);
  if (t < ENV_ATTACK + ENV_HOLD) return 1;
  if (t < ENV_TOTAL) {
    return 1 - easeInOutCubic((t - ENV_ATTACK - ENV_HOLD) / ENV_RELEASE);
  }
  return 0;
}

/* --- component ------------------------------------------------------------ */

export function ParticleField({
  state = "idle",
  className,
}: ParticleFieldProps): JSX.Element {
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  /* The prop reaches the animation loop through refs so that driving it never
     restarts the effect, never regenerates geometry, and never re-renders per
     frame. Written in an effect rather than during render, because a render
     that concurrent React discards must not be able to fire a detonation. */
  const stateRef = useRef<ParticleFieldState>(state);
  const burstRequestRef = useRef(0);

  useEffect(() => {
    stateRef.current = state;
    if (state === "scattered") burstRequestRef.current += 1;
  }, [state]);

  useEffect(() => {
    const wrap = wrapRef.current;
    const canvasEl = canvasRef.current;
    if (wrap === null || canvasEl === null) return;
    const context2d = canvasEl.getContext("2d", { alpha: true });
    if (context2d === null) return;
    /* Re-bound with explicit non-nullable types. The hoisted function
       declarations below do not inherit control-flow narrowing. */
    const canvas: HTMLCanvasElement = canvasEl;
    const ctx: CanvasRenderingContext2D = context2d;

    let disposed = false;
    let raf = 0;

    /* ---- geometry, generated exactly once -------------------------------- */

    const rand = mulberry32(SEED);
    const N = MAX_POINTS;

    const px = new Float32Array(N);
    const py = new Float32Array(N);
    const pz = new Float32Array(N);
    /* Per point shear direction, already scaled by its own magnitude. */
    const sx = new Float32Array(N);
    const sy = new Float32Array(N);
    const sz = new Float32Array(N);
    /* Per point outward speed and detonation delay. */
    const spd = new Float32Array(N);
    const delay = new Float32Array(N);
    const accent = new Uint8Array(N);

    /* A Fibonacci lattice is evenly spread but its prefix is a spiral band, so
       the points are written in a shuffled order. Any prefix of the shuffled
       array is then an unbiased sample of the whole sphere, which is what lets
       the point count follow the canvas size without regenerating anything. */
    const order = new Uint16Array(N);
    for (let i = 0; i < N; i++) order[i] = i;
    for (let i = N - 1; i > 0; i--) {
      const j = (rand() * (i + 1)) | 0;
      const tmp = order[i];
      order[i] = order[j];
      order[j] = tmp;
    }

    const goldenAngle = Math.PI * (3 - Math.sqrt(5));
    for (let i = 0; i < N; i++) {
      const slot = order[i];
      const y = 1 - (2 * i + 1) / N;
      const ring = Math.sqrt(Math.max(0, 1 - y * y));
      const theta = goldenAngle * i;
      const x = Math.cos(theta) * ring;
      const z = Math.sin(theta) * ring;

      px[slot] = x;
      py[slot] = y;
      pz[slot] = z;

      /* Two orthonormal tangents at this point, so the shear can point any
         direction in the local tangent plane. Degenerate at the poles, where
         `ring` collapses, so fall back to a fixed basis there. */
      let t0x: number;
      let t0z: number;
      let t1x: number;
      let t1y: number;
      let t1z: number;
      if (ring < 1e-4) {
        t0x = 1;
        t0z = 0;
        t1x = 0;
        t1y = 0;
        t1z = 1;
      } else {
        t0x = z / ring;
        t0z = -x / ring;
        t1x = (-x * y) / ring;
        t1y = ring;
        t1z = (-y * z) / ring;
      }
      const angle = rand() * Math.PI * 2;
      const mag = 0.35 + rand() * 0.9;
      const ca = Math.cos(angle) * mag;
      const sa = Math.sin(angle) * mag;
      sx[slot] = t0x * ca + t1x * sa;
      sy[slot] = t1y * sa;
      sz[slot] = t0z * ca + t1z * sa;

      spd[slot] = 0.5 + rand() * 1.15;
      /* Squared so most points fire early and a tail lags: a propagating
         detonation rather than a single expanding shell. */
      const d = rand();
      delay[slot] = d * d * 0.42;
      accent[slot] = rand() < ACCENT_FRACTION ? 1 : 0;
    }

    /* ---- draw batching --------------------------------------------------- */

    /* One buffer per shading tier, holding x, y, size triples in device pixels.
       Integers, so Int16 is exact and a third of the memory of Float32. */
    const bins: Int16Array[] = [];
    for (let b = 0; b < BINS; b++) bins.push(new Int16Array(N * 3));
    const binCount = new Int32Array(BINS);
    const binStyle: string[] = new Array<string>(BINS).fill("rgba(0,0,0,0)");

    function readTokens(): void {
      const cs = getComputedStyle(document.documentElement);
      const primary = parseColor(
        cs.getPropertyValue("--text-primary"),
        FALLBACK_PRIMARY,
      );
      const muted = parseColor(
        cs.getPropertyValue("--text-muted"),
        FALLBACK_MUTED,
      );
      const brand = parseColor(cs.getPropertyValue("--brand"), FALLBACK_BRAND);

      for (let i = 0; i < NEU_TIERS; i++) {
        const t = (i + 0.5) / NEU_TIERS;
        binStyle[i] = rgbaStyle(
          mixRgb(muted, primary, t),
          NEU_ALPHA_MIN + (NEU_ALPHA_MAX - NEU_ALPHA_MIN) * t,
        );
      }
      for (let j = 0; j < ACC_TIERS; j++) {
        const t = (j + 0.5) / ACC_TIERS;
        binStyle[NEU_TIERS + j] = rgbaStyle(
          mixRgb(muted, brand, 0.45 + 0.55 * t),
          ACC_ALPHA_MIN + (ACC_ALPHA_MAX - ACC_ALPHA_MIN) * t,
        );
      }
    }

    /* ---- layout ---------------------------------------------------------- */

    let dpr = 1;
    let deviceW = 0;
    let deviceH = 0;
    let radius = 0;
    let count = 0;
    let ready = false;

    function layout(cssW: number, cssH: number): void {
      if (!(cssW > 0) || !(cssH > 0)) {
        /* Zero width, zero height, display:none ancestor, or a NaN box. Stop
           rather than burn frames drawing into nothing. Resumes on the next
           observer entry that reports a real box. */
        ready = false;
        return;
      }
      dpr = Math.min(window.devicePixelRatio || 1, MAX_DPR);
      const nextW = Math.max(1, Math.round(cssW * dpr));
      const nextH = Math.max(1, Math.round(cssH * dpr));
      /* Assigning width or height resets the whole 2D context state, so only
         assign when it actually changed. */
      if (canvas.width !== nextW) canvas.width = nextW;
      if (canvas.height !== nextH) canvas.height = nextH;
      deviceW = nextW;
      deviceH = nextH;

      const radiusCss = SPHERE_FRACTION * Math.min(cssW, cssH);
      radius = radiusCss * dpr;
      count = Math.max(
        MIN_POINTS,
        Math.min(
          MAX_POINTS,
          Math.round((radiusCss * radiusCss) / POINTS_PER_AREA),
        ),
      );
      ready = true;
    }

    /* ---- animation state ------------------------------------------------- */

    let burst = 0;
    let bursting = false;
    let burstClock = 0;
    let rot = INITIAL_ROT;
    let last = 0;
    let seenRequest = burstRequestRef.current;

    /* Mounting already scattered should detonate. The sibling effect above has
       already incremented the request counter by the time this one runs, so
       reconcile explicitly rather than by counter comparison. */
    if (stateRef.current === "scattered") {
      bursting = true;
      burstClock = 0;
    }

    function advance(dt: number): void {
      if (burstRequestRef.current !== seenRequest) {
        seenRequest = burstRequestRef.current;
        bursting = true;
        burstClock = 0;
      }
      /* Checked after the trigger, so a scatter and an un-scatter landing in
         the same frame cancel out instead of flashing. */
      if (stateRef.current === "idle" && bursting) bursting = false;

      if (bursting) {
        burstClock += dt;
        if (burstClock >= ENV_TOTAL) bursting = false;
      }

      const target = bursting ? envelope(burstClock) : 0;
      const tau = target > burst ? TAU_RISE : TAU_FALL;
      burst += (target - burst) * (1 - Math.exp(-dt / tau));
      if (burst < 1e-4) burst = 0;

      rot += dt * (ROT_BASE + burst * ROT_BURST);
      if (rot > Math.PI * 2) rot -= Math.PI * 2;
    }

    function draw(): void {
      if (!ready) return;
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.clearRect(0, 0, deviceW, deviceH);

      const cosR = Math.cos(rot);
      const sinR = Math.sin(rot);
      const cosT = Math.cos(TILT);
      const sinT = Math.sin(TILT);
      const originX = deviceW * 0.5;
      const originY = deviceH * 0.5;
      const dotBase = DOT_CSS * dpr;

      binCount.fill(0);

      for (let i = 0; i < count; i++) {
        const d = delay[i];
        const local = burst === 0 ? 0 : clamp01((burst - d) / (1 - d));

        const reach = 1 + local * spd[i] * BURST_REACH;
        const shear = local * SWIRL_REACH;
        const x = px[i] * reach + sx[i] * shear;
        const y = py[i] * reach + sy[i] * shear;
        const z = pz[i] * reach + sz[i] * shear;

        const x1 = x * cosR - z * sinR;
        const z1 = x * sinR + z * cosR;
        const y2 = y * cosT - z1 * sinT;
        const z2 = y * sinT + z1 * cosT;

        const denom = CAM + z2;
        if (denom <= 0.12) continue;
        const k = CAM / denom;

        const screenX = originX + x1 * radius * k;
        const screenY = originY + y2 * radius * k;
        if (
          screenX < -DOT_MAX ||
          screenX > deviceW + DOT_MAX ||
          screenY < -DOT_MAX ||
          screenY > deviceH + DOT_MAX
        ) {
          continue;
        }

        /* Normalise depth against this point's own reach, so a detonating point
           does not read as "far away" purely because it travelled. */
        const depth = clamp01(0.5 - (z2 / reach) * 0.5);
        const shade = depth * (1 - local * BURST_FADE);
        if (shade < SHADE_FLOOR) continue;

        const isAccent = accent[i] === 1;
        const tiers = isAccent ? ACC_TIERS : NEU_TIERS;
        const base = isAccent ? NEU_TIERS : 0;
        const bin = base + Math.min(tiers - 1, (shade * tiers) | 0);

        let size = Math.round(
          dotBase * (0.62 + 0.55 * k) * (1 - local * BURST_SHRINK),
        );
        if (size < 1) size = 1;
        else if (size > DOT_MAX) size = DOT_MAX;

        const buf = bins[bin];
        const offset = binCount[bin] * 3;
        buf[offset] = screenX;
        buf[offset + 1] = screenY;
        buf[offset + 2] = size;
        binCount[bin]++;
      }

      for (let b = 0; b < BINS; b++) {
        const n = binCount[b];
        if (n === 0) continue;
        ctx.fillStyle = binStyle[b];
        const buf = bins[b];
        for (let j = 0; j < n; j++) {
          const o = j * 3;
          const s = buf[o + 2];
          ctx.fillRect(buf[o], buf[o + 1], s, s);
        }
      }
    }

    /* ---- loop ------------------------------------------------------------ */

    function frame(now: number): void {
      raf = 0;
      if (disposed) return;
      if (last === 0) last = now;
      const dt = Math.min(MAX_DT, Math.max(0, (now - last) / 1000));
      last = now;
      advance(dt);
      draw();
      if (disposed) return;
      raf = requestAnimationFrame(frame);
    }

    function stop(): void {
      if (raf !== 0) {
        cancelAnimationFrame(raf);
        raf = 0;
      }
    }

    function start(): void {
      if (disposed || reduced || !ready || raf !== 0) return;
      last = 0;
      raf = requestAnimationFrame(frame);
    }

    /* ---- observers and media queries ------------------------------------- */

    const motionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    let reduced = motionQuery.matches;

    function refresh(): void {
      if (!ready) {
        stop();
        return;
      }
      if (reduced) {
        stop();
        draw();
      } else {
        start();
      }
    }

    function onMotionChange(): void {
      reduced = motionQuery.matches;
      if (reduced) {
        /* Reduced motion means one static frame of the idle state, not a slower
           loop, so reset the pose rather than freezing wherever it happened to
           be mid-detonation. */
        rot = INITIAL_ROT;
        burst = 0;
        bursting = false;
      }
      refresh();
    }

    const resizeObserver = new ResizeObserver((entries) => {
      const entry = entries[entries.length - 1];
      if (entry === undefined) return;
      layout(entry.contentRect.width, entry.contentRect.height);
      refresh();
    });

    /* Theme flips by re-pointing the same custom properties on a root element,
       so re-read the tokens when that element's attributes change. `style` is
       deliberately not watched: scroll-lock and similar utilities write it
       constantly and it never carries a theme in this codebase. */
    const themeObserver = new MutationObserver(() => {
      readTokens();
      if (reduced) draw();
    });

    readTokens();
    layout(wrap.clientWidth, wrap.clientHeight);
    refresh();


    resizeObserver.observe(wrap);
    themeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme", "class"],
    });
    motionQuery.addEventListener("change", onMotionChange);

    return () => {
      disposed = true;
      stop();
      resizeObserver.disconnect();
      themeObserver.disconnect();
      motionQuery.removeEventListener("change", onMotionChange);
    };
  }, []);

  return (
    <div
      ref={wrapRef}
      aria-hidden="true"
      className={className === undefined ? "relative" : `relative ${className}`}
    >
      <canvas ref={canvasRef} aria-hidden="true" className="absolute inset-0 block h-full w-full" />
    </div>
  );
}
