"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  attemptHeroRevocation,
  createHeroSession,
} from "@/lib/landing/hero-revocation";
import type { HeroSession, HeroSigner } from "@/lib/landing/hero-revocation";
import { MASK, TUMBLE_MS, fingerprint, tumbleFrame } from "@/lib/landing/redaction";
import { focusRing } from "@/components/landing/primitives";

/**
 * The hero object: a globe carrying the fleet, and the two controls that make
 * it an argument.
 *
 * WHY THERE IS NO PANEL ANY MORE. This used to be a globe with a bordered
 * console bolted underneath listing three workers, their regions and their
 * masked keys. The card repeated, in a table, everything the globe was already
 * saying in a picture, and the two competed: the eye went to the card because
 * cards are where information lives, and the globe was demoted back to
 * decoration -- the exact failure the globe was introduced to fix. The rows are
 * gone and their content is now ON the markers, which is where it belonged,
 * because a key that belongs to a process in Frankfurt should be drawn in
 * Frankfurt.
 *
 * WHAT EACH ELEMENT MEANS. Nothing here is ornament.
 *
 *   marker        one live process holding the token, at its region
 *   ring          a heartbeat, drawn only while that process is alive
 *   label         the process's key, masked -- hover a marker to resolve the
 *                 mask into the real SHA-256 fingerprint of its bundle
 *   arc           the standing delivery channel to that process
 *   pulse         a revocation notice actually travelling down it
 *   pulse colour  who signed it: blue for the org key, amber for a forgery
 *
 * THE FORGED CASE IS THE POINT, and it is why pulses and markers are driven
 * independently. On a forgery the pulses still fly and still arrive -- an
 * attacker really can deliver those bytes, that is the premise -- each process
 * still wakes up and checks, and then every one of them refuses. A version that
 * withheld the pulses would be drawing an attacker who cannot reach the fleet,
 * which is a weaker and much less true claim than one who reaches it and is
 * ignored.
 *
 * THE CRYPTOGRAPHY IS REAL. `@/lib/landing/hero-revocation` mints a token,
 * generates an organisation Ed25519 keypair and a second keypair standing in
 * for whoever runs the server, signs a real `RevocationNotice` and runs it
 * through the same `verifyRevocation` the SDK calls. `verified` below is that
 * function's return value and never a literal; the timings and the label copy
 * are this file's business, the verdict is not.
 *
 * THE ANIMATION DELIBERATELY DOES NOT RUN AT THE MEASURED SPEED. Sign and
 * verify land under a couple of milliseconds, which is below the threshold at
 * which an eye reads an event as an event. The motion resolves over about two
 * seconds so a human can watch it happen, and the printed figure stays the
 * measured one. Those two facts are only compatible while the readout says what
 * it measured, which is the crypto and not a round trip.
 */

/* --- the fleet ------------------------------------------------------------ */

/**
 * Real regions, because the alternative is three dots in the Atlantic. Spread
 * across enough longitude that at any rotation at least one faces the viewer,
 * which matters: a kill nobody can see did not read as a kill.
 */
const FLEET = [
  { host: "worker-a", region: "us-east", lat: 39.04, lon: -77.49 },
  { host: "worker-b", region: "eu-central", lat: 50.11, lon: 8.68 },
  { host: "worker-c", region: "ap-southeast", lat: 1.35, lon: 103.82 },
] as const;

/** Where the signing browser is. The origin of every pulse. */
const ADMIN = { lat: 37.77, lon: -122.42 };

/* --- geometry ------------------------------------------------------------- */

/** Idle spin, radians per frame. One revolution in roughly 40 seconds. */
const SPIN = 0.0016;
/** Fixed tilt about X, so the dot rings do not read as a flat disc. */
const TILT = -0.32;
/** Hard cap on device pixel ratio. Beyond 2x is fill rate spent for nothing. */
const MAX_DPR = 2;
/** Drag sensitivity, radians per CSS pixel. */
const DRAG_SPEED = 0.006;
/** Candidate points scattered over the sphere; only those on land are kept. */
const DOT_SAMPLES = 6400;
/** Pointer distance, in CSS pixels, within which a marker counts as hovered. */
const HOVER_RADIUS = 26;

/**
 * Landmasses as coarse lat/lon ellipses.
 *
 * This is not a map and does not want to be. It is the smallest description
 * that makes a rotating dot sphere read as Earth rather than as noise, at a
 * cost of eighteen numbers rather than a GeoJSON download. Nothing in the
 * product depends on a dot being in the right place; the three markers are
 * positioned from real coordinates and they are the only things that must land
 * correctly.
 */
const LAND: readonly (readonly [number, number, number, number])[] = [
  [48, -100, 20, 30], [62, -115, 10, 32], [18, -98, 9, 10], [-12, -60, 20, 15],
  [-38, -67, 10, 7], [50, 12, 11, 20], [62, 22, 8, 18], [6, 20, 24, 18],
  [-20, 26, 12, 13], [48, 92, 20, 48], [63, 105, 10, 45], [22, 78, 10, 8],
  [13, 103, 9, 9], [-25, 134, 11, 17], [-3, 117, 5, 15], [37, 138, 7, 4],
  [72, -40, 8, 17], [25, 45, 10, 12],
];

type Vec3 = [number, number, number];

function isLand(lat: number, lon: number): boolean {
  for (const [a, b, ra, rb] of LAND) {
    let d = lon - b;
    if (d > 180) d -= 360;
    if (d < -180) d += 360;
    if (((lat - a) / ra) ** 2 + (d / rb) ** 2 < 1) return true;
  }
  return false;
}

function toVec(lat: number, lon: number): Vec3 {
  const p = (lat * Math.PI) / 180;
  const l = (lon * Math.PI) / 180;
  return [Math.cos(p) * Math.sin(l), Math.sin(p), Math.cos(p) * Math.cos(l)];
}

/** Great-circle interpolation, lifted off the surface so an arc reads as an arc. */
function slerp(a: Vec3, b: Vec3, t: number): Vec3 {
  const dot = Math.max(-1, Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]));
  const w = Math.acos(dot);
  const s = Math.sin(w) || 1;
  const k1 = Math.sin((1 - t) * w) / s;
  const k2 = Math.sin(t * w) / s;
  const lift = 1 + 0.22 * Math.sin(Math.PI * t);
  return [
    (a[0] * k1 + b[0] * k2) * lift,
    (a[1] * k1 + b[1] * k2) * lift,
    (a[2] * k1 + b[2] * k2) * lift,
  ];
}

/* --- per-process display state -------------------------------------------- */

/**
 * What a marker is saying right now.
 *
 * `live` and `dead` are states of the process. `checking`, `valid`, `draining`
 * and `refused` are states of an in-flight notice at that process, and they are
 * separate from the process state on purpose: `refused` is a process that is
 * very much alive and has just declined an instruction, which is the single
 * most important frame in this whole animation.
 */
type NodeState = "live" | "checking" | "valid" | "draining" | "refused" | "dead";

interface NodeView {
  state: NodeState;
  /** Overrides the key label while a notice is being handled. Null shows the key. */
  message: string | null;
}

const IDLE_VIEW: NodeView = { state: "live", message: null };

/* --- colours -------------------------------------------------------------- */

type Rgb = readonly [number, number, number];

/* Used only when a token is missing or unparseable, which would otherwise paint
   an invisible globe with no clue as to why. */
const FALLBACK: Record<string, Rgb> = {
  healthy: [52, 211, 153],
  warning: [251, 191, 36],
  danger: [248, 113, 113],
  brand: [96, 165, 250],
  muted: [138, 145, 163],
};

function readToken(name: string, fallback: Rgb): Rgb {
  if (typeof window === "undefined") return fallback;
  const raw = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const hex = /^#([0-9a-f]{6})$/i.exec(raw);
  if (hex) {
    const v = parseInt(hex[1]!, 16);
    return [(v >> 16) & 255, (v >> 8) & 255, v & 255];
  }
  const fn = /^rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)/i.exec(raw);
  if (fn) return [Number(fn[1]), Number(fn[2]), Number(fn[3])];
  return fallback;
}

const rgba = (c: Rgb, a: number) => `rgba(${c[0]},${c[1]},${c[2]},${a})`;

/** Display only. The full signature is what was verified. */
function truncate(hex: string): string {
  return `${hex.slice(0, 6)}…${hex.slice(-6)}`;
}

function formatMs(ms: number): string {
  return ms < 0.01 ? "<0.01 ms" : `${ms.toFixed(2)} ms`;
}

/* --- timings, all in milliseconds ----------------------------------------- */

const PULSE_FLIGHT = 1100;
const PULSE_STAGGER = 170;
const CHECK_MS = 480;
const VALID_MS = 420;
const DRAIN_MS = 900;
const REFUSED_MS = 2400;

export function FleetGlobe() {
  const canvas = useRef<HTMLCanvasElement | null>(null);

  /** Drives only the copy under the globe. The canvas never re-renders React. */
  const [status, setStatus] = useState<
    | { kind: "idle" }
    | { kind: "busy" }
    | { kind: "killed"; sig: string; ms: number }
    | { kind: "refused"; sig: string; ms: number }
  >({ kind: "idle" });

  const session = useRef<HeroSession | null>(null);
  const epoch = useRef(1);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  /*
    Everything the draw loop reads lives in refs. The loop runs at sixty frames
    a second and must never be a reason to re-render: the marker labels, the
    pulses and the hover test all mutate these in place, and React is told only
    when the sentence under the globe changes.
  */
  const views = useRef<NodeView[]>(FLEET.map(() => ({ ...IDLE_VIEW })));
  const pulses = useRef<{ target: number; startAt: number; colour: Rgb }[]>([]);
  /** Per marker: the resolved fingerprint, and how far the tumble has run. */
  const labels = useRef(
    FLEET.map(() => ({
      digest: null as string | null,
      /** Set the moment a hash is requested, so the loop asks exactly once. */
      requested: false,
      revealed: false,
      at: 0,
    })),
  );

  const clearTimers = useCallback(() => {
    for (const t of timers.current) clearTimeout(t);
    timers.current = [];
  }, []);

  const later = useCallback((fn: () => void, ms: number) => {
    timers.current.push(setTimeout(fn, ms));
  }, []);

  useEffect(() => () => clearTimers(), [clearTimers]);

  /**
   * Mint on first contact, never on mount.
   *
   * Key generation reads `crypto.getRandomValues`, so doing it during render or
   * in a mount effect would either throw on the server or, worse, succeed and
   * hand the client a different token id than the HTML claims. It also spends
   * three scalar multiplications on a reader who came to read the headline.
   */
  const ensureSession = useCallback((): HeroSession => {
    session.current ??= createHeroSession();
    return session.current;
  }, []);

  /* --- the run -------------------------------------------------------------- */

  const send = useCallback(
    (signer: HeroSigner) => {
      clearTimers();
      const active = ensureSession();
      const attempt = attemptHeroRevocation(active, signer, epoch.current++);

      setStatus({ kind: "busy" });
      views.current = FLEET.map(() => ({ ...IDLE_VIEW }));

      const colour: Rgb = attempt.verified
        ? readToken("--brand", FALLBACK.brand!)
        : readToken("--status-warning", FALLBACK.warning!);

      FLEET.forEach((_, i) => {
        const launch = i * PULSE_STAGGER;
        pulses.current.push({
          target: i,
          startAt: performance.now() + launch,
          colour,
        });

        const arrival = launch + PULSE_FLIGHT;
        later(() => {
          views.current[i] = { state: "checking", message: "verifying signature…" };
        }, arrival);

        if (!attempt.verified) {
          // The whole argument, in one label: the notice arrived, the process
          // looked at it, and the process is still running.
          later(() => {
            views.current[i] = { state: "refused", message: "✕ bad signature · ignored" };
          }, arrival + CHECK_MS);
          return;
        }

        later(() => {
          views.current[i] = { state: "valid", message: "✓ signature valid" };
        }, arrival + CHECK_MS);
        later(() => {
          views.current[i] = { state: "draining", message: "draining…" };
        }, arrival + CHECK_MS + VALID_MS);
        later(() => {
          views.current[i] = { state: "dead", message: "exited (1)" };
        }, arrival + CHECK_MS + VALID_MS + DRAIN_MS);
      });

      const last = (FLEET.length - 1) * PULSE_STAGGER + PULSE_FLIGHT + CHECK_MS;

      if (attempt.verified) {
        later(
          () =>
            setStatus({
              kind: "killed",
              sig: truncate(attempt.signatureHex),
              ms: attempt.elapsedMs,
            }),
          last + VALID_MS + DRAIN_MS,
        );
        return;
      }

      later(
        () =>
          setStatus({
            kind: "refused",
            sig: truncate(attempt.signatureHex),
            ms: attempt.elapsedMs,
          }),
        last,
      );
      // A refusal is not a state the fleet stays in. The processes go back to
      // running, because that is what actually happened to them.
      later(() => {
        views.current = FLEET.map(() => ({ ...IDLE_VIEW }));
      }, last + REFUSED_MS);
    },
    [clearTimers, ensureSession, later],
  );

  const reset = useCallback(() => {
    clearTimers();
    pulses.current = [];
    views.current = FLEET.map(() => ({ ...IDLE_VIEW }));
    setStatus({ kind: "idle" });
  }, [clearTimers]);

  /* --- the draw loop -------------------------------------------------------- */

  useEffect(() => {
    const element = canvas.current;
    if (element === null) return;
    const ctx = element.getContext("2d");
    if (ctx === null) return;

    const colours = {
      healthy: readToken("--status-healthy", FALLBACK.healthy!),
      warning: readToken("--status-warning", FALLBACK.warning!),
      danger: readToken("--status-danger", FALLBACK.danger!),
      brand: readToken("--brand", FALLBACK.brand!),
      muted: readToken("--text-muted", FALLBACK.muted!),
    };
    const stateColour: Record<NodeState, Rgb> = {
      live: colours.healthy,
      checking: colours.warning,
      valid: colours.healthy,
      draining: colours.warning,
      refused: colours.healthy,
      dead: colours.danger,
    };

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");

    let w = 0;
    let h = 0;
    let radius = 0;
    let cx = 0;
    let cy = 0;

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, MAX_DPR);
      const rect = element.getBoundingClientRect();
      w = rect.width;
      h = rect.height;
      element.width = Math.round(w * dpr);
      element.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      radius = Math.min(w, h) * 0.4;
      cx = w * 0.53;
      cy = h * 0.46;
    };
    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(element);

    /* Fibonacci sphere, filtered to land. Generated once: the set never changes,
       only the rotation applied to it does. */
    const dots: Vec3[] = [];
    for (let i = 0; i < DOT_SAMPLES; i++) {
      const y = 1 - (i / (DOT_SAMPLES - 1)) * 2;
      const r = Math.sqrt(1 - y * y);
      const th = i * 2.399963;
      const x = Math.cos(th) * r;
      const z = Math.sin(th) * r;
      const lat = (Math.asin(y) * 180) / Math.PI;
      const lon = (Math.atan2(x, z) * 180) / Math.PI;
      if (isLand(lat, lon)) dots.push([x, y, z]);
    }

    const adminVec = toVec(ADMIN.lat, ADMIN.lon);
    const nodeVecs = FLEET.map((n) => toVec(n.lat, n.lon));

    let rot = 0.4;
    let dragFrom: number | null = null;
    let dragBase = 0;
    let pointer: { x: number; y: number } | null = null;
    let hovered = -1;

    const project = ([x, y, z]: Vec3): [number, number, number] => {
      const c = Math.cos(rot);
      const s = Math.sin(rot);
      const rx = x * c + z * s;
      let rz = -x * s + z * c;
      const ct = Math.cos(TILT);
      const st = Math.sin(TILT);
      const ry = y * ct - rz * st;
      rz = y * st + rz * ct;
      return [cx + rx * radius, cy - ry * radius, rz];
    };

    let frame = requestAnimationFrame(function draw(now: number) {
      frame = requestAnimationFrame(draw);
      if (!reduced.matches && dragFrom === null) rot += SPIN;

      ctx.clearRect(0, 0, w, h);

      /* Body. A light from the upper left, so the sphere has a terminator and
         reads as a solid rather than as a ring of dots. */
      const body = ctx.createRadialGradient(
        cx - radius * 0.35,
        cy - radius * 0.4,
        radius * 0.1,
        cx,
        cy,
        radius,
      );
      body.addColorStop(0, "#10151f");
      body.addColorStop(1, "#040507");
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.fillStyle = body;
      ctx.fill();

      /* Rim light. The only thing separating the sphere from the canvas at the
         silhouette, where the body gradient has gone to near-black. */
      const rim = ctx.createRadialGradient(cx, cy, radius * 0.86, cx, cy, radius * 1.02);
      rim.addColorStop(0, rgba(colours.brand, 0));
      rim.addColorStop(0.85, rgba(colours.brand, 0.28));
      rim.addColorStop(1, rgba(colours.brand, 0));
      ctx.beginPath();
      ctx.arc(cx, cy, radius * 1.02, 0, Math.PI * 2);
      ctx.fillStyle = rim;
      ctx.fill();

      // Landmass dots. Back-facing points are skipped, and brightness tracks
      // depth, which is what sells the rotation as rotation.
      for (const d of dots) {
        const [x, y, z] = project(d);
        if (z < 0) continue;
        ctx.fillStyle = `rgba(190,210,255,${0.12 + z * 0.7})`;
        ctx.fillRect(x - 0.8, y - 0.8, 1.6, 1.6);
      }

      // Standing delivery channels. Always drawn, faintly: the subscription is
      // open whether or not anything is travelling down it.
      nodeVecs.forEach((vec, i) => {
        const dead = views.current[i]!.state === "dead";
        ctx.beginPath();
        let pen = false;
        for (let k = 0; k <= 48; k++) {
          const p = project(slerp(adminVec, vec, k / 48));
          if (p[2] > -0.05) {
            if (pen) ctx.lineTo(p[0], p[1]);
            else ctx.moveTo(p[0], p[1]);
            pen = true;
          } else {
            pen = false;
          }
        }
        ctx.strokeStyle = dead ? rgba(colours.danger, 0.2) : rgba(colours.brand, 0.3);
        ctx.lineWidth = 1;
        ctx.stroke();
      });

      // Notices in flight, drawn as a short comet so direction is legible.
      pulses.current = pulses.current.filter((pulse) => {
        const t = (now - pulse.startAt) / PULSE_FLIGHT;
        if (t < 0) return true;
        if (t > 1) return false;
        for (let j = 0; j < 8; j++) {
          const tt = t - j * 0.018;
          if (tt < 0) break;
          const q = project(slerp(adminVec, nodeVecs[pulse.target]!, tt));
          if (q[2] < -0.05) continue;
          ctx.beginPath();
          ctx.arc(q[0], q[1], 2.6 - j * 0.25, 0, Math.PI * 2);
          ctx.fillStyle = rgba(pulse.colour, 1 - j * 0.12);
          ctx.fill();
        }
        return true;
      });

      // The admin's browser. White, because it is the only thing on the globe
      // that is not a process and the only thing holding the key.
      const adminPoint = project(adminVec);
      if (adminPoint[2] > 0) {
        ctx.beginPath();
        ctx.arc(adminPoint[0], adminPoint[1], 3.5, 0, Math.PI * 2);
        ctx.fillStyle = "#fff";
        ctx.fill();
      }

      /* Markers and their labels. Hover testing happens here rather than in a
         React handler because the marker's position changes every frame and
         only this loop knows where it currently is. */
      hovered = -1;
      nodeVecs.forEach((vec, i) => {
        const [x, y, z] = project(vec);
        if (z < 0) return;
        if (
          pointer !== null &&
          Math.hypot(pointer.x - x, pointer.y - y) < HOVER_RADIUS
        ) {
          hovered = i;
        }
      });
      element.style.cursor = dragFrom !== null ? "grabbing" : hovered >= 0 ? "pointer" : "grab";

      nodeVecs.forEach((vec, i) => {
        const [x, y, z] = project(vec);
        if (z < 0) return;

        const view = views.current[i]!;
        const colour = stateColour[view.state];
        const alive = view.state !== "dead";

        // Heartbeat. Only while the process is running, which makes its
        // absence the thing you notice after a kill.
        if (alive && !reduced.matches) {
          const beat = ((now / 1400) % 1);
          ctx.beginPath();
          ctx.arc(x, y, 4 + beat * 14, 0, Math.PI * 2);
          ctx.strokeStyle = rgba(colour, 0.6 * (1 - beat));
          ctx.lineWidth = 1;
          ctx.stroke();
        }

        ctx.beginPath();
        ctx.arc(x, y, 4, 0, Math.PI * 2);
        ctx.fillStyle = rgba(colour, 1);
        ctx.shadowColor = rgba(colour, 1);
        ctx.shadowBlur = 12;
        ctx.fill();
        ctx.shadowBlur = 0;

        /* The label.
           With no notice in flight it shows the process's key, masked, and
           hovering the marker tumbles that mask into the real SHA-256
           fingerprint of the bundle. The value itself is never drawn here or
           anywhere else: a hash is the only thing this page will show about a
           secret, which is the same promise the server operates under. */
        const label = labels.current[i]!;
        let text: string;
        let textColour: string;

        if (view.message !== null) {
          text = view.message;
          textColour = rgba(colour, 0.95);
        } else {
          /* The fingerprint is computed the first time this marker is hovered,
             not at mount. Minting reads `crypto.getRandomValues` and costs
             three scalar multiplications, and a reader who came for the
             headline should not pay for either; hashing on demand is
             instantaneous and keeps the whole key path off the load path. */
          if (hovered === i && !label.requested) {
            label.requested = true;
            const armed = ensureSession();
            void fingerprint(`${armed.token}/${FLEET[i]!.host}`).then((digest) => {
              label.digest = digest;
            });
          }

          const want = hovered === i && label.digest !== null;
          if (want !== label.revealed) {
            label.revealed = want;
            label.at = now;
          }
          const progress = Math.min(1, (now - label.at) / TUMBLE_MS);
          const target = label.revealed ? label.digest! : MASK;
          text = label.at === 0 ? MASK : tumbleFrame(target, progress);
          textColour = label.revealed
            ? rgba(colours.brand, 0.95)
            : `rgba(220,228,245,0.6)`;
        }

        ctx.font =
          '11px ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace';
        ctx.fillStyle = rgba(colours.muted, 0.85);
        ctx.fillText(FLEET[i]!.region, x + 10, y - 2);
        ctx.fillStyle = textColour;
        ctx.fillText(text, x + 10, y + 12);
      });
    });

    /* --- pointer ------------------------------------------------------------ */

    const localPoint = (event: PointerEvent) => {
      const rect = element.getBoundingClientRect();
      return { x: event.clientX - rect.left, y: event.clientY - rect.top };
    };

    const onMove = (event: PointerEvent) => {
      pointer = localPoint(event);
      if (dragFrom !== null) rot = dragBase + (event.clientX - dragFrom) * DRAG_SPEED;
    };
    const onDown = (event: PointerEvent) => {
      // Hovering a marker to read its fingerprint must not also start a drag,
      // or the label the reader is trying to read walks away under the cursor.
      if (hovered >= 0) return;
      dragFrom = event.clientX;
      dragBase = rot;
      element.setPointerCapture(event.pointerId);
    };
    const onUp = (event: PointerEvent) => {
      dragFrom = null;
      if (element.hasPointerCapture(event.pointerId)) {
        element.releasePointerCapture(event.pointerId);
      }
    };
    const onLeave = () => {
      pointer = null;
      dragFrom = null;
    };

    element.addEventListener("pointermove", onMove);
    element.addEventListener("pointerdown", onDown);
    element.addEventListener("pointerup", onUp);
    element.addEventListener("pointercancel", onUp);
    element.addEventListener("pointerleave", onLeave);

    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      element.removeEventListener("pointermove", onMove);
      element.removeEventListener("pointerdown", onDown);
      element.removeEventListener("pointerup", onUp);
      element.removeEventListener("pointercancel", onUp);
      element.removeEventListener("pointerleave", onLeave);
    };
  }, [ensureSession]);

  const busy = status.kind === "busy";

  return (
    <div className="relative">
      {/* The light the globe is lit by. Breathes, slowly enough never to be the
          thing you are looking at. */}
      <div
        aria-hidden="true"
        className="sluice-breathe pointer-events-none absolute top-[42%] left-1/2 h-[min(640px,110%)] w-[min(640px,110%)] rounded-full"
        style={{
          background:
            "radial-gradient(circle, var(--glow-brand) 0%, rgb(29 78 216 / 0.25) 35%, transparent 68%)",
          filter: "blur(30px)",
        }}
      />

      <canvas
        ref={canvas}
        /* Everything the canvas depicts is also said in the status line below
           it, which is where a screen reader is served. Announcing "globe"
           would add noise, not access. */
        aria-hidden="true"
        className="relative block h-[clamp(320px,52vw,560px)] w-full touch-pan-y select-none"
      />

      <div className="relative mt-2 flex flex-wrap items-center gap-x-4 gap-y-3">
        <p aria-live="polite" className="min-w-0 flex-1 font-mono text-xs text-text-muted">
          {status.kind === "idle" ? (
            <>
              3 processes holding this token
              <span className="hidden text-text-faint sm:inline">
                {" · hover a marker for its key"}
              </span>
            </>
          ) : null}
          {busy ? <span className="text-text-body">notice in flight&hellip;</span> : null}
          {status.kind === "killed" ? (
            <span className="text-status-danger">
              3 processes exited &middot;{" "}
              <span className="text-text-faint">
                sig {status.sig} &middot; {formatMs(status.ms)}
              </span>
            </span>
          ) : null}
          {status.kind === "refused" ? (
            <span className="text-status-healthy">
              rejected by all 3 &middot;{" "}
              <span className="text-text-faint">
                sig {status.sig} &middot; {formatMs(status.ms)}
              </span>
            </span>
          ) : null}
        </p>

        <div className="flex shrink-0 items-center gap-2">
          <button
            type="button"
            onClick={() => send("server")}
            disabled={busy}
            className={`inline-flex h-9 cursor-pointer items-center rounded-full border border-hairline-strong bg-white/4 px-4 text-[13px] font-medium text-text-body transition-colors hover:bg-white/8 disabled:cursor-default disabled:opacity-40 ${focusRing}`}
          >
            Forge as the server
          </button>
          <button
            type="button"
            onClick={status.kind === "killed" ? reset : () => send("org")}
            disabled={busy}
            className={`inline-flex h-9 cursor-pointer items-center rounded-full bg-control-solid px-4 text-[13px] font-medium text-text-on-control-solid transition-colors hover:bg-control-solid-hover disabled:cursor-default disabled:opacity-40 ${focusRing}`}
          >
            {status.kind === "killed" ? "Reset" : "Revoke"}
          </button>
        </div>
      </div>

      {/*
        Fingerprint puts "This is a demo. Production accuracy will be higher."
        directly under the live demo in their hero, and it is the reason a real
        demo can be run without over-claiming. The distinction this line has to
        carry is narrow and load-bearing: the cryptography is real and the fleet
        is not.
      */}
      <p className="relative mt-3 font-mono text-[11px] leading-relaxed text-text-faint">
        Real Ed25519, keys generated in this tab. The processes are simulated;
        the signature is not.
      </p>
    </div>
  );
}
