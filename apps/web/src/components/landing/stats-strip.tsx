import { Container } from "@/components/landing/primitives";
import { Reveal } from "@/components/landing/motion";

/**
 * The band of numbers directly under the hero.
 *
 * Every figure here is checkable by the reader in about a minute, which is the
 * only reason this section is allowed to exist. A strip of impressive-looking
 * numbers is the most over-used device on a developer landing page and it is
 * usually where the lying starts: uptime nobody measured, customers nobody
 * named, latency from a benchmark nobody published.
 *
 * So the rule for this component is that a number goes in only if running the
 * suite or reading one named file settles it:
 *
 *   892       `pnpm test` at the root prints 323 and `pnpm -r test` prints
 *             259 + 124 + 93 + 85 + 8. Six packages, one total.
 *   599,184   `packages/sdk/test/property.test.ts`. The decision core's
 *             "connection loss never kills a process" property is ENUMERATED
 *             over that many event sequences rather than sampled from them,
 *             which is why the label says proven and not tested.
 *   5s        the default drain window before a revoked process exits, from
 *             `SLUICE_DRAIN_MS` in `packages/cli/src/main.ts`. Specified and
 *             implemented, not a measured field number.
 *   0         `SECURITY.md`: the server stores public keys, wrapped blobs it
 *             cannot open, and ciphertext. Nothing that could open customer
 *             data is stored server side.
 *
 * Do not add a fifth kind of number here. There is no user count, no funding
 * line, no uptime and no latency figure, because there are no users, no
 * funding, no uptime measurement and no published benchmark.
 */

const STATS = [
  { value: "892", label: "tests across six packages" },
  { value: "599,184", label: "event sequences the kill switch is proven over" },
  { value: "5s", label: "drain before a revoked process exits" },
  { value: "0", label: "keys on the server that can decrypt a secret" },
] as const;

export function StatsStrip() {
  return (
    <section
      aria-label="Project facts"
      className="border-y border-hairline bg-gradient-to-b from-white/[0.015] to-transparent"
    >
      <Container className="grid grid-cols-2 lg:grid-cols-4">
        {STATS.map((stat, index) => (
          <Reveal
            key={stat.value + stat.label}
            delay={index * 80}
            className="border-l border-hairline px-6 py-7 max-lg:border-b lg:last:border-r"
          >
            <p className="text-[30px] leading-none font-semibold tracking-[-0.04em] text-text-primary">
              {stat.value}
            </p>
            <p className="mt-2 text-[13px] text-text-muted">{stat.label}</p>
          </Reveal>
        ))}
      </Container>
    </section>
  );
}
