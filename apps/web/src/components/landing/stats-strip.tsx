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
 * So the rule for this component is that a number goes in only if running
 * `pnpm -r test`, reading `package.json` or reading section 4 of the plan
 * settles it. "187 tests" is what the suite prints. "0 runtime dependencies"
 * is `packages/crypto/package.json`, which lists two Noble packages as
 * dependencies of the package and ships nothing else into a consumer's runtime
 * graph -- stated as "no runtime dependency on a framework", which is the
 * honest reading and the one the label carries. "5s" is the specified drain
 * window, labelled as specified rather than as measured. "3 runtimes" is the
 * browser, Node and Bun, all three of which the suite is run under.
 *
 * Do not add a fourth kind of number here. There is no user count, no funding
 * line and no uptime, because there are no users, no funding and no uptime.
 */

const STATS = [
  { value: "187", label: "tests across seven files" },
  { value: "0", label: "framework dependencies" },
  { value: "5s", label: "specified drain before exit" },
  { value: "3", label: "runtimes: browser, Node, Bun" },
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
