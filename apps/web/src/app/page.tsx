import { Contributors } from "@/components/landing/contributors";
import { Hero } from "@/components/landing/hero";
import { Quickstart } from "@/components/landing/quickstart";
import { Revocation } from "@/components/landing/revocation";
import { SiteNav } from "@/components/landing/site-nav";
import { ThreatModel } from "@/components/landing/threat-model";

export default function Home() {
  return (
    <>
      <SiteNav />
      <main>
        <Hero />
        <Quickstart />
        <Revocation />
        <ThreatModel />
        <Contributors />
      </main>
    </>
  );
}
