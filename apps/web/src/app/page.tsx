import { Hero } from "@/components/landing/hero";
import { Quickstart } from "@/components/landing/quickstart";
import { Revocation } from "@/components/landing/revocation";
import { SiteNav } from "@/components/landing/site-nav";

export default function Home() {
  return (
    <>
      <SiteNav />
      <main>
        <Hero />
        <Quickstart />
        <Revocation />
      </main>
    </>
  );
}
