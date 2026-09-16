import { Hero } from "@/components/landing/hero";
import { Quickstart } from "@/components/landing/quickstart";
import { SiteNav } from "@/components/landing/site-nav";

export default function Home() {
  return (
    <>
      <SiteNav />
      <main>
        <Hero />
        <Quickstart />
      </main>
    </>
  );
}
