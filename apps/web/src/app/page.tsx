import { Hero } from "@/components/landing/hero";
import { SiteNav } from "@/components/landing/site-nav";

export default function Home() {
  return (
    <>
      <SiteNav />
      <main>
        <Hero />
      </main>
    </>
  );
}
