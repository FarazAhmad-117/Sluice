export default function Home() {
  return (
    <main className="mx-auto flex min-h-[100dvh] w-full max-w-2xl flex-col justify-center gap-6 px-4 py-16">
      <h1 className="font-sans text-4xl font-medium tracking-tight text-text-primary">
        Token smoke test
      </h1>
      <p className="font-sans text-base text-text-muted">
        This page exists to prove the tokens resolve. Surface, text, brand and
        radius all come from custom properties. Nothing here names a colour.
      </p>
      <p className="font-mono text-base text-text-muted">
        SLUICE_TOKEN revoked at 2026-09-16T14:02:11Z
      </p>
      <button
        type="button"
        className="w-fit cursor-pointer rounded-input bg-brand px-4 py-2 font-sans text-base font-medium text-text-on-brand transition-colors hover:bg-brand-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand"
      >
        Brand button
      </button>
    </main>
  );
}
