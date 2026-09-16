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
      <div className="flex items-center gap-6">
        <button
          type="button"
          className="w-fit cursor-pointer rounded-input bg-brand-solid px-4 py-2 font-sans text-base font-medium text-text-on-brand-solid transition-colors hover:bg-brand-solid-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand"
        >
          Filled control
        </button>
        <a
          href="https://github.com/FarazAhmad-117/Sluice"
          className="cursor-pointer font-sans text-base text-brand underline underline-offset-4 transition-colors hover:text-brand-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand"
        >
          Brand as link text
        </a>
      </div>
    </main>
  );
}
