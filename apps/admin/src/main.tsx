import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider } from "react-router";
import { router } from "./routes";
import "./app.css";

/**
 * THE ENTRY POINT.
 *
 * `index.html` declares `<div id="root">` and this fills it. Everything else --
 * providers, the guard, the routes -- is declared in `routes.tsx`, so this file
 * stays the one place that knows about the DOM.
 *
 * THE THROW IS DELIBERATE. A missing mount node means `index.html` and this
 * file have gone out of step, which is a build problem rather than a runtime
 * condition, and it has no recovery worth writing: there is nowhere to render
 * the apology. Failing loudly in the console beats `createRoot(null!)` and a
 * blank page with no explanation.
 *
 * `StrictMode` IS ON, and it is worth knowing what that costs here. In
 * development it mounts every component twice, so effects run twice -- which is
 * exactly what caught the key-derivation single-flight guard being necessary,
 * and what would catch the next effect that assumes it runs once. Nothing in
 * this application derives a key from an effect, so the double mount costs
 * render time and nothing else.
 */
const container = document.getElementById("root");
if (container === null) {
  throw new Error('No #root element in index.html. The mount point and main.tsx disagree.');
}

createRoot(container).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
);
