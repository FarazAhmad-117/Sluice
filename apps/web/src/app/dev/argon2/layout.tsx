import { notFound } from "next/navigation";

/**
 * Gate for the Argon2 measurement harness.
 *
 * The page it wraps derives keys in the browser and prints one in full. The
 * key it prints is only ever the published known-answer vector, never user
 * input, but a route that renders a derived key is not a pattern that belongs
 * on a public deployment, and someone will copy it.
 *
 * `NODE_ENV` is set to "production" by `next build`, so this returns a 404 on
 * anything Vercel serves while leaving the harness available under `next dev`.
 * Checked in a layout rather than in the page so it cannot be bypassed by a
 * future sibling route added under `/dev`.
 */
export default function DevOnlyLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  if (process.env.NODE_ENV === "production") notFound();
  return children;
}
