/**
 * SERVER ERROR SENTENCES THAT A CLIENT MATCHES ON.
 *
 * Convex errors cross the wire as a `ConvexError` whose `data` is a sentence,
 * not a code. When a client must react to one specific refusal, it can only do
 * so by comparing that sentence, and a sentence restated on both sides is one
 * edit away from drifting: the server rewords it, the client's match silently
 * stops firing, and nobody notices. Each such sentence is therefore defined
 * once, here, and imported by both the mutation that throws it and the client
 * that recognises it.
 *
 * THIS FILE MUST NOT IMPORT ANYTHING. The dashboard pulls it into the browser
 * bundle through the `@convex` alias, so an import of `./_generated/server`,
 * a repo module or any server-only library here would ship server code to the
 * browser. Plain string constants only.
 */

/**
 * `auth.signup`'s refusal when the client-minted `usr_` uid is already held by
 * another account. With 128 random bits this should never happen honestly; if
 * it does, it is a broken random source or a replayed request, and submitting
 * again, which mints a fresh uid, is the correct remedy.
 */
export const DUPLICATE_UID = "An account already exists with that uid.";
