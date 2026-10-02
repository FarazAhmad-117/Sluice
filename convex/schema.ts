import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  users: defineTable({
    // Permanent id, `usr_` + 32 lowercase hex: see
    // `packages/crypto/src/ids.ts`.
    // Minted by the client before the creating mutation, never changed, and
    // used in every binding that names this row and every external reference
    // instead of the Convex document id, which is local to this deployment. It
    // arrives from a client, so it is attacker-chosen: the shape is checked on
    // the way in and UNIQUENESS IS ENFORCED HERE, through `by_uid`, not
    // assumed from entropy.
    uid: v.string(),
    email: v.string(),
    // The per-account salt `deriveMUK` takes: 16 random bytes, lowercase hex.
    // Minted by the client at signup and never changed (a new salt is a new
    // MUK, and every key wrapped under the old one stops opening). PUBLIC by
    // design: `getLoginSalt` returns it to anyone who asks to log in as this
    // address. Its job is uniqueness across accounts, not secrecy.
    accountSalt: v.string(),
    // HMAC of the client-computed Argon2id verifier, under a server pepper.
    // Never the password, never the MUK. See Task 6.
    authVerifierHash: v.string(),
    publicKey: v.string(), // X25519, hex
    verifyKey: v.string(), // Ed25519, hex
    wrappedPrivateKey: v.string(),
    wrappedSigningKey: v.string(),
    recoveryBlob: v.optional(v.string()),
  })
    .index("by_email", ["email"])
    .index("by_uid", ["uid"]),

  // A dashboard session. This table IS the trust boundary: every query and
  // every mutation in the product resolves its caller by finding a row here,
  // and nothing anywhere resolves a caller from an argument the client chose.
  //
  // Only the hash of the token is stored, for the same reason `serviceTokens`
  // stores `tokenIdHash`. A dump of this table is a list of digests, and a
  // digest cannot be presented as a credential.
  //
  // There is deliberately no `revoked` flag. Logging out DELETES the row, so
  // there is no state in which a session exists and is not usable, and no
  // second place a reader has to remember to check. It also makes logout
  // invalidate every subscribed Convex query that read the row, which a flag
  // would do too, but a flag would additionally leave a growing table of
  // credentials that are only conditionally dead.
  sessions: defineTable({
    userId: v.id("users"),
    tokenHash: v.string(),
    createdAt: v.number(),
    // Absolute, set at login and never moved. See `lib/session.ts`.
    expiresAt: v.number(),
  })
    .index("by_token_hash", ["tokenHash"])
    // "End every session for this user" during an incident, and the cascade
    // when an account is removed.
    .index("by_user", ["userId"])
    // The prune cron. Without it this table grows by one row per login for
    // ever, which is the same unbounded growth `handshakeNonces` already
    // records as a bug.
    .index("by_expiry", ["expiresAt"]),

  orgs: defineTable({
    // Permanent id, `org_` + 32 lowercase hex: see
    // `packages/crypto/src/ids.ts`.
    // Minted by the client before the creating mutation, never changed, and
    // used in every binding that names this row and every external reference
    // instead of the Convex document id, which is local to this deployment. It
    // arrives from a client, so it is attacker-chosen: the shape is checked on
    // the way in and UNIQUENESS IS ENFORCED HERE, through `by_uid`, not
    // assumed from entropy.
    uid: v.string(),
    name: v.string(),
    slug: v.string(),
    // Public material, one per org, so it belongs here. The wrapped private
    // half does not: see `revocationGrants`.
    revocationPublicKey: v.string(),
  })
    .index("by_slug", ["slug"])
    .index("by_uid", ["uid"]),

  // The revocation signing key, wrapped once per user who is allowed to sign.
  // This used to be a single `orgs.wrappedRevocationKey`, which made the
  // product's entire wedge depend on one person not leaving, not forgetting
  // their password, and not being the one whose laptop was stolen. That last
  // case is the scenario revocation exists for, which made it worse than an
  // ordinary bus-factor problem.
  //
  // Unlike `pdkGrants` there is no `granteeType`: only a user can sign a
  // revocation, so the grantee is typed as a user id rather than a string.
  revocationGrants: defineTable({
    orgId: v.id("orgs"),
    // THE JOIN KEY, NOT THE BINDING. This is the `users` document id, typed as
    // a real reference so a migration between cells remaps it with the row it
    // points at. What the wrapped key is cryptographically bound to is
    // different: the client seals it under associated data naming the
    // grantee's permanent `usr_` uid, which it reads from the `users` row this
    // column points to. Do not put the uid here, and do not put this id into
    // the associated data.
    granteeId: v.id("users"),
    wrappedRevocationKey: v.string(),
    nonce: v.string(),
  }).index("by_org_grantee", ["orgId", "granteeId"]),

  orgMembers: defineTable({
    orgId: v.id("orgs"),
    userId: v.id("users"),
    role: v.union(v.literal("owner"), v.literal("admin"), v.literal("member")),
  })
    .index("by_org_user", ["orgId", "userId"])
    .index("by_user", ["userId"]),

  projects: defineTable({
    orgId: v.id("orgs"),
    name: v.string(),
    slug: v.string(),
  })
    // Prefix-queried by orgId alone for the listing, so there is no separate
    // by_org. The second field makes the duplicate-slug check in Task 8 a real
    // lookup; with only by_org it was a scan a contributor could quietly skip.
    .index("by_org_slug", ["orgId", "slug"]),

  environments: defineTable({
    // Permanent id, `env_` + 32 lowercase hex: see
    // `packages/crypto/src/ids.ts`.
    // Minted by the client before the creating mutation, never changed, and
    // used in every binding that names this row and every external reference
    // instead of the Convex document id, which is local to this deployment. It
    // arrives from a client, so it is attacker-chosen: the shape is checked on
    // the way in and UNIQUENESS IS ENFORCED HERE, through `by_uid`, not
    // assumed from entropy.
    uid: v.string(),
    projectId: v.id("projects"),
    // The owning org, copied from a row the authorisation walk already
    // loaded, never from a caller. It is reachable through `projectId` too, but
    // an org must be liftable into another cell in ONE indexed read per table,
    // and a per-org quota needs a direct count rather than a walk.
    orgId: v.id("orgs"),
    name: v.string(),
    pdkVersion: v.number(),
    epoch: v.number(),
  })
    // Prefix-queried by projectId alone for the listing. The second field is
    // how the SDK addresses a config, org/project/environment by name, and is
    // also the uniqueness check when an environment is created.
    .index("by_project_name", ["projectId", "name"])
    .index("by_uid", ["uid"])
    .index("by_org", ["orgId"]),

  // THE ONE HOME FOR A WRAPPED PROJECT DATA KEY. THERE IS NO SECOND ONE.
  //
  // `serviceTokens` carried `wrappedPDK` and `nonce` of its own until this
  // commit, while this table existed for the same purpose and already had
  // `"token"` in its `granteeType` union. Two authoritative homes for one blob,
  // with nothing that fails when they disagree, is the defect class that
  // produced the duplicate associated-data definition: the bundle would ship
  // one of them, the dashboard would read the other, and a re-key that updated
  // only one would hand a live workload a key the stored ciphertext is not
  // under. Nothing would throw.
  //
  // THE COLUMN LOST RATHER THAN THE TABLE, and the choice is not close. A
  // project data key must reach USERS as well as tokens, and a user is not a
  // service token row, so deleting this table would mean inventing it again
  // under another name the moment the dashboard can decrypt anything. The
  // column was the shortcut.
  //
  // The counter-argument was real and is answered: the bundle is the product's
  // hottest query and now does one extra read. That read is
  // `by_environment_grantee` with all three fields equal, which is a single
  // indexed point lookup on a query that already performs four. Neither table
  // had a row when this was decided, so the merge cost nothing exactly once.
  //
  // `granteeId` IS A STRING BECAUSE THE TWO GRANTEE NAMESPACES ARE NOT THE SAME
  // KIND OF THING, AND NEITHER IS A CONVEX DOCUMENT ID. For a user it is the
  // permanent `usr_` uid from `users.uid`. For a token it is the
  // `tokenIdHash`, NOT the `serviceTokens` document id, because the bundle
  // knows an authenticated token only by its hash. In both cases the value is
  // the one the client names in the associated data it wraps under, spelled
  // exactly as stored here, so the server's lookup key and the client's
  // binding are one string. A document id would be wrong twice over: it is
  // not what the binding names, and inside a `v.string()` a migration to
  // another cell would carry it across unremapped, pointing at nothing.
  // `granteeType` is what keeps the two namespaces from colliding in one
  // index.
  pdkGrants: defineTable({
    environmentId: v.id("environments"),
    // The owning org, copied from a row the authorisation walk already
    // loaded, never from a caller. It is reachable through `environmentId`
    // too, but an org must be liftable into another cell in ONE indexed read
    // per table, and a per-org quota needs a direct count rather than a walk.
    orgId: v.id("orgs"),

    granteeType: v.union(v.literal("user"), v.literal("token")),
    granteeId: v.string(),
    wrappedPDK: v.string(),
    nonce: v.string(),
    // WHICH project data key version this blob opens. The client wraps under
    // `pdkAssociatedData`, which binds this version, so it STATES the version
    // it wrapped under, and the writing mutation checks that it equals the
    // environment's current `pdkVersion` (exactly 1 in `createEnvironment`)
    // and refuses otherwise, writing nothing. The value stored is then the
    // environment's, which by that check is also exactly what the bytes name;
    // a caller can make a write fail but cannot make this column say
    // anything else. Without the column the bundle would have to report
    // `environments.pdkVersion` beside a wrapped key from this row: two rows
    // describing one key, free to disagree, which is the very thing the
    // column above was deleted for.
    pdkVersion: v.number(),
  })
    // Prefix-queried by `environmentId` alone for "every grant on this
    // environment", and read with all three fields equal for "this grantee's
    // grant", which is the bundle's lookup and the dashboard's. One index, two
    // queries, no scan.
    .index("by_environment_grantee", [
      "environmentId",
      "granteeType",
      "granteeId",
    ])
    // "Everything this grantee can open", which the index above cannot answer
    // because it is keyed by environment first.
    .index("by_grantee", ["granteeType", "granteeId"])
    .index("by_org", ["orgId"]),

  secrets: defineTable({
    environmentId: v.id("environments"),
    // The owning org, copied from a row the authorisation walk already
    // loaded, never from a caller. It is reachable through `environmentId`
    // too, but an org must be liftable into another cell in ONE indexed read
    // per table, and a per-org quota needs a direct count rather than a walk.
    orgId: v.id("orgs"),

    // The secret's PERMANENT id, `sec_` + 32 lowercase hex: see
    // `packages/crypto/src/ids.ts`. Every version of one logical secret shares
    // it. Without it versioning is unrepresentable: the name is ciphertext
    // under a random nonce, so two versions of the same secret are not
    // comparable byte for byte and nothing else links the rows.
    //
    // MINTED BY THE CLIENT, NOT BY THIS SERVER, because the client seals both
    // fields under `secretAssociatedData({ environmentUid, secretUid, version,
    // field })` and must know the id before the first write. The server never
    // computes that associated data. Its job is to STORE EXACTLY the
    // `secretUid` and `version` the client sealed under and hand both back, so
    // a reader can rebuild the bytes. A row whose stored slot differs from the
    // slot it was sealed under does not open, which is what turns a
    // server-side splice (swapping ciphertext between rows, or rolling one
    // back to an older version) into a loud failure instead of a wrong value.
    // The id arrives from a client, so it is attacker-chosen: `createSecret`
    // checks the shape and refuses an id any row already carries, through
    // `by_secret_version`, in the same mutation as the insert.
    secretUid: v.string(),
    // Both name and value are ciphertext. The name is encrypted because a
    // plaintext column full of STRIPE_LIVE_SECRET_KEY tells an attacker with
    // database access exactly which ciphertext to prioritise, and tells the
    // operator something they publicly claim not to know.
    nameCiphertext: v.string(),
    nameNonce: v.string(),
    valueCiphertext: v.string(),
    valueNonce: v.string(),
    pdkVersion: v.number(),
    // The version the client sealed THIS row under, bound into its associated
    // data, stored exactly as sealed. 1 on create; on update exactly the
    // current row's version plus one, enforced as a compare-and-set in
    // `updateSecret`, so a write prepared against a version that is no longer
    // current fails loudly instead of landing.
    version: v.number(),
    // Set when a newer version of the same secret replaces this row. Unset
    // means current. There is deliberately no `isCurrent` boolean: it would
    // restate what this field already says and the two could disagree.
    supersededAt: v.optional(v.number()),
    deletedAt: v.optional(v.number()),
    // Links the per-environment rows of ONE shared secret ("All environments").
    // Absent on a secret that lives in one environment only. Plaintext metadata,
    // bound into nothing: see packages/crypto/src/ids.ts on `shr_`.
    shareUid: v.optional(v.string()),
    // On a shared row: true when this environment keeps its own value instead of
    // the shared one. Absent on non-shared rows.
    overridden: v.optional(v.boolean()),
  })
    // One index serves three queries by prefix, which is why there is no
    // separate `by_environment`:
    //   [environmentId]                                -> every row, all history
    //   [environmentId, supersededAt=undefined]        -> current, including deleted
    //   [environmentId, supersededAt, deletedAt]       -> current and live
    // The last is the dashboard load and the bundle fetch, so it has to be a
    // single indexed read rather than a scan and a filter. Convex indexes a
    // missing field as `undefined`, so `eq(field, undefined)` is a real index
    // lookup, not a predicate applied after the fact.
    .index("by_environment_current", [
      "environmentId",
      "supersededAt",
      "deletedAt",
    ])
    .index("by_secret_version", ["secretUid", "version"])
    // Every row of one shared secret, across the project's environments. Read
    // for `createSharedSecret`'s uniqueness check and `deleteSharedSecret`'s
    // fan-out.
    .index("by_share", ["shareUid"])
    .index("by_org", ["orgId"]),

  serviceTokens: defineTable({
    environmentId: v.id("environments"),
    // The owning org, copied from a row the authorisation walk already
    // loaded, never from a caller. It is reachable through `environmentId`
    // too, but an org must be liftable into another cell in ONE indexed read
    // per table, and a per-org quota needs a direct count rather than a walk.
    orgId: v.id("orgs"),

    // The id is stored hashed so a database reader cannot enumerate valid
    // identifiers. Lookups hash the incoming id and match on this.
    tokenIdHash: v.string(),
    publicKey: v.string(),
    // NO `wrappedPDK` AND NO `nonce`. They lived here and in `pdkGrants` at the
    // same time, for the same blob, with nothing that failed when the two
    // disagreed. `pdkGrants` won; see the note on that table. Do not put them
    // back: a second home is not a cache, it is a second answer.
    epoch: v.number(),
    status: v.union(v.literal("active"), v.literal("revoked")),
    lastSeenAt: v.optional(v.number()),
    expiresAt: v.optional(v.number()),
  })
    .index("by_token_id_hash", ["tokenIdHash"])
    .index("by_environment", ["environmentId"])
    .index("by_org", ["orgId"]),

  revocations: defineTable({
    // Both forms of the identifier are stored on purpose. Do not "clean up"
    // this duplication.
    //
    // `tokenId` is the plaintext id because the notice is signed over it and
    // the SDK matches on it; hashing it would break verification.
    //
    // `tokenIdHash` exists because `serviceTokens` stores only the hash, so
    // without this column there is no join from an authenticated token to its
    // revocation and the bundle query in Task 11 cannot find the notice. The
    // alternative was carrying the plaintext id in the handshake JWT, which
    // would push the very identifier `tokenIdHash` exists to protect into a
    // bearer token, into SDK memory, and into every log that prints a JWT.
    // One denormalised column is far cheaper than that.
    tokenId: v.string(),
    tokenIdHash: v.string(),
    // The environment the revoked token belonged to, and its org. Neither is
    // signed -- the notice covers the token id and epoch -- they are here so
    // that every tenant row can be found by org in one indexed read, and so a
    // revocation stays attributable after its token row is gone. Both are
    // copied from the token row the mutation loaded, never from a caller.
    orgId: v.id("orgs"),
    environmentId: v.id("environments"),
    epoch: v.number(),
    signature: v.string(),
    signedBy: v.id("users"),
    revokedAt: v.number(),
    reason: v.string(),
  })
    .index("by_token_id", ["tokenId"])
    .index("by_token_id_hash", ["tokenIdHash"])
    .index("by_org", ["orgId"]),

  // Replay protection for the handshake. Ed25519 signatures are deterministic,
  // so the same token id and timestamp always produce the same signature.
  // Verification proves authenticity, not freshness. See Task 10.
  handshakeNonces: defineTable({
    signatureHash: v.string(),
    expiresAt: v.number(),
  })
    .index("by_signature_hash", ["signatureHash"])
    .index("by_expiry", ["expiresAt"]),

  auditLog: defineTable({
    orgId: v.id("orgs"),
    actorType: v.union(
      v.literal("user"),
      v.literal("token"),
      v.literal("system"),
    ),
    actorId: v.string(),
    action: v.string(),
    targetId: v.optional(v.string()),
    ip: v.optional(v.string()),
    ts: v.number(),
    metadata: v.optional(v.string()),
  })
    .index("by_org_ts", ["orgId", "ts"])
    // "Everything this actor did, in order" is the first query anyone runs
    // during an incident, and by_org_ts cannot answer it.
    .index("by_actor_ts", ["actorId", "ts"]),
});
