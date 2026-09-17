import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  users: defineTable({
    email: v.string(),
    // HMAC of the client-computed Argon2id verifier, under a server pepper.
    // Never the password, never the MUK. See Task 6.
    authVerifierHash: v.string(),
    publicKey: v.string(), // X25519, hex
    verifyKey: v.string(), // Ed25519, hex
    wrappedPrivateKey: v.string(),
    wrappedSigningKey: v.string(),
    recoveryBlob: v.optional(v.string()),
  }).index("by_email", ["email"]),

  orgs: defineTable({
    name: v.string(),
    slug: v.string(),
    // Public material, one per org, so it belongs here. The wrapped private
    // half does not: see `revocationGrants`.
    revocationPublicKey: v.string(),
  }).index("by_slug", ["slug"]),

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
    projectId: v.id("projects"),
    name: v.string(),
    pdkVersion: v.number(),
    epoch: v.number(),
  })
    // Prefix-queried by projectId alone for the listing. The second field is
    // how the SDK addresses a config, org/project/environment by name, and is
    // also the uniqueness check when an environment is created.
    .index("by_project_name", ["projectId", "name"]),

  pdkGrants: defineTable({
    environmentId: v.id("environments"),
    granteeType: v.union(v.literal("user"), v.literal("token")),
    granteeId: v.string(),
    wrappedPDK: v.string(),
    nonce: v.string(),
  })
    .index("by_environment", ["environmentId"])
    .index("by_grantee", ["granteeType", "granteeId"]),

  secrets: defineTable({
    environmentId: v.id("environments"),
    // Every version of one logical secret shares a `lineageId`. Without it
    // versioning is unrepresentable: the name is ciphertext under a random
    // nonce, so two versions of the same secret are not comparable byte for
    // byte and nothing else links the rows. You could have history or a usable
    // listing, not both.
    lineageId: v.string(),
    // Both name and value are ciphertext. The name is encrypted because a
    // plaintext column full of STRIPE_LIVE_SECRET_KEY tells an attacker with
    // database access exactly which ciphertext to prioritise, and tells the
    // operator something they publicly claim not to know.
    nameCiphertext: v.string(),
    nameNonce: v.string(),
    valueCiphertext: v.string(),
    valueNonce: v.string(),
    pdkVersion: v.number(),
    version: v.number(),
    // Set when a newer version of the same lineage replaces this row. Unset
    // means current. There is deliberately no `isCurrent` boolean: it would
    // restate what this field already says and the two could disagree.
    supersededAt: v.optional(v.number()),
    deletedAt: v.optional(v.number()),
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
    .index("by_lineage_version", ["lineageId", "version"]),

  serviceTokens: defineTable({
    environmentId: v.id("environments"),
    // The id is stored hashed so a database reader cannot enumerate valid
    // identifiers. Lookups hash the incoming id and match on this.
    tokenIdHash: v.string(),
    publicKey: v.string(),
    wrappedPDK: v.string(),
    nonce: v.string(),
    epoch: v.number(),
    status: v.union(v.literal("active"), v.literal("revoked")),
    lastSeenAt: v.optional(v.number()),
    expiresAt: v.optional(v.number()),
  })
    .index("by_token_id_hash", ["tokenIdHash"])
    .index("by_environment", ["environmentId"]),

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
    epoch: v.number(),
    signature: v.string(),
    signedBy: v.id("users"),
    revokedAt: v.number(),
    reason: v.string(),
  })
    .index("by_token_id", ["tokenId"])
    .index("by_token_id_hash", ["tokenIdHash"]),

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
