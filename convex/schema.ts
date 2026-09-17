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
    revocationPublicKey: v.string(),
    wrappedRevocationKey: v.string(),
  }).index("by_slug", ["slug"]),

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
  }).index("by_org", ["orgId"]),

  environments: defineTable({
    projectId: v.id("projects"),
    name: v.string(),
    pdkVersion: v.number(),
    epoch: v.number(),
  }).index("by_project", ["projectId"]),

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
    deletedAt: v.optional(v.number()),
  }).index("by_environment", ["environmentId"]),

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
    tokenId: v.string(),
    epoch: v.number(),
    signature: v.string(),
    signedBy: v.id("users"),
    revokedAt: v.number(),
    reason: v.string(),
  }).index("by_token_id", ["tokenId"]),

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
  }).index("by_org_ts", ["orgId", "ts"]),
});
