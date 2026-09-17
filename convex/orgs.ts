import { ConvexError, v } from "convex/values";
import { mutation, query } from "./_generated/server";
import type { Id } from "./_generated/dataModel";
import { recordUserEvent } from "./lib/audit";
import {
  sessionArg,
  requireOrg,
  requireSession,
  NOT_PERMITTED,
} from "./lib/authz";
import { assertHexBytes } from "./lib/hex";
import { assertDisplayName, assertSlug } from "./lib/naming";
import {
  getOrg as getOrgRow,
  getOrgBySlug,
  getRevocationGrant,
  insertOrg,
  insertOrgMember,
  insertRevocationGrant,
  listOrgMembersByUser,
} from "./repo/orgs";

/**
 * An organisation is the unit of tenancy and the unit of revocation. Nothing
 * below it, and no secret, is reachable without a membership row.
 */

const DUPLICATE_SLUG = "An organisation with that slug already exists.";

// Ed25519 public key, 32 bytes.
const REVOCATION_PUBLIC_KEY_BYTES = 32;
// AES-GCM nonce, 96 bits, which is the only width `@sluice/crypto` produces.
const NONCE_BYTES = 12;

export const createOrg = mutation({
  args: {
    ...sessionArg,
    name: v.string(),
    slug: v.string(),
    // The public half of the org revocation keypair. Public material, one per
    // org, and the value customers pin in their own configuration.
    revocationPublicKey: v.string(),
    // The private half, wrapped to the creator's master unlock key. The server
    // cannot open it and must never be able to.
    wrappedRevocationKey: v.string(),
    revocationKeyNonce: v.string(),
  },
  returns: v.id("orgs"),
  handler: async (ctx, args): Promise<Id<"orgs">> => {
    const user = await requireSession(ctx, args.sessionToken);

    const name = assertDisplayName("name", args.name);
    const slug = assertSlug("slug", args.slug);
    assertHexBytes(
      "revocationPublicKey",
      args.revocationPublicKey,
      REVOCATION_PUBLIC_KEY_BYTES,
    );
    // The nonce is checked by shape and the wrapped key is not, which looks
    // inconsistent and is not. A nonce has exactly one correct width: AES-GCM
    // accepts any length and derives its counter block through GHASH when the
    // nonce is not 96 bits, so a wrong-width nonce decrypts happily and
    // silently leaves the construction the package was reviewed under. The
    // wrapped key is an opaque blob whose internal format is the client's
    // business, and the server has no way to check it beyond "not empty".
    assertHexBytes("revocationKeyNonce", args.revocationKeyNonce, NONCE_BYTES);
    if (args.wrappedRevocationKey.length === 0) {
      throw new ConvexError("wrappedRevocationKey must not be empty.");
    }

    // A real indexed lookup rather than a scan and a filter, which is why
    // `by_slug` exists. Convex mutations are serialisable transactions, so
    // read-then-insert here is not a race: a concurrent create with the same
    // slug conflicts and retries, and the retry sees this row.
    if ((await getOrgBySlug(ctx, slug)) !== null) {
      throw new ConvexError(DUPLICATE_SLUG);
    }

    const orgId = await insertOrg(ctx, {
      name,
      slug,
      revocationPublicKey: args.revocationPublicKey,
    });

    await insertOrgMember(ctx, { orgId, userId: user._id, role: "owner" });

    // THE GRANT IS CREATED HERE, IN THIS MUTATION, AND THIS IS THE ENTIRE
    // REASON `revocationGrants` EXISTS AS A TABLE.
    //
    // `orgs.wrappedRevocationKey` was removed from the schema so that the
    // signing key could be wrapped to more than one person. The cost of that
    // change is that an org and its first grant are now two rows, and an org
    // written without one is an org for which no revocation notice can ever be
    // signed: the product's whole wedge, broken at creation time, discovered
    // during the incident it exists for. Convex mutations are atomic, so the
    // two rows either both land or neither does, and that atomicity is the
    // only thing making this safe. Never split this across two mutations, and
    // never add a second way to insert into `orgs`.
    await insertRevocationGrant(ctx, {
      orgId,
      granteeId: user._id,
      wrappedRevocationKey: args.wrappedRevocationKey,
      nonce: args.revocationKeyNonce,
    });

    await recordUserEvent(ctx, {
      orgId,
      actorId: user._id,
      action: "org.create",
      targetId: orgId,
    });

    return orgId;
  },
});

export const getOrg = query({
  args: { ...sessionArg, orgId: v.id("orgs") },
  returns: v.object({
    orgId: v.id("orgs"),
    name: v.string(),
    slug: v.string(),
    revocationPublicKey: v.string(),
    role: v.union(v.literal("owner"), v.literal("admin"), v.literal("member")),
  }),
  handler: async (ctx, args) => {
    const { org, member } = await requireOrg(ctx, args.sessionToken, args.orgId);
    // No wrapped key material. `revocationPublicKey` is public by design and
    // the wrapped private half is reachable only through the grant below, and
    // only by its own grantee.
    return {
      orgId: org._id,
      name: org.name,
      slug: org.slug,
      revocationPublicKey: org.revocationPublicKey,
      role: member.role,
    };
  },
});

export const listMyOrgs = query({
  args: { ...sessionArg },
  returns: v.array(
    v.object({
      orgId: v.id("orgs"),
      name: v.string(),
      slug: v.string(),
      revocationPublicKey: v.string(),
      role: v.union(
        v.literal("owner"),
        v.literal("admin"),
        v.literal("member"),
      ),
    }),
  ),
  handler: async (ctx, args) => {
    const user = await requireSession(ctx, args.sessionToken);
    // Driven from `orgMembers` by user, never from a scan of `orgs` filtered
    // afterwards. The listing can only ever contain orgs this user is in
    // because membership is what it iterates.
    const memberships = await listOrgMembersByUser(ctx, user._id);

    const out = [];
    for (const membership of memberships) {
      const org = await getOrgRow(ctx, membership.orgId);
      // A membership pointing at an org that is gone is skipped rather than
      // thrown on. Nothing deletes orgs today; if something ever does, one
      // dangling row must not make the whole dashboard unloadable.
      if (org === null) continue;
      out.push({
        orgId: org._id,
        name: org.name,
        slug: org.slug,
        revocationPublicKey: org.revocationPublicKey,
        role: membership.role,
      });
    }
    return out;
  },
});

/**
 * The caller's own wrapped revocation key, for unwrapping with their master
 * unlock key before signing a notice.
 *
 * It takes no grantee argument, and that is the authorisation: the only grant
 * anyone can read is their own. A `granteeId` parameter would make this an
 * endpoint for fetching other people's wrapped key material, which is useless
 * to them but is exactly the kind of read that looks harmless in review.
 */
export const getMyRevocationGrant = query({
  args: { ...sessionArg, orgId: v.id("orgs") },
  returns: v.object({
    wrappedRevocationKey: v.string(),
    nonce: v.string(),
    revocationPublicKey: v.string(),
  }),
  handler: async (ctx, args) => {
    const { org, user } = await requireOrg(ctx, args.sessionToken, args.orgId);
    const grant = await getRevocationGrant(ctx, org._id, user._id);
    // A member without a grant is a member who cannot sign, which is a real
    // state once grants are issued to some members and not others. It answers
    // with the shared refusal rather than a distinct message, so it cannot be
    // used to map who in an org holds signing power.
    if (grant === null) throw new ConvexError(NOT_PERMITTED);
    return {
      wrappedRevocationKey: grant.wrappedRevocationKey,
      nonce: grant.nonce,
      revocationPublicKey: org.revocationPublicKey,
    };
  },
});
