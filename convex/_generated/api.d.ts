/* eslint-disable */
/**
 * Generated `api` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type * as auth from "../auth.js";
import type * as bundle from "../bundle.js";
import type * as crons from "../crons.js";
import type * as environments from "../environments.js";
import type * as handshake from "../handshake.js";
import type * as http from "../http.js";
import type * as lib_audit from "../lib/audit.js";
import type * as lib_authz from "../lib/authz.js";
import type * as lib_email from "../lib/email.js";
import type * as lib_handshake from "../lib/handshake.js";
import type * as lib_hex from "../lib/hex.js";
import type * as lib_jwt from "../lib/jwt.js";
import type * as lib_naming from "../lib/naming.js";
import type * as lib_session from "../lib/session.js";
import type * as lib_verifier from "../lib/verifier.js";
import type * as orgs from "../orgs.js";
import type * as projects from "../projects.js";
import type * as repo_audit from "../repo/audit.js";
import type * as repo_environments from "../repo/environments.js";
import type * as repo_orgs from "../repo/orgs.js";
import type * as repo_projects from "../repo/projects.js";
import type * as repo_secrets from "../repo/secrets.js";
import type * as repo_sessions from "../repo/sessions.js";
import type * as repo_tokens from "../repo/tokens.js";
import type * as repo_users from "../repo/users.js";
import type * as secrets from "../secrets.js";
import type * as sessions from "../sessions.js";
import type * as tokens from "../tokens.js";

import type {
  ApiFromModules,
  FilterApi,
  FunctionReference,
} from "convex/server";

declare const fullApi: ApiFromModules<{
  auth: typeof auth;
  bundle: typeof bundle;
  crons: typeof crons;
  environments: typeof environments;
  handshake: typeof handshake;
  http: typeof http;
  "lib/audit": typeof lib_audit;
  "lib/authz": typeof lib_authz;
  "lib/email": typeof lib_email;
  "lib/handshake": typeof lib_handshake;
  "lib/hex": typeof lib_hex;
  "lib/jwt": typeof lib_jwt;
  "lib/naming": typeof lib_naming;
  "lib/session": typeof lib_session;
  "lib/verifier": typeof lib_verifier;
  orgs: typeof orgs;
  projects: typeof projects;
  "repo/audit": typeof repo_audit;
  "repo/environments": typeof repo_environments;
  "repo/orgs": typeof repo_orgs;
  "repo/projects": typeof repo_projects;
  "repo/secrets": typeof repo_secrets;
  "repo/sessions": typeof repo_sessions;
  "repo/tokens": typeof repo_tokens;
  "repo/users": typeof repo_users;
  secrets: typeof secrets;
  sessions: typeof sessions;
  tokens: typeof tokens;
}>;

/**
 * A utility for referencing Convex functions in your app's public API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = api.myModule.myFunction;
 * ```
 */
export declare const api: FilterApi<
  typeof fullApi,
  FunctionReference<any, "public">
>;

/**
 * A utility for referencing Convex functions in your app's internal API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = internal.myModule.myFunction;
 * ```
 */
export declare const internal: FilterApi<
  typeof fullApi,
  FunctionReference<any, "internal">
>;

export declare const components: {};
