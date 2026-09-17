/* eslint-disable */
/**
 * Generated `api` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type * as repo_audit from "../repo/audit.js";
import type * as repo_environments from "../repo/environments.js";
import type * as repo_orgs from "../repo/orgs.js";
import type * as repo_projects from "../repo/projects.js";
import type * as repo_secrets from "../repo/secrets.js";
import type * as repo_tokens from "../repo/tokens.js";
import type * as repo_users from "../repo/users.js";

import type {
  ApiFromModules,
  FilterApi,
  FunctionReference,
} from "convex/server";

declare const fullApi: ApiFromModules<{
  "repo/audit": typeof repo_audit;
  "repo/environments": typeof repo_environments;
  "repo/orgs": typeof repo_orgs;
  "repo/projects": typeof repo_projects;
  "repo/secrets": typeof repo_secrets;
  "repo/tokens": typeof repo_tokens;
  "repo/users": typeof repo_users;
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
