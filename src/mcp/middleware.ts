import { ErrorCode, createErrorEnvelope, ErrorEnvelope } from '../shared/errors';
import { normalizeRepoIdentifier, resolveRepoIdentity, RepoIdentity } from '../core/repo';

// Types for the MCP Tool Context
export interface ToolContext {
  repoStore: any; // Replace with actual RepoStore interface
  maxResultSize?: number;
}

export type ToolHandler = (args: any, identity: RepoIdentity) => Promise<unknown>;

/**
 * Wraps an MCP tool handler with:
 * 1. Parameter validation (Repo existence).
 * 2. Repo Normalization.
 * 3. Identity Resolution (Fingerprint/Index check).
 * 4. Max Result Size enforcement.
 * 5. Canonical Error Mapping.
 */
export function withRepoHandling(
  handler: ToolHandler,
  context: ToolContext
) {
  return async (args: { repo?: string; [key: string]: any }): Promise<unknown> => {
    try {
      // 1. Check for missing repo parameter
      if (!args.repo) {
        return createErrorEnvelope(
          ErrorCode.MISSING_REPO,
          'The "repo" parameter is required but was not provided.'
        );
      }

      // 2. Normalize Repo
      const normalizedRepo = normalizeRepoIdentifier(args.repo);
      if (!normalizedRepo) {
        return createErrorEnvelope(
          ErrorCode.INVALID_REPO_FORMAT,
          `Invalid repository format: "${args.repo}". Expected "owner/repo", "https://...", or "git@..."`,
          { repoId: args.repo }
        );
      }

      // 3. Resolve Identity & Check Index
      const identity = await resolveRepoIdentity(normalizedRepo, context.repoStore);

      if (!identity.isIndexed) {
        return createErrorEnvelope(
          ErrorCode.UNKNOWN_REPO,
          `Repository "${normalizedRepo}" is not indexed or does not exist.`,
          { repoId: normalizedRepo }
        );
      }

      if (identity.isStale) {
        return createErrorEnvelope(
          ErrorCode.STALE_INDEX,
          `Repository "${normalizedRepo}" index is stale. Please re-index.`,
          { repoId: normalizedRepo, fingerprint: identity.fingerprint || undefined }
        );
      }

      // 4. Execute Tool
      const result = await handler(args, identity);

      // 5. Enforce Max Result Size
      if (context.maxResultSize) {
        const resultStr = JSON.stringify(result);
        if (resultStr.length > context.maxResultSize) {
           return createErrorEnvelope(
             ErrorCode.RESULT_SIZE_EXCEEDED,
             'Tool output exceeds maximum allowed size.',
             { actualSize: resultStr.length, maxSize: context.maxResultSize }
           );
        }
      }

      return result;

    } catch (error) {
      // Catch-all for internal errors
      console.error('[MCP Middleware] Internal Error:', error);
