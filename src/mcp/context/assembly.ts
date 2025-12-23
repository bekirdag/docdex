import { McpError, McpErrorCode } from '../errors.js';
import { getWorkspaceStore } from '../../core/workspace.js'; // Assumed existing store

/**
 * Result of a successful context assembly.
 */
export interface RepoContext {
  repoId: string;
  rootPath: string;
  indexStatus: 'ready' | 'stale' | 'missing';
}

/**
 * Validates repo scope and assembles context.
 * 
 * This function acts as a fail-closed gate. If any validation fails,
 * it throws a canonical McpError immediately, preventing partial execution.
 * 
 * @param repoId - The repository identifier from the tool request.
 * @returns RepoContext - The verified context object.
 * @throws McpError - If validation fails.
 */
export async function validateRepoScope(repoId: string | undefined | null): Promise<RepoContext> {
  // 1. Check for missing repo parameter
  if (!repoId || typeof repoId !== 'string' || repoId.trim() === '') {
    throw new McpError(
      McpErrorCode.MISSING_REPO,
      'Repository parameter is required and must be a non-empty string.',
      { retryable: false }
    );
  }

  const workspace = getWorkspaceStore();
  
  // 2. Check for unknown repo
  const repoConfig = workspace.getRepo(repoId);
  if (!repoConfig) {
    throw new McpError(
      McpErrorCode.UNKNOWN_REPO,
      `Repository '${repoId}' is not known or not accessible in the current workspace.`,
      { context: { repoId } }
    );
  }

  // 3. Check index status (Fail-closed on stale/missing)
  // Assuming repoConfig has an index state property
  if (repoConfig.indexState !== 'ready') {
    const state = repoConfig.indexState || 'missing';
    throw new McpError(
      McpErrorCode.STALE_INDEX,
      `Repository index for '${repoId}' is ${state}. Re-indexing is required before tool execution.`,
      { context: { repoId, currentState: state } }
    );
  }

  return {
    repoId,
    rootPath: repoConfig.path,
    indexStatus: 'ready',
  };
