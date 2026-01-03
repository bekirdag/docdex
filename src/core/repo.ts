import { ErrorCode, createErrorEnvelope } from '../shared/errors';

/**
 * Result of repo normalization and resolution.
 */
export interface RepoIdentity {
  id: string; // Canonical 'owner/repo'
  fingerprint: string | null;
  isIndexed: boolean;
  isStale: boolean;
}

/**
 * Normalizes various repo string formats to 'owner/repo'.
 * Handles: https://github.com/owner/repo, git@github.com:owner/repo.git, owner/repo
 */
export function normalizeRepoIdentifier(input: string): string | null {
  if (!input || typeof input !== 'string') return null;

  let clean = input.trim();

  // Remove .git suffix
  if (clean.endsWith('.git')) {
    clean = clean.slice(0, -4);
  }

  // Handle SSH format: git@github.com:owner/repo
  const sshMatch = clean.match(/^git@[\w.-]+:(.+)$/);
  if (sshMatch) {
    clean = sshMatch[1];
  }

  // Handle HTTPS format: https://github.com/owner/repo
  const urlMatch = clean.match(/^https?:\/\/[\w.-]+\/(.+)$/);
  if (urlMatch) {
    clean = urlMatch[1];
  }

  // Validate final format (owner/repo)
  const parts = clean.split('/');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return null;
  }

  return `${parts[0].toLowerCase()}/${parts[1].toLowerCase()}`;
}

/**
 * Resolves repo identity against the store.
 * Note: 'repoStore' is assumed to be an injected dependency or global singleton.
 */
export async function resolveRepoIdentity(
  repoId: string,
  repoStore: { get: (id: string) => Promise<{ fingerprint: string; indexedAt: number } | null> }
): Promise<RepoIdentity> {
  const record = await repoStore.get(repoId);
  return {
    id: repoId,
    fingerprint: record?.fingerprint || null,
    isIndexed: !!record,
