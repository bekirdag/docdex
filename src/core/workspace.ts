/*
 * Minimal workspace store for MCP context validation.
 * The store holds repo metadata (path + index state) keyed by repo identifier.
 * By default it seeds one repo from `DOCDEX_REPO_ID`/`DOCDEX_REPO_PATH`, but
 * callers can also register additional repos at runtime.
 */

export type IndexState = 'ready' | 'stale' | 'missing';

export interface RepoConfig {
  id: string;
  path: string;
  indexState: IndexState;
}

class WorkspaceStore {
  private repos = new Map<string, RepoConfig>();

  constructor() {
    this.seedFromEnvironment();
  }

  public getRepo(id: string): RepoConfig | null {
    return this.repos.get(id) || null;
  }

  public register(repo: RepoConfig): void {
    this.repos.set(repo.id, repo);
  }

  private seedFromEnvironment(): void {
    const envRepoId = process.env.DOCDEX_REPO_ID;
    if (!envRepoId) {
      return;
    }
    const envRepoPath = process.env.DOCDEX_REPO_PATH || process.cwd();
    this.repos.set(envRepoId, {
      id: envRepoId,
      path: envRepoPath,
      indexState: 'ready',
    });
  }
}

const workspaceStore = new WorkspaceStore();

export function getWorkspaceStore(): WorkspaceStore {
  return workspaceStore;
}
