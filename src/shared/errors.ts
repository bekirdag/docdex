/**
 * Canonical error definitions for the application.
 * Used by Daemon (HTTP/CLI) and MCP tools to ensure consistency.
 */

export enum ErrorCode {
  // Parameter Validation
  MISSING_REPO = 'MISSING_REPO',
  INVALID_REPO_FORMAT = 'INVALID_REPO_FORMAT',

  // Repo Identity & Indexing
  UNKNOWN_REPO = 'UNKNOWN_REPO',
  STALE_INDEX = 'STALE_INDEX',
  MISSING_DEPENDENCY = 'MISSING_DEPENDENCY',

  // Operational
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  BACKOFF_REQUIRED = 'BACKOFF_REQUIRED',
  INTERNAL_ERROR = 'INTERNAL_ERROR',
  RESULT_SIZE_EXCEEDED = 'RESULT_SIZE_EXCEEDED',
}

export interface ErrorDetails {
  repoId?: string;
  fingerprint?: string;
  maxSize?: number;
  actualSize?: number;
  retryAfter?: number; // seconds
  [key: string]: unknown;
}

export interface ErrorEnvelope {
  success: false;
  error: {
    code: ErrorCode;
    message: string;
    details?: ErrorDetails;
  };
}

export const createErrorEnvelope = (code: ErrorCode, message: string, details?: ErrorDetails): ErrorEnvelope => ({
  success: false,
