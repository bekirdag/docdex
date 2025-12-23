/**
 * Canonical error definitions for MCP tools.
 * Ensures consistency with daemon HTTP/CLI behavior.
 */

export enum McpErrorCode {
  // Parameter Validation
  MISSING_REPO = 'MISSING_REPO',
  UNKNOWN_REPO = 'UNKNOWN_REPO',
  
  // System State
  STALE_INDEX = 'STALE_INDEX',
  MISSING_DEPENDENCY = 'MISSING_DEPENDENCY',
  
  // Operational
  RATE_LIMIT = 'RATE_LIMIT',
  MAX_SIZE_EXCEEDED = 'MAX_SIZE_EXCEEDED',
  
  // Generic
  INTERNAL_ERROR = 'INTERNAL_ERROR',
}

export interface McpErrorDetails {
  context?: Record<string, unknown>;
  retryable?: boolean;
}

export class McpError extends Error {
  public readonly code: McpErrorCode;
  public readonly details: McpErrorDetails;

  constructor(code: McpErrorCode, message: string, details: McpErrorDetails = {}) {
    super(message);
    this.name = 'McpError';
    this.code = code;
    this.details = details;
    
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, McpError);
    }
  }
