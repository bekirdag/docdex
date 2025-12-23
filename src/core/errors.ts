/**
 * Shared error definitions and sanitization utilities.
 * Ensures consistent error reporting across MCP tools and Daemon surfaces.
 */

export enum McpErrorCode {
  MISSING_REPO = 'MISSING_REPO',
  UNKNOWN_REPO = 'UNKNOWN_REPO',
  STALE_INDEX = 'STALE_INDEX',
  MISSING_DEPENDENCY = 'MISSING_DEPENDENCY',
  RATE_LIMIT = 'RATE_LIMIT',
  INTERNAL_ERROR = 'INTERNAL_ERROR',
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  RESULT_TOO_LARGE = 'RESULT_TOO_LARGE',
}

export interface ErrorEnvelope {
  code: McpErrorCode;
  message: string;
  details?: Record<string, unknown>;
}

/**
 * Sanitizes error messages to prevent leakage of cross-repo identifiers
 * or absolute file paths.
 */
export function sanitizeMessage(message: string): string {
  // Redact absolute paths (Unix/Windows)
  let sanitized = message.replace(/\/[a-zA-Z0-9_\-./]+/g, '[PATH]');
  sanitized = sanitized.replace(/[a-zA-Z]:\\[a-zA-Z0-9_\-./\\]+/g, '[PATH]');
  
  // Redact potential cross-repo identifiers (e.g., repo:other-id)
  sanitized = sanitized.replace(/repo:[a-zA-Z0-9_\-]+/g, '[REPO_ID]');
  
  return sanitized;
}

export class McpError extends Error {
  public readonly code: McpErrorCode;
  public readonly details?: Record<string, unknown>;

  constructor(code: McpErrorCode, message: string, details?: Record<string, unknown>) {
    super(sanitizeMessage(message));
    this.name = 'McpError';
    this.code = code;
    this.details = details;
    
    // Maintains proper stack trace (only available on V8)
    Error.captureStackTrace(this, McpError);
  }

  toJSON(): ErrorEnvelope {
    return {
      code: this.code,
      message: this.message,
      details: this.details,
    };
  }
}

export function toErrorEnvelope(err: unknown): ErrorEnvelope {
  if (err instanceof McpError) return err.toJSON();
  return { code: McpErrorCode.INTERNAL_ERROR, message: sanitizeMessage(String(err)) };
}