import { McpError, McpErrorCode } from '../errors.js';
import { validateRepoScope } from '../context/assembly.js';
import { ToolHandler, ToolResult } from './types.js'; // Assumed existing types

/**
 * Wraps a raw tool handler with the repo isolation gate and error mapping.
 * 
 * This ensures that all tools adhere to the fail-closed policy and return
 * consistent error envelopes.
 */
export function withRepoGate(handler: ToolHandler): ToolHandler {
  return async (args, context): Promise<ToolResult> => {
    try {
      // Step 1: Validate Repo Scope (Fail-closed gate)
      // We assume 'repo' is a standard parameter. If a tool doesn't need it,
      // it should opt-out, but per the task, we are enforcing repo-scoping.
      const repoContext = await validateRepoScope(args.repo);

      // Step 2: Execute the actual tool logic with validated context
      // We merge the validated context into the handler arguments/context
      const result = await handler(args, { ...context, repo: repoContext });

      // Step 3: Enforce Max Result Size
      // If the result is too large, truncate or error. 
      // Here we choose to error to be safe/predictable as per acceptance criteria.
      const MAX_SIZE = 1024 * 1024; // 1MB limit example
      const resultSize = JSON.stringify(result).length;
      
      if (resultSize > MAX_SIZE) {
        throw new McpError(
          McpErrorCode.MAX_SIZE_EXCEEDED,
          `Tool result exceeds maximum allowed size of ${MAX_SIZE} bytes.`,
          { context: { size: resultSize, limit: MAX_SIZE } }
        );
      }

      return result;

    } catch (error) {
      // Step 4: Ensure consistent error mapping
      if (error instanceof McpError) {
        // Return structured error for MCP transport
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify({
