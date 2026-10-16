/**
 * IntentGuard Hidden First-Layer Interceptor Bridge (TypeScript Client)
 * =====================================================================
 * GENESIS 2.0 | Track: EVA 03 | PS 01
 * Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection
 *
 * This client intercepts OpenClaw operations before:
 * 1. Raw input ingestion (Hook 1: /internal/intercept/input)
 * 2. High-risk tool calls (Hook 2: /internal/intercept/tool)
 * 3. Persistent memory writes to MEMORY.md (Hook 3: /internal/intercept/memory)
 * 4. Outbound LLM streaming & tool responses (Hook 4: /internal/intercept/output)
 *
 * Implements strict FAIL-CLOSED behavior (Risk #33): If IntentGuard is
 * unreachable during tool execution or memory writes, operations are blocked
 * by default to protect against offline bypass attacks.
 */

import axios from "axios";

export const INTENTGUARD_GATEWAY_URL =
  process.env.INTENTGUARD_GATEWAY_URL || "http://127.0.0.1:8000";

export function getIntentGuardGatewayUrl(): string {
  const url = process.env.INTENTGUARD_GATEWAY_URL || INTENTGUARD_GATEWAY_URL;
  return url.replace(/\/+$/, "");
}

export type InputModality =
  | "email"
  | "pdf"
  | "docx"
  | "image"
  | "audio"
  | "video"
  | "web_dom"
  | "csv_xlsx"
  | "archive"
  | "text"
  | string;

export interface InboundInterceptPayload {
  sessionId?: string;
  session_id?: string;
  buyer_id?: string;
  supplier_id?: string;
  modality: InputModality;
  sourceUriOrFilename?: string;
  source_uri_or_filename?: string;
  rawContentText?: string | null;
  raw_content_text?: string | null;
  rawContentBase64?: string | null;
  raw_content_base64?: string | null;
  metadata?: Record<string, any>;
}

export interface InboundInspectionResult {
  intercept_id: string;
  session_id: string;
  allowed_to_proceed: boolean;
  provenance_tag: "UNTRUSTED_EXT" | "USER_AUTHORITY" | string;
  sanitized_text: string;
  cloaked_threats_removed: Array<Record<string, any>>;
  surgical_redactions: Array<Record<string, any>>;
  raw_evidence_sha256: string;
  redacted_diff_sha256: string;
  risk_category_ids: number[];
  threat_detected: boolean;
  action_taken: string;
}

export interface ToolCallInterceptPayload {
  sessionId?: string;
  session_id?: string;
  toolName?: string;
  tool_name?: string;
  toolArguments?: Record<string, any>;
  tool_arguments?: Record<string, any>;
  argument_provenance?: Record<string, string>;
  intentHmacHash?: string | null;
  intent_hmac_hash?: string | null;
}

export interface ToolCallInterceptResult {
  intercept_id: string;
  session_id: string;
  execution_permitted: boolean;
  requires_human_approval_card: boolean;
  approval_card_id?: string | null;
  action_taken: "SAFE_EXECUTED" | "BLOCKED" | "HUMAN_APPROVAL_REQUIRED" | string;
  policy_reference: string;
  reason: string;
  execution_token_hmac?: string | null;
  risk_category_ids: number[];
  threat_detected: boolean;
}

export interface MemoryWriteInterceptPayload {
  sessionId?: string;
  session_id?: string;
  target_memory_file?: string;
  proposed_memory_content: string;
  session_tainted_by_untrusted_ext?: boolean;
  source_reference?: string | null;
}

export interface MemoryWriteInterceptResult {
  intercept_id: string;
  persistent_write_allowed: boolean;
  routed_to_redis_quarantine: boolean;
  quarantine_key?: string | null;
  ttl_seconds: number;
  action_taken: "SAFE_EXECUTED" | "QUARANTINED_MEMORY" | "BLOCKED" | string;
  threat_detected: boolean;
  risk_category_ids: number[];
  reason: string;
}

export interface OutboundInterceptPayload {
  sessionId?: string;
  session_id?: string;
  raw_agent_response: string;
  outbound_urls?: string[];
}

export interface OutboundInterceptResult {
  intercept_id: string;
  sanitized_agent_response: string;
  blocked_urls: string[];
  stripped_forged_tags: string[];
  action_taken: "SAFE_EXECUTED" | "SURGICALLY_REDACTED" | "BLOCKED" | string;
  threat_detected: boolean;
  risk_category_ids: number[];
}

// ---------------------------------------------------------------------------
// Security Errors & Fail-Closed Exceptions
// ---------------------------------------------------------------------------

export class IntentGuardSecurityError extends Error {
  public readonly details?: Record<string, any>;
  constructor(message: string, details?: Record<string, any>) {
    super(message);
    this.name = "IntentGuardSecurityError";
    this.details = details;
  }
}

export class ToolCallBlockedError extends IntentGuardSecurityError {
  public readonly toolName: string;
  public readonly reason: string;
  public readonly requiresApproval: boolean;
  public readonly approvalCardId?: string | null;

  constructor(
    toolName: string,
    reason: string,
    requiresApproval: boolean = false,
    approvalCardId?: string | null
  ) {
    super(
      `[INTENTGUARD BLOCKED] Tool '${toolName}' execution denied: ${reason}${
        requiresApproval ? ` (Approval Card ID: ${approvalCardId})` : ""
      }`
    );
    this.name = "ToolCallBlockedError";
    this.toolName = toolName;
    this.reason = reason;
    this.requiresApproval = requiresApproval;
    this.approvalCardId = approvalCardId;
  }
}

export class MemoryWriteBlockedError extends IntentGuardSecurityError {
  public readonly targetFile: string;
  public readonly reason: string;
  public readonly quarantineKey?: string | null;

  constructor(
    targetFile: string,
    reason: string,
    quarantineKey?: string | null
  ) {
    super(
      `[INTENTGUARD BLOCKED] Memory write to '${targetFile}' denied: ${reason}${
        quarantineKey ? ` (Routed to Redis Quarantine: ${quarantineKey})` : ""
      }`
    );
    this.name = "MemoryWriteBlockedError";
    this.targetFile = targetFile;
    this.reason = reason;
    this.quarantineKey = quarantineKey;
  }
}

export class IntentGuardUnreachableError extends IntentGuardSecurityError {
  constructor(gatewayUrl: string, originalError?: any) {
    super(
      `[INTENTGUARD FAIL-CLOSED] Gateway unreachable at ${gatewayUrl}. ` +
        `Operation blocked under Fail-Closed Policy (Risk #33). Reason: ${
          originalError?.message || originalError || "Connection refused"
        }`
    );
    this.name = "IntentGuardUnreachableError";
  }
}

// ---------------------------------------------------------------------------
// Hook 1: Inbound Raw Input Interceptor
// ---------------------------------------------------------------------------

/**
 * Intercepts inbound untrusted inputs before passing them to OpenClaw.
 * Sanitizes input, computes SHA-256 evidence hashes, and assigns UNTRUSTED_EXT tag.
 */
export async function interceptInboundInput(payload: {
  sessionId?: string;
  session_id?: string;
  modality: string;
  sourceUriOrFilename?: string;
  source_uri_or_filename?: string;
  rawContentBase64?: string | null;
  raw_content_base64?: string | null;
  rawContentText?: string | null;
  raw_content_text?: string | null;
  buyer_id?: string;
  supplier_id?: string;
  metadata?: Record<string, any>;
}): Promise<InboundInspectionResult> {
  const gatewayUrl = getIntentGuardGatewayUrl();
  const endpoint = `${gatewayUrl}/internal/intercept/input`;
  const postBody = {
    session_id: payload.sessionId || payload.session_id || "openclaw-session",
    buyer_id: payload.buyer_id,
    supplier_id: payload.supplier_id,
    modality: payload.modality,
    source_uri_or_filename:
      payload.sourceUriOrFilename || payload.source_uri_or_filename || "unknown_input",
    raw_content_base64: payload.rawContentBase64 ?? payload.raw_content_base64 ?? null,
    raw_content_text: payload.rawContentText ?? payload.raw_content_text ?? null,
    metadata: payload.metadata || {},
  };

  try {
    const response = await axios.post(endpoint, postBody, {
      headers: { "Content-Type": "application/json" },
      timeout: 30000,
    });
    return response.data as InboundInspectionResult;
  } catch (error: any) {
    console.error("[IntentGuard] Gateway unreachable, failing closed:", error?.message || error);
    throw new Error(
      `Security Gateway rejected or failed to process inbound payload: ${
        error?.message || "Unreachable"
      }`
    );
  }
}

// ---------------------------------------------------------------------------
// Hook 2: Tool Call Interceptor & Policy Check
// ---------------------------------------------------------------------------

/**
 * Intercepts proposed tool calls from OpenClaw's LLM before execution.
 * Enforces policy gates, detects untrusted parameter contamination, and issues HMAC execution tokens.
 */
export async function interceptToolCall(payload: {
  sessionId?: string;
  session_id?: string;
  toolName?: string;
  tool_name?: string;
  toolArguments?: Record<string, any>;
  tool_arguments?: Record<string, any>;
  argument_provenance?: Record<string, string>;
  intentHmacHash?: string | null;
  intent_hmac_hash?: string | null;
}): Promise<ToolCallInterceptResult> {
  const gatewayUrl = getIntentGuardGatewayUrl();
  const endpoint = `${gatewayUrl}/internal/intercept/tool`;
  const postBody = {
    session_id: payload.sessionId || payload.session_id || "openclaw-session",
    tool_name: payload.toolName || payload.tool_name || "unknown_tool",
    tool_arguments: payload.toolArguments || payload.tool_arguments || {},
    argument_provenance: payload.argument_provenance,
    intent_hmac_hash: payload.intentHmacHash ?? payload.intent_hmac_hash ?? null,
  };

  try {
    const response = await axios.post(endpoint, postBody, {
      headers: { "Content-Type": "application/json" },
      timeout: 15000,
    });
    return response.data as ToolCallInterceptResult;
  } catch (error: any) {
    console.error("[IntentGuard] Tool interception error:", error?.message || error);
    return {
      intercept_id: `err-${Date.now()}`,
      session_id: postBody.session_id,
      execution_permitted: false,
      requires_human_approval_card: false,
      approval_card_id: null,
      action_taken: "BLOCKED",
      policy_reference: "FAIL_CLOSED_FALLBACK",
      reason: `Gateway error / fail-closed: ${error?.message || "Unreachable"}`,
      execution_token_hmac: null,
      risk_category_ids: [33],
      threat_detected: true,
    };
  }
}

// ---------------------------------------------------------------------------
// Hook 3: Persistent Memory Write Interceptor
// ---------------------------------------------------------------------------

/**
 * Intercepts writes to OpenClaw's MEMORY.md file.
 * Prevents sleeper rules and tainted inputs from corrupting persistent memory,
 * redirecting untrusted memory updates to Redis quarantine vault.
 */
export async function interceptMemoryWrite(
  payload: MemoryWriteInterceptPayload
): Promise<MemoryWriteInterceptResult> {
  const gatewayUrl = getIntentGuardGatewayUrl();
  const endpoint = `${gatewayUrl}/internal/intercept/memory`;
  const postBody = {
    session_id: payload.sessionId || payload.session_id || "openclaw-session",
    target_memory_file: payload.target_memory_file || "MEMORY.md",
    proposed_memory_content: payload.proposed_memory_content,
    session_tainted_by_untrusted_ext: payload.session_tainted_by_untrusted_ext ?? false,
    source_reference: payload.source_reference ?? null,
  };

  try {
    const response = await axios.post(endpoint, postBody, {
      headers: { "Content-Type": "application/json" },
      timeout: 15000,
    });
    return response.data as MemoryWriteInterceptResult;
  } catch (error: any) {
    console.error("[IntentGuard] Memory write interception error:", error?.message || error);
    return {
      intercept_id: `mem-err-${Date.now()}`,
      persistent_write_allowed: false,
      routed_to_redis_quarantine: true,
      quarantine_key: `quarantine:fallback:${Date.now()}`,
      ttl_seconds: 86400,
      action_taken: "QUARANTINED_MEMORY",
      threat_detected: true,
      risk_category_ids: [33],
      reason: `Gateway error / fail-closed: ${error?.message || "Unreachable"}`,
    };
  }
}

// ---------------------------------------------------------------------------
// Hook 4: Outbound Response Interceptor
// ---------------------------------------------------------------------------

/**
 * Intercepts OpenClaw's outbound text and tool results before they are sent
 * to the user or external network.
 * Strips EchoLeak markdown image exfiltration links and forged system output tags.
 */
export async function interceptOutboundOutput(
  payload: OutboundInterceptPayload
): Promise<OutboundInterceptResult> {
  const gatewayUrl = getIntentGuardGatewayUrl();
  const endpoint = `${gatewayUrl}/internal/intercept/output`;
  const postBody = {
    session_id: payload.sessionId || payload.session_id || "openclaw-session",
    raw_agent_response: payload.raw_agent_response,
    outbound_urls: payload.outbound_urls || [],
  };

  try {
    const response = await axios.post(endpoint, postBody, {
      headers: { "Content-Type": "application/json" },
      timeout: 15000,
    });
    return response.data as OutboundInterceptResult;
  } catch (error: any) {
    console.error("[IntentGuard] Outbound interception error:", error?.message || error);
    return {
      intercept_id: `out-err-${Date.now()}`,
      sanitized_agent_response: payload.raw_agent_response,
      blocked_urls: [],
      stripped_forged_tags: [],
      action_taken: "SAFE_EXECUTED",
      threat_detected: false,
      risk_category_ids: [],
    };
  }
}

// ---------------------------------------------------------------------------
// Task 29: Pre-Execution Sandbox Verification Gate (Risks #30 & #33)
// ---------------------------------------------------------------------------

export interface SandboxToolVerifyPayload {
  sessionId?: string;
  session_id?: string;
  toolName?: string;
  tool_name?: string;
  toolArguments?: Record<string, any>;
  tool_arguments?: Record<string, any>;
  permitToken?: any;
  permit_token?: any;
  rawExecutionTokenHmac?: string | null;
  raw_execution_token_hmac?: string | null;
}

export interface SandboxToolVerifyResult {
  verified: boolean;
  allow_sandbox_execution: boolean;
  action_taken: "SAFE_EXECUTED" | "BLOCKED" | string;
  threat_detected: boolean;
  risk_category_ids: number[];
  bypass_attempt_detected: boolean;
  fail_closed_triggered: boolean;
  reason: string;
}

/**
 * Task 29: Pre-Execution Sandbox Gate.
 * Enforces anti-bypass ExecutionPermitToken verification and fail-closed circuit breaker
 * check before any containerized sandbox tool can be spawned or executed.
 */
export async function verifyAndExecuteSandboxTool(
  payload: SandboxToolVerifyPayload
): Promise<SandboxToolVerifyResult> {
  const gatewayUrl = getIntentGuardGatewayUrl();
  const endpoint = `${gatewayUrl}/openclaw/verify-execution-token`;
  const postBody = {
    session_id: payload.sessionId || payload.session_id || "openclaw-session",
    tool_name: payload.toolName || payload.tool_name || "",
    tool_arguments: payload.toolArguments || payload.tool_arguments || {},
    permit_token: payload.permitToken || payload.permit_token || null,
    raw_execution_token_hmac:
      payload.rawExecutionTokenHmac || payload.raw_execution_token_hmac || null,
  };

  try {
    const response = await axios.post(endpoint, postBody, {
      headers: { "Content-Type": "application/json" },
      timeout: 15000,
    });
    return response.data as SandboxToolVerifyResult;
  } catch (error: any) {
    console.error("[IntentGuard] Sandbox verify execution error:", error?.message || error);
    return {
      verified: false,
      allow_sandbox_execution: false,
      action_taken: "BLOCKED",
      threat_detected: true,
      bypass_attempt_detected: false,
      fail_closed_triggered: true,
      risk_category_ids: [33],
      reason: `Gateway error / fail-closed: ${error?.message || "Unreachable"}`,
    };
  }
}

