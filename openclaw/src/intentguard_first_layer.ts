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
  | "text";

export interface InboundInterceptPayload {
  session_id: string;
  buyer_id?: string;
  supplier_id?: string;
  modality: InputModality;
  source_uri_or_filename: string;
  raw_content_text?: string | null;
  raw_content_base64?: string | null;
  metadata?: Record<string, any>;
}

export interface InboundInterceptResult {
  intercept_id: string;
  session_id: string;
  allowed_to_proceed: boolean;
  provenance_tag: "UNTRUSTED_EXT" | "USER_AUTHORITY";
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
  session_id: string;
  tool_name: string;
  tool_arguments: Record<string, any>;
  argument_provenance?: Record<string, string>;
  intent_hmac_hash?: string | null;
}

export interface ToolCallInterceptResult {
  intercept_id: string;
  session_id: string;
  execution_permitted: boolean;
  requires_human_approval_card: boolean;
  approval_card_id?: string | null;
  action_taken: "SAFE_EXECUTED" | "BLOCKED" | "HUMAN_APPROVAL_REQUIRED";
  policy_reference: string;
  reason: string;
  execution_token_hmac?: string | null;
  risk_category_ids: number[];
  threat_detected: boolean;
}

export interface MemoryWriteInterceptPayload {
  session_id: string;
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
  action_taken: "SAFE_EXECUTED" | "QUARANTINED_MEMORY" | "BLOCKED";
  threat_detected: boolean;
  risk_category_ids: number[];
  reason: string;
}

export interface OutboundInterceptPayload {
  session_id: string;
  raw_agent_response: string;
  outbound_urls?: string[];
}

export interface OutboundInterceptResult {
  intercept_id: string;
  sanitized_agent_response: string;
  blocked_urls: string[];
  stripped_forged_tags: string[];
  action_taken: "SAFE_EXECUTED" | "SURGICALLY_REDACTED" | "BLOCKED";
  threat_detected: boolean;
  risk_category_ids: number[];
}

// ---------------------------------------------------------------------------
// Security Errors & Fail-Closed Exceptions
// ---------------------------------------------------------------------------

export class IntentGuardSecurityError extends Error {
  constructor(message: string, public readonly details?: Record<string, any>) {
    super(message);
    this.name = "IntentGuardSecurityError";
  }
}

export class ToolCallBlockedError extends IntentGuardSecurityError {
  constructor(
    public readonly toolName: string,
    public readonly reason: string,
    public readonly requiresApproval: boolean = false,
    public readonly approvalCardId?: string | null
  ) {
    super(
      `[INTENTGUARD BLOCKED] Tool '${toolName}' execution denied: ${reason}${
        requiresApproval ? ` (Approval Card ID: ${approvalCardId})` : ""
      }`
    );
    this.name = "ToolCallBlockedError";
  }
}

export class MemoryWriteBlockedError extends IntentGuardSecurityError {
  constructor(
    public readonly targetFile: string,
    public readonly reason: string,
    public readonly quarantineKey?: string | null
  ) {
    super(
      `[INTENTGUARD BLOCKED] Memory write to '${targetFile}' denied: ${reason}${
        quarantineKey ? ` (Routed to Redis Quarantine: ${quarantineKey})` : ""
      }`
    );
    this.name = "MemoryWriteBlockedError";
  }
}

export class IntentGuardUnreachableError extends IntentGuardSecurityError {
  constructor(gatewayUrl: string, originalError?: Error) {
    super(
      `[INTENTGUARD FAIL-CLOSED] Gateway unreachable at ${gatewayUrl}. ` +
        `Operation blocked under Fail-Closed Policy (Risk #33). Reason: ${originalError?.message || "Connection refused"}`
    );
    this.name = "IntentGuardUnreachableError";
  }
}

// ---------------------------------------------------------------------------
// Gateway Configuration
// ---------------------------------------------------------------------------

export function getIntentGuardGatewayUrl(): string {
  const url = process.env.INTENTGUARD_GATEWAY_URL || "http://127.0.0.1:8000";
  return url.replace(/\/+$/, "");
}

// ---------------------------------------------------------------------------
// Hook 1: Inbound Raw Input Interceptor
// ---------------------------------------------------------------------------

/**
 * Intercepts inbound untrusted inputs before passing them to OpenClaw.
 * Sanitizes input, computes SHA-256 evidence hashes, and assigns UNTRUSTED_EXT tag.
 */
export async function interceptInboundInput(
  payload: InboundInterceptPayload
): Promise<InboundInterceptResult> {
  const gatewayUrl = getIntentGuardGatewayUrl();
  const endpoint = `${gatewayUrl}/internal/intercept/input`;

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Gateway returned HTTP ${response.status}: ${errText}`);
    }

    return (await response.json()) as InboundInterceptResult;
  } catch (err: any) {
    // Fail-closed for inbound data if gateway is down
    if (err instanceof IntentGuardSecurityError) throw err;
    throw new IntentGuardUnreachableError(gatewayUrl, err);
  }
}

// ---------------------------------------------------------------------------
// Hook 2: Tool Call Interceptor & Policy Check
// ---------------------------------------------------------------------------

/**
 * Intercepts proposed tool calls from OpenClaw's LLM before execution.
 * Enforces policy gates, detects untrusted parameter contamination, and issues HMAC execution tokens.
 * Throws ToolCallBlockedError if execution is disallowed (FAIL-CLOSED).
 */
export async function interceptToolCall(
  payload: ToolCallInterceptPayload
): Promise<ToolCallInterceptResult> {
  const gatewayUrl = getIntentGuardGatewayUrl();
  const endpoint = `${gatewayUrl}/internal/intercept/tool`;

  let result: ToolCallInterceptResult;
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Gateway returned HTTP ${response.status}: ${errText}`);
    }

    result = (await response.json()) as ToolCallInterceptResult;
  } catch (err: any) {
    // Fail-Closed Policy (Risk #33) - Block all tool calls if IntentGuard is offline
    throw new IntentGuardUnreachableError(gatewayUrl, err);
  }

  if (!result.execution_permitted) {
    throw new ToolCallBlockedError(
      payload.tool_name,
      result.reason,
      result.requires_human_approval_card,
      result.approval_card_id
    );
  }

  return result;
}

// ---------------------------------------------------------------------------
// Hook 3: Persistent Memory Write Interceptor
// ---------------------------------------------------------------------------

/**
 * Intercepts writes to OpenClaw's MEMORY.md file.
 * Prevents sleeper rules and tainted inputs from corrupting persistent memory,
 * redirecting untrusted memory updates to Redis quarantine vault.
 * Throws MemoryWriteBlockedError if persistent write is disallowed (FAIL-CLOSED).
 */
export async function interceptMemoryWrite(
  payload: MemoryWriteInterceptPayload
): Promise<MemoryWriteInterceptResult> {
  const gatewayUrl = getIntentGuardGatewayUrl();
  const endpoint = `${gatewayUrl}/internal/intercept/memory`;

  let result: MemoryWriteInterceptResult;
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Gateway returned HTTP ${response.status}: ${errText}`);
    }

    result = (await response.json()) as MemoryWriteInterceptResult;
  } catch (err: any) {
    // Fail-Closed Policy (Risk #33) - Block persistent memory writes if IntentGuard is offline
    throw new IntentGuardUnreachableError(gatewayUrl, err);
  }

  if (!result.persistent_write_allowed) {
    throw new MemoryWriteBlockedError(
      payload.target_memory_file || "MEMORY.md",
      result.reason,
      result.quarantine_key
    );
  }

  return result;
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

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Gateway returned HTTP ${response.status}: ${errText}`);
    }

    return (await response.json()) as OutboundInterceptResult;
  } catch (err: any) {
    if (err instanceof IntentGuardSecurityError) throw err;
    throw new IntentGuardUnreachableError(gatewayUrl, err);
  }
}
