/**
 * IntentGuard Frontend Core Type Definitions
 * ===========================================
 * GENESIS 2.0 | Track: EVA 03 | PS 01
 * Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection
 */

export type DashboardTabId = "arena" | "xray" | "approvals" | "fabric";

export type HookStage =
  | "HOOK_1_INBOUND"
  | "HOOK_2_TOOL_CALL"
  | "HOOK_3_MEMORY_WRITE"
  | "HOOK_4_OUTBOUND";

export interface XRayTelemetryEvent {
  event_id: string;
  timestamp: string;
  session_id: string;
  hook_stage: HookStage | string;
  modality_or_tool: string;
  threat_detected: boolean;
  action_taken: string;
  risk_category_ids: number[];
  summary: string;
  details: Record<string, any>;
}

export interface SystemTelemetryState {
  backendConnected: boolean;
  wsConnected: boolean;
  openclawSandboxStatus: "ISOLATED" | "RESTRICTED_UNTRUSTED_CONTEXT" | "OFFLINE";
  step0HmacStatus: "LOCKED" | "TAMPER_ALERT";
  memoryVaultStatus: "REDIS TTL ACTIVE" | "QUARANTINED";
  fabricStatus: "CONNECTED" | "MOCK_LEDGER_ACTIVE" | "FAIL_CLOSED_503";
  activeModel: string;
  activeIntentHmacSample: string;
}

export interface POBaselineComparison {
  po_id: string;
  trusted_buyer_id: string;
  trusted_supplier_id: string;
  approved_bank_account: string;
  proposed_bank_account: string;
  approved_amount_inr: number;
  proposed_amount_inr: number;
  delivery_receipt_status: string;
  discrepancy_summary: string;
}

export interface PendingApprovalCard {
  card_id: string;
  event_id: string;
  session_id: string;
  buyer_id: string;
  supplier_id: string;
  status: "PENDING" | "APPROVED" | "REJECTED";
  proposed_action: {
    tool_name?: string;
    tool_arguments?: Record<string, any>;
    escalation_type?: string;
    intent_hmac_hash?: string;
    raw_evidence_sha256?: string;
    redacted_diff_sha256?: string;
  };
  po_comparison?: POBaselineComparison;
  source_file: string;
  source_page_number: number;
  source_line_number: number;
  exact_source_line_text: string;
  reason: string;
  risk_category_ids: number[];
  created_at: string;
  resolved_at?: string | null;
  resolved_by?: string | null;
  execution_token_hmac?: string | null;
}

export interface FabricAuditEvent {
  event_id: string;
  timestamp: string;
  buyer_id: string;
  supplier_id: string;
  input_modality: string;
  action_taken: string;
  policy_reference: string;
  raw_evidence_sha256: string;
  redacted_diff_sha256: string;
  intent_hmac_hash: string;
  risk_category_ids: number[];
  threat_detected: boolean;
  transaction_id?: string;
  recorded_at?: string;
}

export interface HealthStatus {
  status: string;
  app_name: string;
  environment: string;
  openclaw_primary_model: string;
  interceptor_bridge_ready: boolean;
  active_telemetry_subscribers: number;
}

export interface BlockchainVerificationResult {
  connected: boolean;
  target_url: string;
  status_code: number;
  latency_ms: number;
  remote_response?: any;
  mode: string;
  checked_at: string;
  error?: string;
  test_dispatch?: any;
}
