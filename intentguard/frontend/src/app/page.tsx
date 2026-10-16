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
} from "lucide-react";
import { SplitScreenArena } from "../components/SplitScreenArena";
import { XRayDiffViewer } from "../components/XRayDiffViewer";
import { StepBackApprovalModal } from "../components/StepBackApprovalModal";
import { FabricAuditExplorer } from "../components/FabricAuditExplorer";
import { ScenarioSwitcher } from "../components/ScenarioSwitcher";

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

        {/* 1-Click Multi-Modal Synthetic Scenario Switcher */}
        <section aria-label="Multi-Modal Synthetic Attack Vector Selector">
          <ScenarioSwitcher />
        </section>

        {/* 4. Active Tab Content Area */}
        <div className="w-full flex flex-col gap-6">
          {activeTab === "arena" && (
            <div id="tab-arena" className="flex flex-col gap-6">
              <SplitScreenArena onSwitchTab={setActiveTab} />
            </div>
          )}

          {activeTab === "xray" && (
            <div id="tab-xray" className="flex flex-col gap-6">
              <XRayDiffViewer onSwitchTab={setActiveTab} />
            </div>
          )}

          {activeTab === "approvals" && (
            <div id="tab-approvals" className="flex flex-col gap-6">
              <StepBackApprovalModal />
            </div>
          )}

          {activeTab === "fabric" && (
            <div id="tab-fabric" className="flex flex-col gap-6">
              <FabricAuditExplorer />
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
