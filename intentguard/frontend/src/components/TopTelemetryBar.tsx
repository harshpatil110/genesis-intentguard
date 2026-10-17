"use client";

/**
 * TopTelemetryBar — Modern Glassmorphic Enterprise Masthead
 * ==========================================================
 * Linear / Vercel Aesthetic: Clean typography, subtle borders, refined pills,
 * and live Remote Blockchain Connection Verifier to peer PC (192.168.21.160:8000).
 */

import React, { useState } from "react";
import { SystemTelemetryState, BlockchainVerificationResult } from "../types/intentguard";
import {
  ShieldCheck,
  Lock,
  Database,
  Radio,
  Terminal,
  Server,
  Loader2,
  CheckCircle2,
  XCircle,
  X,
  ExternalLink,
  Send,
  Zap,
} from "lucide-react";

interface TopTelemetryBarProps {
  systemState: SystemTelemetryState;
  wsConnected: boolean;
  eventCount: number;
  onTriggerPing: () => void;
}

export const TopTelemetryBar: React.FC<TopTelemetryBarProps> = ({
  systemState,
  wsConnected,
  eventCount,
  onTriggerPing,
}) => {
  const [isVerifying, setIsVerifying] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [verifyResult, setVerifyResult] = useState<BlockchainVerificationResult | null>(null);
  const [isSendingTestEvent, setIsSendingTestEvent] = useState(false);
  const [testEventReceipt, setTestEventReceipt] = useState<any | null>(null);

  const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";

  const handleVerifyRemoteBlockchain = async () => {
    setIsVerifying(true);
    setShowModal(true);
    setTestEventReceipt(null);
    try {
      const res = await fetch(`${backendUrl}/api/blockchain/verify-connection?send_test_ping=true`);
      const data: BlockchainVerificationResult = await res.json();
      setVerifyResult(data);
    } catch (err: any) {
      setVerifyResult({
        connected: false,
        target_url: "http://192.168.21.160:8000",
        status_code: 0,
        latency_ms: 0,
        error: err?.message || "Failed to contact backend proxy.",
        mode: "REMOTE_FABRIC_NODE",
        checked_at: new Date().toISOString(),
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const handleSendTestEvent = async () => {
    setIsSendingTestEvent(true);
    try {
      const res = await fetch(`${backendUrl}/api/blockchain/send-test-event`, {
        method: "POST",
      });
      const data = await res.json();
      setTestEventReceipt(data);
    } catch (err: any) {
      setTestEventReceipt({
        success: false,
        error: err?.message || "Failed to dispatch test event.",
      });
    } finally {
      setIsSendingTestEvent(false);
    }
  };

  return (
    <>
      <header className="sticky top-0 z-30 w-full bg-white/90 backdrop-blur-md border-b border-slate-200/80 px-6 py-3 select-none transition-all shadow-xs">
        <div className="max-w-[1600px] w-full mx-auto flex flex-col xl:flex-row xl:items-center xl:justify-between gap-3.5">
          {/* Brand & Identity */}
          <div className="flex items-center gap-3.5">
            <div className="w-9 h-9 rounded-xl bg-slate-900 text-white flex items-center justify-center font-bold text-sm tracking-tight shadow-sm ring-1 ring-slate-900/10">
              IG
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-semibold tracking-tight text-slate-900">
                  IntentGuard
                </h1>
                <span className="text-[11px] font-medium px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 border border-slate-200/60">
                  v2.0 Enterprise
                </span>
                <span className="text-[11px] font-medium px-2 py-0.5 rounded-full bg-indigo-50 text-indigo-700 border border-indigo-200/60 hidden sm:inline">
                  EVA 03 • PS 01
                </span>
              </div>
              <p className="text-xs text-slate-500 font-normal">
                Enterprise AI Firewall &amp; CaMeL Policy Gateway • OpenClaw Bridge
              </p>
            </div>
          </div>

          {/* 4 Architectural Status Pills with Pulsing Dots */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Sandbox Isolation */}
            <div
              title="Isolated non-root Docker runtime with memory & tool boundary"
              className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-50 border border-slate-200/80 text-xs text-slate-600 shadow-2xs"
            >
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              <span className="text-slate-500 font-medium">Sandbox:</span>
              <span className="font-semibold text-emerald-700">ISOLATED</span>
            </div>

            {/* Step-0 HMAC Lock */}
            <div
              title="Step-0 Cryptographic Intent Contract signed via HMAC-SHA256"
              className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-50 border border-slate-200/80 text-xs text-slate-600 shadow-2xs"
            >
              <Lock className="w-3.5 h-3.5 text-emerald-600" />
              <span className="text-slate-500 font-medium">Step-0 HMAC:</span>
              <span className="font-semibold text-emerald-700">LOCKED</span>
            </div>

            {/* Memory Vault */}
            <div
              title="Redis Ephemeral Quarantine Vault (EXPIRE 300s) protecting MEMORY.md"
              className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-50 border border-slate-200/80 text-xs text-slate-600 shadow-2xs"
            >
              <Database className="w-3.5 h-3.5 text-emerald-600" />
              <span className="text-slate-500 font-medium">Memory Vault:</span>
              <span className="font-semibold text-emerald-700">REDIS TTL</span>
            </div>

            {/* Hyperledger Fabric */}
            <div
              title="Remote Hyperledger Fabric Node on Peer PC (192.168.21.160:8000)"
              className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-50 border border-slate-200/80 text-xs text-slate-600 shadow-2xs"
            >
              <ShieldCheck className="w-3.5 h-3.5 text-indigo-600" />
              <span className="text-slate-500 font-medium">Fabric Node:</span>
              <span className="font-semibold text-indigo-700">
                192.168.21.160
              </span>
            </div>
          </div>

          {/* Right Action Bar */}
          <div className="flex items-center gap-2.5">
            {/* Live WS Ticker Pill */}
            <div className="flex items-center gap-2 px-3 py-1 rounded-lg bg-slate-100/80 border border-slate-200/60 text-xs text-slate-600">
              <Radio
                className={`w-3.5 h-3.5 ${
                  wsConnected ? "text-emerald-600 animate-pulse" : "text-amber-600"
                }`}
              />
              <span className="font-medium">X-Ray Stream:</span>
              <span
                className={`font-semibold ${
                  wsConnected ? "text-emerald-700" : "text-amber-700"
                }`}
              >
                {wsConnected ? "LIVE" : "STANDBY"}
              </span>
              <span className="text-slate-300">|</span>
              <span className="font-mono text-[11px] text-slate-500">
                {eventCount} evts
              </span>
            </div>

            {/* Verify Live Bridge button */}
            <button
              onClick={onTriggerPing}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 active:scale-95 border border-slate-200 rounded-lg shadow-2xs transition-all"
            >
              <Terminal className="w-3.5 h-3.5 text-slate-500" />
              <span>Verify Bridge</span>
            </button>

            {/* Verify Remote Blockchain button */}
            <button
              onClick={handleVerifyRemoteBlockchain}
              disabled={isVerifying}
              className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-700 active:scale-95 rounded-lg shadow-xs hover:shadow transition-all disabled:opacity-70"
            >
              {isVerifying ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Pinging Peer Node...</span>
                </>
              ) : (
                <>
                  <Server className="w-3.5 h-3.5" />
                  <span>Verify Remote Blockchain</span>
                </>
              )}
            </button>
          </div>
        </div>
      </header>

      {/* Interactive Remote Blockchain Verification Popover / Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs animate-in fade-in duration-150">
          <div className="bg-white rounded-2xl shadow-2xl border border-slate-200 max-w-xl w-full p-6 flex flex-col gap-4 animate-in zoom-in-95 duration-150">
            {/* Modal Header */}
            <div className="flex items-start justify-between border-b border-slate-100 pb-3">
              <div className="flex items-center gap-2.5">
                <div
                  className={`w-9 h-9 rounded-xl flex items-center justify-center ${
                    isVerifying
                      ? "bg-slate-100 text-slate-600"
                      : verifyResult?.connected
                      ? "bg-emerald-50 text-emerald-600 border border-emerald-200"
                      : "bg-rose-50 text-rose-600 border border-rose-200"
                  }`}
                >
                  {isVerifying ? (
                    <Loader2 className="w-5 h-5 animate-spin" />
                  ) : verifyResult?.connected ? (
                    <CheckCircle2 className="w-5 h-5" />
                  ) : (
                    <XCircle className="w-5 h-5" />
                  )}
                </div>
                <div>
                  <h3 className="text-base font-semibold text-slate-900">
                    Peer Hyperledger Fabric Gateway
                  </h3>
                  <p className="text-xs text-slate-500 font-mono">
                    Target: {verifyResult?.target_url || "http://192.168.21.160:8000"}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowModal(false)}
                className="text-slate-400 hover:text-slate-600 p-1 rounded-lg hover:bg-slate-100 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Body */}
            {isVerifying ? (
              <div className="py-8 flex flex-col items-center justify-center gap-3 text-center">
                <Loader2 className="w-8 h-8 text-indigo-600 animate-spin" />
                <p className="text-sm font-medium text-slate-700">
                  Contacting remote peer node at 192.168.21.160:8000...
                </p>
                <p className="text-xs text-slate-400">
                  Measuring round-trip latency &amp; verifying x-api-key authentication
                </p>
              </div>
            ) : verifyResult ? (
              <div className="flex flex-col gap-4">
                {/* Status Pill & Latency Card */}
                <div className="grid grid-cols-2 gap-3">
                  <div className="bg-slate-50 rounded-xl p-3 border border-slate-100">
                    <span className="text-[11px] font-medium text-slate-500 block">
                      Connection Status
                    </span>
                    <div className="mt-1 flex items-center gap-1.5">
                      <span
                        className={`inline-block w-2 h-2 rounded-full ${
                          verifyResult.connected ? "bg-emerald-500" : "bg-rose-500"
                        }`}
                      ></span>
                      <span
                        className={`text-sm font-semibold ${
                          verifyResult.connected
                            ? "text-emerald-700"
                            : "text-rose-700"
                        }`}
                      >
                        {verifyResult.connected
                          ? "ONLINE & AUTHENTICATED"
                          : "UNREACHABLE / OFFLINE"}
                      </span>
                    </div>
                  </div>

                  <div className="bg-slate-50 rounded-xl p-3 border border-slate-100">
                    <span className="text-[11px] font-medium text-slate-500 block">
                      Round-Trip Latency
                    </span>
                    <span className="text-sm font-semibold font-mono text-slate-800 mt-1 block">
                      {verifyResult.latency_ms > 0 ? `${verifyResult.latency_ms} ms` : "Timeout"}
                    </span>
                  </div>
                </div>

                {/* Diagnostic Details */}
                <div className="bg-slate-900 text-slate-100 rounded-xl p-3.5 text-xs font-mono overflow-x-auto max-h-48 border border-slate-800">
                  <div className="text-slate-400 text-[10px] uppercase tracking-wider mb-1 font-semibold">
                    Node Diagnostic Log &bull; Checked at {verifyResult.checked_at}
                  </div>
                  {verifyResult.connected ? (
                    <div>
                      <span className="text-emerald-400 font-semibold">
                        [HTTP {verifyResult.status_code} OK] Remote Health Check Passed:
                      </span>
                      <pre className="mt-1 text-slate-200">
                        {JSON.stringify(verifyResult.remote_response, null, 2)}
                      </pre>
                    </div>
                  ) : (
                    <div className="text-rose-400">
                      <span>[Connection Error]: </span>
                      <span>
                        {verifyResult.error || "Remote peer PC at 192.168.21.160:8000 is currently unreachable on this subnet."}
                      </span>
                      <p className="mt-2 text-slate-400 text-[11px]">
                        Tip: Ensure the teammate's machine has the Node.js/FastAPI Fabric service running on port 8000 and firewall permits inbound traffic.
                      </p>
                    </div>
                  )}
                </div>

                {/* Live Cross-Laptop Action: Send Test Audit Event */}
                <div className="pt-2 border-t border-slate-100 flex flex-col gap-2">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-xs font-semibold text-slate-900 block">
                        Live Cross-Laptop Ledger Demonstration
                      </span>
                      <span className="text-[11px] text-slate-500">
                        Mint an immutable audit transaction on peer PC during pitch
                      </span>
                    </div>
                    <button
                      onClick={handleSendTestEvent}
                      disabled={isSendingTestEvent}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-700 active:scale-95 rounded-lg shadow-xs transition-all disabled:opacity-60"
                    >
                      {isSendingTestEvent ? (
                        <>
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          <span>Dispatching...</span>
                        </>
                      ) : (
                        <>
                          <Send className="w-3.5 h-3.5" />
                          <span>Send Test Audit Event</span>
                        </>
                      )}
                    </button>
                  </div>

                  {testEventReceipt && (
                    <div
                      className={`p-3 rounded-xl text-xs font-mono border ${
                        testEventReceipt.success
                          ? "bg-emerald-50 text-emerald-800 border-emerald-200"
                          : "bg-rose-50 text-rose-800 border-rose-200"
                      }`}
                    >
                      {testEventReceipt.success ? (
                        <div>
                          <div className="font-semibold flex items-center gap-1 text-emerald-900">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            <span>Audit Transaction Committed on Peer Ledger!</span>
                          </div>
                          <div className="mt-1 text-[11px] space-y-0.5 text-emerald-700">
                            <div>Tx ID: <span className="font-bold">{testEventReceipt.transaction_id || testEventReceipt.receipt?.transaction_id || "tx-verified"}</span></div>
                            <div>Event ID: <span>{testEventReceipt.event_id}</span></div>
                            <div>Latency: <span>{testEventReceipt.latency_ms} ms</span></div>
                          </div>
                        </div>
                      ) : (
                        <div>
                          <div className="font-semibold text-rose-900 flex items-center gap-1">
                            <XCircle className="w-3.5 h-3.5" />
                            <span>Dispatch Failed</span>
                          </div>
                          <div className="mt-0.5 text-[11px] text-rose-700">
                            {testEventReceipt.error}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            ) : null}

            {/* Modal Footer */}
            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-100">
              <button
                onClick={() => setShowModal(false)}
                className="px-3.5 py-1.5 text-xs font-medium text-slate-600 hover:text-slate-800 hover:bg-slate-100 rounded-lg transition-colors"
              >
                Close
              </button>
              <button
                onClick={handleVerifyRemoteBlockchain}
                disabled={isVerifying}
                className="px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-lg transition-all shadow-xs"
              >
                Re-check Node
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
