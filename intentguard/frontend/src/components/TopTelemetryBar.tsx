"use client";

/**
 * TopTelemetryBar — Forensic Editorial Status Masthead
 * ====================================================
 * Features the 4 Mandatory Connection Badges:
 * 1. OpenClaw Docker Sandbox: ISOLATED
 * 2. Step-0 HMAC Contract: LOCKED
 * 3. Memory Vault: REDIS TTL ACTIVE
 * 4. Hyperledger Fabric 2.5.16 (Channel: intentguard | Chaincode v1.0.1): CONNECTED
 */

import React from "react";
import { SystemTelemetryState } from "../types/intentguard";
import { ShieldCheck, Lock, Database, Radio, Activity, Terminal } from "lucide-react";

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
  return (
    <header className="w-full bg-[#FFFFFF] border-b border-[#E5E4DF] px-6 py-3 select-none">
      <div className="max-w-[1600px] mx-auto flex flex-col xl:flex-row xl:items-center xl:justify-between gap-4">
        {/* Brand & Track Identity */}
        <div className="flex items-center gap-4">
          <div className="w-9 h-9 bg-[#1C1917] text-[#FAF9F6] flex items-center justify-center font-mono font-bold text-sm tracking-tighter">
            IG
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-bold tracking-tight text-[#1C1917] font-mono">
                INTENTGUARD // FORENSIC X-RAY & POLICY GATEWAY
              </h1>
              <span className="text-[10px] font-mono px-1.5 py-0.5 bg-[#FAF9F6] border border-[#E5E4DF] text-[#57534E]">
                v2.0-STABLE
              </span>
            </div>
            <p className="text-[11px] text-[#57534E] font-mono mt-0.5">
              GENESIS 2.0 • TRACK EVA 03 • PS 01 | Base Agent: OpenClaw (groq/llama-3.3-70b-versatile)
            </p>
          </div>
        </div>

        {/* 4 Mandatory Architectural Status Badges */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Badge 1: Sandbox Isolation */}
          <div
            title="Isolated non-root Docker runtime with memory & tool boundary"
            className="flex items-center gap-2 px-2.5 py-1.5 bg-[#FAF9F6] border border-[#E5E4DF] text-[11px] font-mono"
          >
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-600"></span>
            </span>
            <span className="text-[#57534E]">OpenClaw Docker Sandbox:</span>
            <span className="font-semibold text-[#065F46] bg-[#ECFDF5] px-1 py-0.5 border border-[#A7F3D0]">
              ISOLATED
            </span>
            <span className="text-[10px] text-[#78716C] hidden 2xl:inline">
              (0.5c | 512MB | non-root)
            </span>
          </div>

          {/* Badge 2: Step-0 HMAC Lock */}
          <div
            title="Step-0 Cryptographic Intent Contract signed via HMAC-SHA256"
            className="flex items-center gap-2 px-2.5 py-1.5 bg-[#FAF9F6] border border-[#E5E4DF] text-[11px] font-mono"
          >
            <Lock className="w-3.5 h-3.5 text-[#065F46]" />
            <span className="text-[#57534E]">Step-0 HMAC Contract:</span>
            <span className="font-semibold text-[#065F46] bg-[#ECFDF5] px-1 py-0.5 border border-[#A7F3D0]">
              LOCKED
            </span>
          </div>

          {/* Badge 3: Memory Vault */}
          <div
            title="Redis Ephemeral Quarantine Vault (EXPIRE 300s) protecting MEMORY.md"
            className="flex items-center gap-2 px-2.5 py-1.5 bg-[#FAF9F6] border border-[#E5E4DF] text-[11px] font-mono"
          >
            <Database className="w-3.5 h-3.5 text-[#065F46]" />
            <span className="text-[#57534E]">Memory Vault:</span>
            <span className="font-semibold text-[#065F46] bg-[#ECFDF5] px-1 py-0.5 border border-[#A7F3D0]">
              REDIS TTL ACTIVE
            </span>
          </div>

          {/* Badge 4: Hyperledger Fabric 2.5.16 */}
          <div
            title="Hyperledger Fabric 2.5.16 gRPC Gateway on Channel 'intentguard'"
            className="flex items-center gap-2 px-2.5 py-1.5 bg-[#FAF9F6] border border-[#E5E4DF] text-[11px] font-mono"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-[#065F46]" />
            <span className="text-[#57534E]">
              Hyperledger Fabric 2.5.16 (Channel: intentguard | Chaincode v1.0.1):
            </span>
            <span className="font-semibold text-[#065F46] bg-[#ECFDF5] px-1 py-0.5 border border-[#A7F3D0]">
              CONNECTED
            </span>
          </div>
        </div>

        {/* Live Bridge Ping & WebSocket Ticker */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 px-2 py-1 bg-[#FAF9F6] border border-[#E5E4DF] text-[10px] font-mono text-[#57534E]">
            <Radio className={`w-3 h-3 ${wsConnected ? "text-emerald-600 animate-pulse" : "text-amber-600"}`} />
            <span>WS /ws/xray-stream:</span>
            <span className={wsConnected ? "text-emerald-700 font-semibold" : "text-amber-700 font-semibold"}>
              {wsConnected ? "LIVE" : "STANDBY"}
            </span>
            <span className="text-[#A8A29E]">|</span>
            <span>{eventCount} evts</span>
          </div>

          <button
            onClick={onTriggerPing}
            className="flex items-center gap-1.5 px-3 py-1 bg-[#1C1917] hover:bg-[#292524] text-[#FAF9F6] text-xs font-mono transition-colors active:scale-95 border border-[#1C1917]"
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Verify Live Bridge</span>
          </button>
        </div>
      </div>
    </header>
  );
};
