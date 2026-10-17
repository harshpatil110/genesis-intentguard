"use client";

/**
 * LiveTelemetryTicker — Real-Time Event Stream Console
 * ====================================================
 * Linear / Vercel Aesthetic: Clean, collapsible drawer showing live
 * forensic hook events from /ws/xray-stream with hashes, action badges, and risks.
 */

import React, { useState } from "react";
import { XRayTelemetryEvent } from "../types/intentguard";
import { ChevronDown, ChevronUp, ShieldAlert, ShieldCheck, Activity, Terminal } from "lucide-react";

interface LiveTelemetryTickerProps {
  events: XRayTelemetryEvent[];
}

export const LiveTelemetryTicker: React.FC<LiveTelemetryTickerProps> = ({ events }) => {
  const [isExpanded, setIsExpanded] = useState<boolean>(true);

  return (
    <div className="w-full bg-white rounded-xl border border-slate-200/80 shadow-sm overflow-hidden select-text transition-all font-sans">
      {/* Ticker Header */}
      <div
        onClick={() => setIsExpanded(!isExpanded)}
        className="px-5 py-3 bg-slate-50/80 border-b border-slate-200/60 flex items-center justify-between cursor-pointer hover:bg-slate-100/60 transition-colors"
      >
        <div className="flex items-center gap-3">
          <div className="w-6 h-6 rounded-md bg-indigo-50 text-indigo-600 flex items-center justify-center">
            <Activity className="w-3.5 h-3.5" />
          </div>
          <span className="text-xs font-semibold text-slate-900 tracking-wide uppercase">
            Live Forensic X-Ray Telemetry Stream (/ws/xray-stream)
          </span>
          <span className="text-[11px] font-medium px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200/60 font-mono">
            {events.length} Events Logged
          </span>
        </div>
        <div className="flex items-center gap-2 text-xs font-medium text-slate-500">
          <span>{isExpanded ? "Collapse Stream" : "Expand Stream"}</span>
          {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronUp className="w-3.5 h-3.5" />}
        </div>
      </div>

      {/* Event Stream List */}
      {isExpanded && (
        <div className="max-h-64 overflow-y-auto divide-y divide-slate-100 bg-white text-xs">
          {events.length === 0 ? (
            <div className="p-8 text-center text-slate-400 font-sans flex flex-col items-center gap-2">
              <Terminal className="w-5 h-5 text-slate-300" />
              <span>Awaiting real-time interception telemetry from OpenClaw bridge...</span>
            </div>
          ) : (
            events.map((evt, idx) => {
              const isThreat = evt.threat_detected;
              return (
                <div
                  key={`${evt.event_id}-${idx}`}
                  className="px-5 py-2.5 flex flex-col md:flex-row md:items-center justify-between gap-3 hover:bg-slate-50/80 transition-colors"
                >
                  <div className="flex items-start md:items-center gap-2.5 flex-1 min-w-0">
                    {/* Threat Icon */}
                    {isThreat ? (
                      <ShieldAlert className="w-4 h-4 text-rose-600 shrink-0 mt-0.5 md:mt-0" />
                    ) : (
                      <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5 md:mt-0" />
                    )}

                    {/* Hook Stage Pill */}
                    <span className="px-2 py-0.5 rounded-md bg-slate-100 text-slate-700 font-mono text-[10px] font-medium shrink-0 border border-slate-200/60">
                      {evt.hook_stage}
                    </span>

                    {/* Action Taken Pill */}
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] shrink-0 font-semibold ${
                        isThreat
                          ? "bg-rose-50 text-rose-700 border border-rose-200/60"
                          : "bg-emerald-50 text-emerald-700 border border-emerald-200/60"
                      }`}
                    >
                      {evt.action_taken}
                    </span>

                    {/* Summary Text */}
                    <span className="text-slate-800 truncate font-sans text-xs">
                      {evt.summary}
                    </span>
                  </div>

                  {/* Metadata: Risk IDs + Timestamp + Hashes */}
                  <div className="flex items-center gap-2.5 shrink-0 text-slate-500 text-[11px]">
                    {evt.risk_category_ids && evt.risk_category_ids.length > 0 && (
                      <span className="px-1.5 py-0.5 rounded-md bg-amber-50 text-amber-800 border border-amber-200/60 text-[10px] font-mono font-medium">
                        Risk #{evt.risk_category_ids.join(", #")}
                      </span>
                    )}

                    {evt.details?.raw_evidence_sha256 && (
                      <span
                        title={`Evidence SHA-256: ${evt.details.raw_evidence_sha256}`}
                        className="text-[10px] font-mono bg-slate-50 px-1.5 py-0.5 rounded border border-slate-200/60 text-slate-600 hidden lg:inline"
                      >
                        sha: {evt.details.raw_evidence_sha256.slice(0, 8)}...
                      </span>
                    )}

                    <span className="text-[11px] text-slate-400 font-mono">
                      {new Date(evt.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                </div>
              );
            })
          )}
        </div>
      )}
    </div>
  );
};
