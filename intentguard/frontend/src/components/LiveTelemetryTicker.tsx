"use client";

/**
 * LiveTelemetryTicker — Real-time event stream console
 * ====================================================
 * Renders incoming hook events from /ws/xray-stream with
 * cryptographic hashes, action badges, and risk category IDs.
 */

import React, { useState } from "react";
import { XRayTelemetryEvent } from "../types/intentguard";
import { ChevronDown, ChevronUp, ShieldAlert, ShieldCheck, Activity } from "lucide-react";

interface LiveTelemetryTickerProps {
  events: XRayTelemetryEvent[];
}

export const LiveTelemetryTicker: React.FC<LiveTelemetryTickerProps> = ({ events }) => {
  const [isExpanded, setIsExpanded] = useState<boolean>(true);

  return (
    <div className="w-full bg-[#FFFFFF] border-t border-[#E5E4DF] select-text">
      {/* Ticker Header */}
      <div
        onClick={() => setIsExpanded(!isExpanded)}
        className="px-6 py-2 bg-[#FAFAF9] border-b border-[#E5E4DF] flex items-center justify-between cursor-pointer hover:bg-[#F5F5F4] transition-colors"
      >
        <div className="flex items-center gap-3">
          <Activity className="w-4 h-4 text-[#1C1917]" />
          <span className="text-xs font-mono font-semibold text-[#1C1917] tracking-wider uppercase">
            Live X-Ray Telemetry Stream (/ws/xray-stream)
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 bg-[#ECFDF5] border border-[#A7F3D0] text-[#065F46]">
            {events.length} EVENTS RECORDED
          </span>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-[#57534E]">
          <span>{isExpanded ? "Collapse Stream" : "Expand Stream"}</span>
          {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronUp className="w-3.5 h-3.5" />}
        </div>
      </div>

      {/* Event Stream List */}
      {isExpanded && (
        <div className="max-h-60 overflow-y-auto divide-y divide-[#E5E4DF] bg-[#FFFFFF] font-mono text-xs">
          {events.length === 0 ? (
            <div className="p-6 text-center text-[#78716C]">
              Awaiting real-time telemetry from OpenClaw Interceptor Bridge...
            </div>
          ) : (
            events.map((evt, idx) => {
              const isThreat = evt.threat_detected;
              return (
                <div
                  key={`${evt.event_id}-${idx}`}
                  className="px-6 py-2.5 flex flex-col md:flex-row md:items-center justify-between gap-3 hover:bg-[#FAF9F6] transition-colors"
                >
                  <div className="flex items-start md:items-center gap-3 flex-1 min-w-0">
                    {/* Threat Icon */}
                    {isThreat ? (
                      <ShieldAlert className="w-4 h-4 text-rose-600 shrink-0 mt-0.5 md:mt-0" />
                    ) : (
                      <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5 md:mt-0" />
                    )}

                    {/* Hook Stage Pill */}
                    <span className="px-1.5 py-0.5 bg-[#FAF9F6] border border-[#E5E4DF] text-[10px] text-[#57534E] shrink-0">
                      {evt.hook_stage}
                    </span>

                    {/* Action Taken Pill */}
                    <span
                      className={`px-1.5 py-0.5 text-[10px] border shrink-0 font-medium ${
                        isThreat
                          ? "bg-[#FEF2F2] text-[#991B1B] border-[#FECACA]"
                          : "bg-[#ECFDF5] text-[#065F46] border-[#A7F3D0]"
                      }`}
                    >
                      {evt.action_taken}
                    </span>

                    {/* Summary Text */}
                    <span className="text-[#1C1917] truncate font-sans text-xs">
                      {evt.summary}
                    </span>
                  </div>

                  {/* Metadata: Risk IDs + Timestamp + Hashes */}
                  <div className="flex items-center gap-3 shrink-0 text-[11px] text-[#78716C]">
                    {evt.risk_category_ids && evt.risk_category_ids.length > 0 && (
                      <span className="px-1.5 py-0.5 bg-[#FFFBEB] text-[#92400E] border border-[#FDE68A] text-[10px]">
                        Risk #{evt.risk_category_ids.join(", #")}
                      </span>
                    )}

                    {evt.details?.raw_evidence_sha256 && (
                      <span
                        title={`Evidence SHA-256: ${evt.details.raw_evidence_sha256}`}
                        className="text-[10px] bg-[#FAF9F6] px-1 py-0.5 border border-[#E5E4DF] hidden lg:inline"
                      >
                        sha: {evt.details.raw_evidence_sha256.slice(0, 8)}...
                      </span>
                    )}

                    <span className="text-[10px] text-[#A8A29E]">
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
