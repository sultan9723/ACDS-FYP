import React from "react";
import { useDashboard } from "../../context/DashboardContext";

const ModelPerformanceLogs = () => {
  const dashboardData = useDashboard() || {};
  const { logs = [], activityLogs = [] } = dashboardData;

  // Ensure logs is an array - prefer activity logs if available
  const safeLogs =
    Array.isArray(logs) && logs.length > 0
      ? logs
      : Array.isArray(activityLogs)
      ? activityLogs
          .filter(
            (log) =>
              log.event === "email_scanned" || log.event === "threat_detected"
          )
          .map((log, idx) => ({
            id: log.id || idx + 1,
            date: log.timestamp
              ? new Date(log.timestamp).toLocaleDateString()
              : "N/A",
            type:
              log.is_phishing || log.details?.is_phishing ? "Phishing" : "Safe",
            decision:
              log.is_phishing || log.details?.is_phishing
                ? "True Positive"
                : "True Negative",
            action:
              log.is_phishing || log.details?.is_phishing
                ? "Quarantine"
                : "Allowed",
            modelVersion: "v2.0",
            confidence: Math.round(
              (log.confidence || log.details?.confidence || 0) * 100
            ),
            subject: log.subject || log.details?.subject || "N/A",
          }))
      : [];

  return (
    <div>
      <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
            Historical Logs
          </p>
          <h2 className="mt-1 text-lg font-semibold text-slate-100">
            Model Performance Logs
          </h2>
        </div>
        <span className="rounded-full border border-slate-700 bg-slate-950/40 px-3 py-1 text-xs text-slate-400">
          {safeLogs.length} events available
        </span>
      </div>
      <div className="bg-slate-900/70 backdrop-blur-sm border border-slate-800/80 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[860px] text-sm text-left">
            <thead className="text-xs text-slate-500 uppercase bg-slate-950/50">
              <tr>
                <th className="px-4 py-3">Date</th>
                <th className="px-4 py-3">Subject</th>
                <th className="px-4 py-3">Classification</th>
                <th className="px-4 py-3">Confidence</th>
                <th className="px-4 py-3">Action</th>
                <th className="px-4 py-3">Model Version</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {safeLogs.length > 0 ? (
                safeLogs.slice(0, 20).map((log, index) => (
                  <tr
                    key={log?.id || index}
                    className="hover:bg-slate-800/40 transition-colors"
                  >
                    <td className="px-4 py-3 text-slate-400 font-mono text-xs">
                      {log?.date || "N/A"}
                    </td>
                    <td className="px-4 py-3 text-slate-300 max-w-[200px] truncate">
                      {log?.subject || "N/A"}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`px-2 py-1 rounded text-xs ${
                          log?.type === "Phishing"
                            ? "bg-red-500/15 text-red-200 border border-red-500/30"
                            : "bg-emerald-500/15 text-emerald-200 border border-emerald-500/30"
                        }`}
                      >
                        {log?.type || "N/A"}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="rounded-full border border-slate-700 bg-slate-950/40 px-2 py-0.5 text-xs text-slate-300">
                        {log?.confidence !== undefined
                          ? `${log.confidence}%`
                          : "N/A"}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`px-2 py-1 rounded text-xs ${
                          log?.action === "Quarantine" ||
                          log?.action === "Account Lock"
                            ? "bg-amber-500/20 text-amber-400"
                            : "bg-cyan-500/10 text-cyan-200 border border-cyan-500/25"
                        }`}
                      >
                        {log?.action || "N/A"}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-500 font-mono text-xs">
                      {log?.modelVersion || "N/A"}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td
                    colSpan={6}
                    className="px-4 py-10 text-center"
                  >
                    <p className="text-sm font-medium text-slate-300">
                      No audit events available
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                      Run demo mode or process detections to populate model
                      decisions, confidence, and action history.
                    </p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default ModelPerformanceLogs;
