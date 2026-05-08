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
      <h2 className="text-sm font-semibold text-emerald-400/80 uppercase tracking-wider mb-4">
        Model Performance Logs
      </h2>
      <div className="bg-slate-900/50 backdrop-blur-sm border border-slate-800 rounded-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs text-slate-500 uppercase bg-slate-900/30">
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
                    className="hover:bg-emerald-500/5 transition-colors"
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
                            ? "bg-red-500/20 text-red-400"
                            : "bg-green-500/20 text-green-400"
                        }`}
                      >
                        {log?.type || "N/A"}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-400 text-xs">
                      {log?.confidence !== undefined
                        ? `${log.confidence}%`
                        : "N/A"}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`px-2 py-1 rounded text-xs ${
                          log?.action === "Quarantine" ||
                          log?.action === "Account Lock"
                            ? "bg-amber-500/20 text-amber-400"
                            : "bg-blue-500/20 text-blue-400"
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
                    className="px-4 py-8 text-center text-slate-500"
                  >
                    No model logs yet. Run demo mode or process emails to see
                    logs.
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
