import React from "react";
import { useDashboard } from "../../context/DashboardContext";
import { fetchIncidentDetails } from "../../utils/api";

const ThreatMonitoringTable = () => {
  const dashboardData = useDashboard() || {};
  const { threats = [], setSelectedIncident = () => {} } = dashboardData;

  // Ensure threats is an array
  const safeThreats = Array.isArray(threats) ? threats : [];

  const handleRowClick = async (id) => {
    try {
      const details = await fetchIncidentDetails(id);
      setSelectedIncident(details);
    } catch (error) {
      console.error("Failed to fetch incident details:", error);
    }
  };

  return (
    <div className="bg-slate-900/70 backdrop-blur-sm border border-slate-800/80 rounded-xl h-full">
      <div className="p-4 border-b border-slate-800/80">
        <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
          Investigation Queue
        </p>
        <h3 className="mt-1 text-sm font-semibold text-slate-100">
          Threat Monitoring
        </h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm text-left">
          <thead className="text-xs text-slate-500 uppercase bg-slate-900/30">
            <tr>
              <th className="px-4 py-3">Time</th>
              <th className="px-4 py-3">Threat Type</th>
              <th className="px-4 py-3">Source IP</th>
              <th className="px-4 py-3">User</th>
              <th className="px-4 py-3">Confidence (%)</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/50">
            {safeThreats.length > 0 ? (
              safeThreats.map((threat) => (
                <tr
                  key={threat?.id || Math.random()}
                  onClick={() => threat?.id && handleRowClick(threat.id)}
                  className="hover:bg-emerald-500/5 transition-colors cursor-pointer"
                >
                  <td className="px-4 py-3 text-slate-400 font-mono text-xs">
                    {threat?.time || "N/A"}
                  </td>
                  <td className="px-4 py-3 text-slate-300">
                    {threat?.status === "Phishing" ? "Phishing" : "Safe"}
                  </td>
                  <td className="px-4 py-3 text-slate-400 font-mono text-xs">
                    {threat?.sourceIp || "192.152.0." + (threat?.id || 0)}
                  </td>
                  <td className="px-4 py-3 text-slate-300">
                    {threat?.sender?.split("@")[0] || "Unknown"}
                  </td>
                  <td className="px-4 py-3 text-slate-300">
                    {threat?.confidence || 0}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={5} className="px-4 py-10 text-center">
                  <p className="text-sm font-medium text-slate-300">
                    No incidents are waiting for review
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    New detections will populate this investigation queue for
                    analyst triage.
                  </p>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ThreatMonitoringTable;
