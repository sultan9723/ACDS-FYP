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
    <div className="bg-slate-900/50 backdrop-blur-sm border border-slate-800 rounded-xl">
      <div className="p-4 border-b border-slate-800">
        <h3 className="text-sm font-semibold text-emerald-400/80">
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
            {safeThreats.map((threat) => (
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
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ThreatMonitoringTable;
