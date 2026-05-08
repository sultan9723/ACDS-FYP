import React from "react";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/Card";
import { Badge } from "../ui/Badge";
import { useDashboard } from "../../context/DashboardContext";
import { fetchIncidentDetails } from "../../utils/api";

const EmailList = () => {
  const dashboardData = useDashboard() || {};
  const allEmails = dashboardData.allEmails || [];
  const setSelectedIncident = dashboardData.setSelectedIncident || (() => {});
  const loading = dashboardData.loading;

  const handleRowClick = async (id) => {
    const details = await fetchIncidentDetails(id);
    setSelectedIncident(details);
  };

  // Helper to format confidence value
  const formatConfidence = (value) => {
    if (!value && value !== 0) return "N/A";
    // Already in percentage format
    if (value > 1) return `${Math.round(value)}%`;
    // Convert from decimal
    return `${Math.round(value * 100)}%`;
  };

  // Get severity badge color
  const getSeverityColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case "HIGH":
      case "CRITICAL":
        return "bg-red-900/50 text-red-400 border-red-900";
      case "MEDIUM":
        return "bg-yellow-900/50 text-yellow-400 border-yellow-900";
      case "LOW":
      case "SAFE":
        return "bg-green-900/50 text-green-400 border-green-900";
      default:
        return "bg-slate-900/50 text-slate-400 border-slate-700";
    }
  };

  return (
    <Card className="bg-slate-900/50 border-slate-800 h-full">
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-slate-200">Scanned Emails</CardTitle>
        <span className="text-xs text-slate-500">
          {allEmails.length} emails scanned
        </span>
      </CardHeader>
      <CardContent className="p-0">
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div>
          </div>
        ) : allEmails.length === 0 ? (
          <div className="text-center py-12 text-slate-500">
            <p>No emails scanned yet</p>
            <p className="text-sm mt-1">Run demo mode to scan sample emails</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="text-xs text-slate-400 uppercase bg-slate-900/50 border-b border-slate-800">
                <tr>
                  <th className="px-6 py-3">Sender</th>
                  <th className="px-6 py-3">Subject</th>
                  <th className="px-6 py-3">Severity</th>
                  <th className="px-6 py-3">Confidence</th>
                  <th className="px-6 py-3">Prediction</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {allEmails.map((email) => (
                  <tr
                    key={email.id}
                    onClick={() => handleRowClick(email.id)}
                    className="hover:bg-slate-800/30 transition-colors cursor-pointer"
                  >
                    <td className="px-6 py-4 text-slate-300 break-all max-w-[200px]">
                      {email.sender || email.source || "Unknown"}
                    </td>
                    <td className="px-6 py-4 text-slate-300 max-w-[200px] truncate">
                      {email.subject || email.description || "No subject"}
                    </td>
                    <td className="px-6 py-4">
                      <span className={`text-xs px-2 py-1 rounded border ${getSeverityColor(email.severity)}`}>
                        {email.severity || "N/A"}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <div className="w-full bg-slate-700 rounded-full h-1.5 max-w-[60px]">
                          <div
                            className={`h-1.5 rounded-full ${
                              email.prediction === "Phishing"
                                ? "bg-red-500"
                                : "bg-green-500"
                            }`}
                            style={{ width: `${Math.min(email.confidence > 1 ? email.confidence : email.confidence * 100, 100)}%` }}
                          ></div>
                        </div>
                        <span className="text-xs text-slate-400">
                          {formatConfidence(email.confidence)}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <Badge
                        variant={
                          email.prediction === "Phishing"
                            ? "destructive"
                            : "success"
                        }
                      >
                        {email.prediction || (email.is_phishing ? "Phishing" : "Safe")}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default EmailList;
