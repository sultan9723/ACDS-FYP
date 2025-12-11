import React, { useState } from "react";
import { useDashboard } from "../../context/DashboardContext";
import {
  DocumentTextIcon,
  FunnelIcon,
  ArrowPathIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  ClockIcon,
} from "@heroicons/react/24/outline";

const SystemActivityLogs = () => {
  const dashboardData = useDashboard() || {};
  const {
    testLogs = [],
    refreshTestLogs = async () => {},
    testRunning = false,
  } = dashboardData;

  const [filter, setFilter] = useState("all");
  const [refreshing, setRefreshing] = useState(false);

  // Ensure testLogs is an array
  const safeTestLogs = Array.isArray(testLogs) ? testLogs : [];

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await refreshTestLogs();
    } catch (error) {
      console.error("Failed to refresh logs:", error);
    } finally {
      setRefreshing(false);
    }
  };

  // Filter logs based on selection
  const filteredLogs = safeTestLogs.filter((log) => {
    if (filter === "all") return true;
    return log && log.event === filter;
  });

  const formatTime = (timestamp) => {
    if (!timestamp) return "";
    const date = new Date(timestamp);
    return date.toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  const getEventIcon = (event) => {
    switch (event) {
      case "email_scanned":
        return <DocumentTextIcon className="h-4 w-4 text-blue-400" />;
      case "threat_response":
        return <ShieldExclamationIcon className="h-4 w-4 text-green-400" />;
      case "error":
        return <ExclamationTriangleIcon className="h-4 w-4 text-red-400" />;
      case "test_completed":
        return <CheckCircleIcon className="h-4 w-4 text-cyan-400" />;
      default:
        return <DocumentTextIcon className="h-4 w-4 text-slate-400" />;
    }
  };

  const getEventColor = (event) => {
    switch (event) {
      case "email_scanned":
        return "border-l-blue-500";
      case "threat_response":
        return "border-l-green-500";
      case "error":
        return "border-l-red-500";
      case "test_completed":
        return "border-l-cyan-500";
      default:
        return "border-l-slate-500";
    }
  };

  return (
    <div className="bg-slate-900/50 backdrop-blur-sm border border-slate-800 rounded-xl p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-purple-500/20 rounded-lg">
            <DocumentTextIcon className="h-6 w-6 text-purple-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-slate-100">
              System Activity Logs
            </h2>
            <p className="text-sm text-slate-400">
              Real-time detection and response logs
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          {/* Filter */}
          <div className="flex items-center space-x-2">
            <FunnelIcon className="h-4 w-4 text-slate-500" />
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="bg-slate-800 border border-slate-700 rounded-lg px-2 py-1 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500"
            >
              <option value="all">All Events</option>
              <option value="email_scanned">Scans</option>
              <option value="threat_response">Responses</option>
              <option value="error">Errors</option>
              <option value="test_completed">Completed</option>
            </select>
          </div>

          {/* Refresh Button */}
          <button
            onClick={handleRefresh}
            disabled={refreshing || testRunning}
            className="p-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
          >
            <ArrowPathIcon
              className={`h-4 w-4 text-slate-400 ${
                refreshing ? "animate-spin" : ""
              }`}
            />
          </button>
        </div>
      </div>

      {/* Stats Bar */}
      <div className="flex items-center space-x-4 mb-4 text-xs">
        <span className="text-slate-500">
          Total: <span className="text-slate-300">{safeTestLogs.length}</span>
        </span>
        <span className="text-slate-600">|</span>
        <span className="text-blue-400">
          Scans:{" "}
          {safeTestLogs.filter((l) => l && l.event === "email_scanned").length}
        </span>
        <span className="text-green-400">
          Responses:{" "}
          {
            safeTestLogs.filter((l) => l && l.event === "threat_response")
              .length
          }
        </span>
        <span className="text-red-400">
          Errors: {safeTestLogs.filter((l) => l && l.event === "error").length}
        </span>
      </div>

      {/* Logs List */}
      {filteredLogs.length > 0 ? (
        <div className="space-y-2 max-h-[300px] overflow-y-auto custom-scrollbar">
          {filteredLogs.slice(0, 30).map((log, idx) => (
            <div
              key={idx}
              className={`flex items-start space-x-3 p-3 bg-slate-700/30 rounded-lg border-l-2 ${getEventColor(
                log.event
              )}`}
            >
              {/* Icon */}
              <div className="mt-1">{getEventIcon(log.event)}</div>

              {/* Content */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-slate-200 capitalize">
                    {log.event?.replace(/_/g, " ")}
                  </span>
                  <span className="text-xs text-slate-500 flex items-center">
                    <ClockIcon className="h-3 w-3 mr-1" />
                    {formatTime(log.timestamp)}
                  </span>
                </div>

                {/* Event specific details */}
                {log.event === "email_scanned" && (
                  <div className="text-xs text-slate-400">
                    <span className="truncate block max-w-[300px]">
                      {log.subject || "No subject"}
                    </span>
                    <div className="flex items-center space-x-3 mt-1">
                      <span
                        className={
                          log.is_phishing_detected
                            ? "text-red-400"
                            : "text-green-400"
                        }
                      >
                        {log.is_phishing_detected ? "⚠ Phishing" : "✓ Safe"}
                      </span>
                      <span>
                        Confidence: {Math.round((log.confidence || 0) * 100)}%
                      </span>
                      {log.correct_prediction !== undefined && (
                        <span
                          className={
                            log.correct_prediction
                              ? "text-green-400"
                              : "text-red-400"
                          }
                        >
                          {log.correct_prediction ? "Correct" : "Incorrect"}
                        </span>
                      )}
                    </div>
                  </div>
                )}

                {log.event === "threat_response" && (
                  <div className="text-xs text-slate-400">
                    <span>Threat: {log.threat_id}</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {(log.actions || []).map((action, i) => (
                        <span
                          key={i}
                          className="px-1.5 py-0.5 bg-green-500/20 text-green-400 rounded"
                        >
                          {action.replace(/_/g, " ")}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {log.event === "error" && (
                  <p className="text-xs text-red-400">{log.error}</p>
                )}

                {log.event === "test_completed" && (
                  <div className="text-xs text-slate-400">
                    <span>
                      Processed: {log.total_processed} | Accuracy:{" "}
                      {Math.round((log.accuracy || 0) * 100)}% | Threats:{" "}
                      {log.threats_found}
                    </span>
                  </div>
                )}

                {/* Session ID */}
                <span className="text-xs text-slate-600 mt-1 block">
                  Session: {log.session_id}
                </span>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-center py-8 text-slate-500">
          <DocumentTextIcon className="h-10 w-10 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No activity logs yet</p>
          <p className="text-xs mt-1">Logs will appear when tests are run</p>
        </div>
      )}
    </div>
  );
};

export default SystemActivityLogs;
