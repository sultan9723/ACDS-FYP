import React from "react";
import { useDashboard } from "../../context/DashboardContext";
import {
  ShieldCheckIcon,
  BellAlertIcon,
  TrashIcon,
  EnvelopeIcon,
  ClockIcon,
  CheckCircleIcon,
} from "@heroicons/react/24/outline";

const ThreatResponseFeed = () => {
  const dashboardData = useDashboard() || {};
  const { liveThreats = [], responseActions = [] } = dashboardData;

  // Ensure arrays are valid
  const safeLiveThreats = Array.isArray(liveThreats) ? liveThreats : [];
  const safeResponseActions = Array.isArray(responseActions)
    ? responseActions
    : [];

  // Combine threats and responses into a timeline
  const timelineItems = [];

  // Add threats to timeline
  safeLiveThreats.forEach((threat) => {
    if (threat) {
      timelineItems.push({
        type: "threat",
        id: threat.id,
        timestamp: threat.detected_at,
        data: threat,
      });
    }
  });

  // Add response actions to timeline
  safeResponseActions.forEach((action) => {
    if (action) {
      timelineItems.push({
        type: "response",
        id: `action-${action.threat_id}`,
        timestamp: action.timestamp,
        data: action,
      });
    }
  });

  // Sort by timestamp descending
  timelineItems.sort(
    (a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0)
  );

  const formatTime = (timestamp) => {
    if (!timestamp) return "";
    const date = new Date(timestamp);
    return date.toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case "CRITICAL":
        return "text-red-500 bg-red-500/20";
      case "HIGH":
        return "text-orange-500 bg-orange-500/20";
      case "MEDIUM":
        return "text-yellow-500 bg-yellow-500/20";
      case "LOW":
        return "text-green-500 bg-green-500/20";
      default:
        return "text-slate-400 bg-slate-500/20";
    }
  };

  const getActionIcon = (actionType) => {
    switch (actionType) {
      case "quarantine_email":
        return <EnvelopeIcon className="h-4 w-4" />;
      case "block_sender":
        return <ShieldCheckIcon className="h-4 w-4" />;
      case "delete_email":
        return <TrashIcon className="h-4 w-4" />;
      case "send_alert":
        return <BellAlertIcon className="h-4 w-4" />;
      default:
        return <CheckCircleIcon className="h-4 w-4" />;
    }
  };

  return (
    <div className="bg-slate-900/50 backdrop-blur-sm border border-slate-800 rounded-xl p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-red-500/20 rounded-lg">
            <ShieldCheckIcon className="h-6 w-6 text-red-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-slate-100">
              Threat Response Feed
            </h2>
            <p className="text-sm text-slate-400">
              Real-time detection & automated responses
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2 text-sm">
          <span className="text-slate-500">Threats:</span>
          <span className="text-red-400 font-bold">
            {safeLiveThreats.length}
          </span>
          <span className="text-slate-600 mx-1">|</span>
          <span className="text-slate-500">Resolved:</span>
          <span className="text-green-400 font-bold">
            {safeResponseActions.length}
          </span>
        </div>
      </div>

      {/* Timeline */}
      {timelineItems.length > 0 ? (
        <div className="space-y-4 max-h-[400px] overflow-y-auto custom-scrollbar">
          {timelineItems.slice(0, 15).map((item, idx) => (
            <div key={item.id || idx} className="relative">
              {/* Timeline line */}
              {idx < timelineItems.length - 1 && (
                <div className="absolute left-[15px] top-[40px] bottom-[-16px] w-[2px] bg-slate-700" />
              )}

              {item.type === "threat" ? (
                // Threat Detected Item
                <div className="flex items-start space-x-4">
                  <div className="p-2 bg-red-500/20 rounded-full border-2 border-red-500/50 z-10">
                    <BellAlertIcon className="h-4 w-4 text-red-400" />
                  </div>
                  <div className="flex-1 bg-red-500/10 border border-red-500/30 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-semibold text-red-400">
                        THREAT DETECTED
                      </span>
                      <span className="text-xs text-slate-500 flex items-center">
                        <ClockIcon className="h-3 w-3 mr-1" />
                        {formatTime(item.timestamp)}
                      </span>
                    </div>
                    <p className="text-sm text-slate-100 font-medium truncate">
                      {item.data.subject}
                    </p>
                    <p className="text-xs text-slate-400 mt-1">
                      From: {item.data.sender}
                    </p>
                    <div className="flex items-center space-x-3 mt-2">
                      <span
                        className={`text-xs px-2 py-1 rounded ${getSeverityColor(
                          item.data.severity
                        )}`}
                      >
                        {item.data.severity}
                      </span>
                      <span className="text-xs text-slate-500">
                        Confidence:{" "}
                        {Math.round((item.data.confidence || 0) * 100)}%
                      </span>
                      <span className="text-xs text-slate-600">
                        ID: {item.data.id}
                      </span>
                    </div>
                  </div>
                </div>
              ) : (
                // Response Action Item
                <div className="flex items-start space-x-4">
                  <div className="p-2 bg-green-500/20 rounded-full border-2 border-green-500/50 z-10">
                    <ShieldCheckIcon className="h-4 w-4 text-green-400" />
                  </div>
                  <div className="flex-1 bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-semibold text-green-400">
                        AUTO-RESOLVED
                      </span>
                      <span className="text-xs text-slate-500 flex items-center">
                        <ClockIcon className="h-3 w-3 mr-1" />
                        {formatTime(item.timestamp)}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mb-2">
                      Threat ID: {item.data.threat_id}
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {(item.data.actions || []).map((action, actionIdx) => (
                        <span
                          key={actionIdx}
                          className="flex items-center space-x-1 text-xs px-2 py-1 bg-green-500/20 text-green-400 rounded"
                        >
                          {getActionIcon(action)}
                          <span>{action.replace(/_/g, " ")}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        // Empty State
        <div className="text-center py-12 text-slate-500">
          <ShieldCheckIcon className="h-12 w-12 mx-auto mb-3 opacity-50" />
          <p>No threat activity yet</p>
          <p className="text-sm mt-1">
            Run a live test to see real-time threat detection
          </p>
        </div>
      )}
    </div>
  );
};

export default ThreatResponseFeed;
