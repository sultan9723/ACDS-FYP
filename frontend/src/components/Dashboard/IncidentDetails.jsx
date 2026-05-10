import React from "react";
import { useDashboard } from "../../context/DashboardContext";

const IncidentDetails = () => {
  const dashboardData = useDashboard() || {};
  const { selectedIncident } = dashboardData;

  if (!selectedIncident) {
    return (
      <div className="bg-slate-900/70 backdrop-blur-sm border border-slate-800/80 rounded-xl p-6 h-full flex items-center justify-center">
        <div className="max-w-sm text-center">
          <p className="text-sm font-medium text-slate-300">
            No incident selected
          </p>
          <p className="mt-2 text-xs leading-5 text-slate-500">
            Select a row from Threat Monitoring to review evidence,
            confidence, automated action, and analyst feedback.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-slate-900/70 backdrop-blur-sm border border-slate-800/80 rounded-xl h-full">
      <div className="p-4 border-b border-slate-800/80">
        <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
          Analyst Review
        </p>
        <h3 className="mt-1 text-sm font-semibold text-slate-100">
          Incident Details
        </h3>
      </div>
      <div className="p-4 space-y-4">
        {/* Details Grid */}
        <div className="space-y-3 text-sm">
          <div className="flex justify-between">
            <span className="text-slate-500">Date & Time</span>
            <span className="text-slate-300">
              {selectedIncident?.date || "N/A"}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">Description</span>
            <span className="text-slate-300">
              {selectedIncident?.prediction || "N/A"}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">Source IP</span>
            <span className="text-slate-300 font-mono text-xs">
              {selectedIncident?.sourceIp || "202.122.44.18"}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">Target Account</span>
            <span className="text-slate-300 text-xs truncate max-w-[150px]">
              {selectedIncident.sender}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">Confidence</span>
            <span className="text-slate-300">
              {selectedIncident.confidence}%
            </span>
          </div>
        </div>

        {/* Explanation */}
        <div>
          <p className="text-slate-500 text-xs mb-1">Explanation</p>
          <p className="text-slate-400 text-xs leading-relaxed">
            {selectedIncident.explanation}
          </p>
        </div>

        {/* Automated Action */}
        <div className="pt-2 border-t border-slate-800">
          <p className="text-slate-500 text-xs mb-2">Automated Action</p>
          <div className="space-y-1 text-xs">
            <p className="text-slate-400">
              <span className="text-slate-500">Account</span>{" "}
              <span className="text-slate-300">temporarily locked</span>
            </p>
            <p className="text-slate-400">
              <span className="text-slate-500">Source IP blocked</span>{" "}
              <span className="text-slate-300">(Firewall)</span>
            </p>
          </div>
        </div>

        {/* Analyst Ticket */}
        <div className="text-xs text-slate-400">
          A <span className="text-emerald-400">ticket</span> logged for{" "}
          <span className="text-slate-300">SOC analyst</span>
        </div>

        {/* Feedback Buttons */}
        <div className="flex gap-2 pt-2">
          <button className="flex-1 px-3 py-2 text-xs font-medium text-slate-300 bg-slate-800/50 border border-slate-700 rounded-lg hover:bg-slate-700/50 transition-colors">
            True Positive
          </button>
          <button className="flex-1 px-3 py-2 text-xs font-medium text-emerald-400 bg-emerald-900/20 border border-emerald-800/50 rounded-lg hover:bg-emerald-900/30 transition-colors">
            False Positive
          </button>
        </div>

        {/* Feedback Log */}
        <div className="pt-4 border-t border-slate-800">
          <p className="text-slate-500 text-xs mb-3">Feedback Log</p>
          <div className="flex justify-around">
            <div className="text-center">
              <p className="text-xs text-slate-500">True Positive</p>
              <p className="text-lg font-semibold text-slate-300">12</p>
            </div>
            <div className="text-center">
              <p className="text-xs text-slate-500">False Positive</p>
              <p className="text-lg font-semibold text-slate-300">3</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default IncidentDetails;
