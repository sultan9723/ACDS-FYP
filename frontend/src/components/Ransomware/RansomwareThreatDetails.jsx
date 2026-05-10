import React from "react";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/Card";
import ThreeLayerDetectionVisualization from "./ThreeLayerDetectionVisualization";
import ResponseActionsPanel from "./ResponseActionsPanel";

const getSeverityColor = (severity) => {
  switch (severity?.toUpperCase()) {
    case "CRITICAL":
      return "bg-red-900/50 text-red-400 border-red-900";
    case "HIGH":
      return "bg-orange-900/50 text-orange-400 border-orange-900";
    case "MEDIUM":
      return "bg-yellow-900/50 text-yellow-400 border-yellow-900";
    default:
      return "bg-green-900/50 text-green-400 border-green-900";
  }
};

const RansomwareThreatDetails = ({ threat }) => {
  if (!threat) {
    return (
      <Card className="bg-slate-900/50 border-slate-800 min-h-[320px]">
        <CardHeader>
          <CardTitle className="text-slate-200">Threat Details</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col items-center justify-center h-48 text-slate-500">
            <p className="text-sm">No threat selected</p>
            <p className="text-xs mt-1">Scan a command to see details</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (threat.layers) {
    return (
      <div className="space-y-4">
        <ThreeLayerDetectionVisualization result={threat} />
        <ResponseActionsPanel threat={threat} embedded />
      </div>
    );
  }

  const detection = threat.pipeline_results?.detection || {};
  const explain = threat.pipeline_results?.explainability || {};
  const response = threat.pipeline_results?.response || {};

  return (
    <Card className="bg-slate-900/50 border-slate-800">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-slate-200 text-base">
            Threat Details
          </CardTitle>
          <span
            className={`text-xs px-2 py-1 rounded border ${getSeverityColor(
              threat.severity
            )}`}
          >
            {threat.severity || "LOW"}
          </span>
        </div>
        <p className="text-xs text-slate-500 font-mono mt-1">
          {threat.incident_id}
        </p>
      </CardHeader>

      <CardContent className="space-y-4 text-sm">
        {/* Detection Summary */}
        <div>
          <p className="text-xs text-slate-500 uppercase mb-2">
            Detection Result
          </p>
          <div className="grid grid-cols-2 gap-2">
            <div className="bg-slate-800/50 rounded-lg p-3">
              <p className="text-xs text-slate-500">Result</p>
              <p
                className={`font-semibold ${
                  detection.is_ransomware ? "text-red-400" : "text-green-400"
                }`}
              >
                {detection.is_ransomware ? "Ransomware" : "Safe"}
              </p>
            </div>
            <div className="bg-slate-800/50 rounded-lg p-3">
              <p className="text-xs text-slate-500">Confidence</p>
              <p className="text-slate-200 font-semibold">
                {detection.confidence
                  ? `${Math.round(detection.confidence * 100)}%`
                  : "N/A"}
              </p>
            </div>
            <div className="bg-slate-800/50 rounded-lg p-3">
              <p className="text-xs text-slate-500">Risk Score</p>
              <p className="text-slate-200 font-semibold">
                {detection.risk_score ?? "N/A"}/100
              </p>
            </div>
            <div className="bg-slate-800/50 rounded-lg p-3">
              <p className="text-xs text-slate-500">Model</p>
              <p className="text-slate-200 font-semibold text-xs">
                {detection.model_used || "N/A"}
              </p>
            </div>
          </div>
        </div>

        {/* Behavior Categories */}
        {explain.behavior_categories?.length > 0 && (
          <div>
            <p className="text-xs text-slate-500 uppercase mb-2">
              Behavior Categories
            </p>
            <div className="flex flex-wrap gap-2">
              {explain.behavior_categories.map((cat) => (
                <span
                  key={cat}
                  className="text-xs px-2 py-1 bg-red-900/30 text-red-400 border border-red-900/50 rounded"
                >
                  {cat.replace(/_/g, " ")}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Attack Stage */}
        {explain.attack_stage && (
          <div>
            <p className="text-xs text-slate-500 uppercase mb-2">
              Attack Stage
            </p>
            <span className="text-xs px-2 py-1 bg-orange-900/30 text-orange-400 border border-orange-900/50 rounded">
              {explain.attack_stage.replace(/_/g, " ")}
            </span>
          </div>
        )}

        {/* MITRE ATT&CK */}
        {explain.mitre_tactics?.length > 0 && (
          <div>
            <p className="text-xs text-slate-500 uppercase mb-2">
              MITRE ATT&CK
            </p>
            <div className="space-y-1">
              {explain.mitre_tactics.map((tactic) => (
                <p
                  key={tactic}
                  className="text-xs text-slate-300 font-mono bg-slate-800/50 px-2 py-1 rounded"
                >
                  {tactic}
                </p>
              ))}
            </div>
          </div>
        )}

        {/* IOCs */}
        {explain.iocs && (
          <div>
            <p className="text-xs text-slate-500 uppercase mb-2">IOCs</p>
            <div className="space-y-1">
              {explain.iocs.suspicious_keywords?.length > 0 && (
                <div className="bg-slate-800/50 rounded-lg p-2">
                  <p className="text-xs text-slate-500 mb-1">
                    Suspicious Keywords
                  </p>
                  <p className="text-xs text-red-400 font-mono">
                    {explain.iocs.suspicious_keywords.join(", ")}
                  </p>
                </div>
              )}
              {explain.iocs.file_paths?.length > 0 && (
                <div className="bg-slate-800/50 rounded-lg p-2">
                  <p className="text-xs text-slate-500 mb-1">File Paths</p>
                  {explain.iocs.file_paths.map((fp) => (
                    <p key={fp} className="text-xs text-slate-300 font-mono">
                      {fp}
                    </p>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Explanation */}
        {explain.explanation && (
          <div>
            <p className="text-xs text-slate-500 uppercase mb-2">
              Explanation
            </p>
            <p className="text-xs text-slate-300 leading-relaxed bg-slate-800/50 rounded-lg p-3">
              {explain.explanation}
            </p>
          </div>
        )}

        {/* Response Actions */}
        {response.actions_executed?.length > 0 && (
          <div>
            <p className="text-xs text-slate-500 uppercase mb-2">
              Response Actions
            </p>
            <div className="space-y-1">
              {response.actions_executed.map((action) => (
                <div
                  key={action}
                  className="flex items-center gap-2 text-xs text-emerald-400"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                  {action}
                </div>
              ))}
            </div>
          </div>
        )}

        <ResponseActionsPanel threat={threat} embedded />

        {/* Lifecycle State */}
        <div className="pt-2 border-t border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>State: {threat.lifecycle_state || "—"}</span>
            <span>{threat.processing_time_ms}ms</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default RansomwareThreatDetails;
