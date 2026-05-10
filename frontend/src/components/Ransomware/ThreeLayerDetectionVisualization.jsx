import React from "react";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/Card";

const ThreeLayerDetectionVisualization = ({ result }) => {
  if (!result) {
    return (
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-slate-200">3-Layer Detection Analysis</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col items-center justify-center py-12 text-slate-500">
            <p className="text-sm">No detection results available</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  const layers = result.layers || {};
  const layer1 = layers.layer1_command_behavior || {};
  const layer2 = layers.layer2_pe_header || {};
  const layer3 = layers.layer3_mass_encryption || {};

  const getVerdictColor = (verdict) => {
    switch (verdict?.toUpperCase()) {
      case "RANSOMWARE_DETECTED":
        return "bg-red-900/50 text-red-400 border-red-900";
      case "SUSPICIOUS":
        return "bg-yellow-900/50 text-yellow-400 border-yellow-900";
      case "BENIGN":
        return "bg-green-900/50 text-green-400 border-green-900";
      default:
        return "bg-slate-900/50 text-slate-400 border-slate-700";
    }
  };

  const getLayerStatusColor = (status, isRansomware) => {
    if (status === "error") return "bg-red-900/30 text-red-400 border-red-800";
    if (status === "threat_detected" || isRansomware)
      return "bg-red-900/30 text-red-400 border-red-800";
    if (status === "ready" || status === "monitoring")
      return "bg-green-900/30 text-green-400 border-green-800";
    return "bg-slate-900/30 text-slate-400 border-slate-700";
  };

  const getProgressBarColor = (isRansomware) => {
    return isRansomware ? "bg-red-500" : "bg-green-500";
  };

  const formatConfidence = (value) => {
    if (!value && value !== 0) return "N/A";
    if (value > 1) return `${Math.round(value)}%`;
    return `${Math.round(value * 100)}%`;
  };

  return (
    <div className="space-y-4">
      {/* Overall Verdict */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-slate-200 text-lg">
            Detection Verdict
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-end justify-between">
            <div>
              <p className="text-xs text-slate-500 uppercase mb-2">
                Overall Result
              </p>
              <p
                className={`text-2xl font-bold ${
                  result.overall_verdict === "RANSOMWARE_DETECTED"
                    ? "text-red-400"
                    : result.overall_verdict === "SUSPICIOUS"
                    ? "text-yellow-400"
                    : "text-green-400"
                }`}
              >
                {result.overall_verdict?.replace(/_/g, " ")}
              </p>
            </div>
            <div className="text-right">
              <p className="text-xs text-slate-500 mb-2">Confidence</p>
              <p className="text-xl font-bold text-slate-200">
                {formatConfidence(result.detection_confidence)}
              </p>
            </div>
          </div>

          {/* Confidence Bar */}
          <div>
            <div className="w-full bg-slate-700 rounded-full h-2">
              <div
                className={`h-2 rounded-full transition-all ${
                  result.detection_confidence > 0.7
                    ? "bg-red-500"
                    : result.detection_confidence > 0.4
                    ? "bg-yellow-500"
                    : "bg-green-500"
                }`}
                style={{
                  width: `${Math.min(result.detection_confidence * 100, 100)}%`,
                }}
              ></div>
            </div>
          </div>

          {/* Threat ID */}
          {result.threat_id && (
            <div className="pt-2 border-t border-slate-800">
              <p className="text-xs text-slate-500 mb-1">Threat ID</p>
              <p className="text-sm font-mono text-slate-300">
                {result.threat_id}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Layer 1: Command Behavior Detection */}
      <Card
        className={`border-2 transition-colors ${getLayerStatusColor(
          layer1.status,
          layer1.is_ransomware
        )}`}
      >
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-slate-800/50 flex items-center justify-center text-lg font-bold">
                1
              </div>
              <div>
                <CardTitle className="text-slate-200 text-base">
                  Command Behavior Analysis
                </CardTitle>
                <p className="text-xs text-slate-500 mt-1">
                  TF-IDF + Random Forest Model
                </p>
              </div>
            </div>
            {layer1.status === "error" ? (
              <span className="text-xs px-3 py-1 bg-red-900/50 text-red-400 rounded border border-red-800">
                Error
              </span>
            ) : layer1.status !== "success" ? (
              <span className="text-xs px-3 py-1 bg-slate-900/50 text-slate-400 rounded border border-slate-700">
                Not Available
              </span>
            ) : layer1.is_ransomware ? (
              <span className="text-xs px-3 py-1 bg-red-900/50 text-red-400 rounded border border-red-800 font-semibold">
                ⚠ Detected
              </span>
            ) : (
              <span className="text-xs px-3 py-1 bg-green-900/50 text-green-400 rounded border border-green-800">
                ✓ Safe
              </span>
            )}
          </div>
        </CardHeader>
        {layer1.status === "success" && (
          <CardContent className="pt-0 space-y-3">
            <div className="grid grid-cols-3 gap-2">
              <div className="bg-slate-800/50 rounded p-2">
                <p className="text-xs text-slate-500 mb-1">Ransomware</p>
                <p className="text-sm font-bold text-slate-200">
                  {formatConfidence(layer1.confidence)}
                </p>
              </div>
              <div className="bg-slate-800/50 rounded p-2">
                <p className="text-xs text-slate-500 mb-1">Risk Score</p>
                <p className="text-sm font-bold text-slate-200">
                  {layer1.risk_score
                    ? `${Math.round(layer1.risk_score * 100)}/100`
                    : "N/A"}
                </p>
              </div>
              <div className="bg-slate-800/50 rounded p-2">
                <p className="text-xs text-slate-500 mb-1">Severity</p>
                <p className="text-sm font-bold text-slate-200">
                  {layer1.severity || "N/A"}
                </p>
              </div>
            </div>

            {layer1.detected_patterns?.length > 0 && (
              <div>
                <p className="text-xs text-slate-500 mb-2">Why Detected</p>
                <div className="flex flex-wrap gap-1">
                  {layer1.detected_patterns.map((pattern) => (
                    <span
                      key={pattern}
                      className="text-xs px-2 py-1 bg-red-900/30 text-red-400 rounded border border-red-800/50"
                    >
                      {pattern === "shadow_copy_deletion" && "Shadow copy deletion commands detected"}
                      {pattern === "encryption_commands" && "File encryption commands identified"}
                      {pattern === "backup_interference" && "Backup system interference detected"}
                      {pattern === "suspicious_network" && "Suspicious network activity patterns"}
                      {pattern.replace(/_/g, " ")}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        )}
      </Card>

      {/* Layer 2: PE Header Binary Detection */}
      <Card
        className={`border-2 transition-colors ${getLayerStatusColor(
          layer2.status,
          false
        )}`}
      >
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-slate-800/50 flex items-center justify-center text-lg font-bold">
                2
              </div>
              <div>
                <CardTitle className="text-slate-200 text-base">
                  PE Header Binary Detection
                </CardTitle>
                <p className="text-xs text-slate-500 mt-1">
                  Gradient Boosting Classifier (Ransomware-Only)
                </p>
              </div>
            </div>
            <span className="text-xs px-3 py-1 bg-slate-900/50 text-slate-400 rounded border border-slate-700">
              {layer2.status === "success"
                ? "Analysis Complete"
                : layer2.status === "ready"
                  ? "Waiting for input"
                  : layer2.status || "Waiting for input"}
            </span>
          </div>
        </CardHeader>
        <CardContent className="pt-0 space-y-3">
          <p className="text-xs text-slate-400">
            {layer2.note ||
              "Analyzes PE header features from executable files for ransomware-specific signatures. Filtering ensures detection of ransomware binaries, not generic malware."}
          </p>
        </CardContent>
      </Card>

      {/* Layer 3: Mass-Encryption Orchestrator */}
      <Card
        className={`border-2 transition-colors ${getLayerStatusColor(
          layer3.status,
          layer3.status === "threat_detected"
        )}`}
      >
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-slate-800/50 flex items-center justify-center text-lg font-bold">
                3
              </div>
              <div>
                <CardTitle className="text-slate-200 text-base">
                  Mass-Encryption Orchestrator
                </CardTitle>
                <p className="text-xs text-slate-500 mt-1">
                  Rule-Based File Activity Analysis
                </p>
              </div>
            </div>
            {layer3.status === "threat_detected" ? (
              <span className="text-xs px-3 py-1 bg-red-900/50 text-red-400 rounded border border-red-800 font-semibold">
                ⚠ Threat Detected
              </span>
            ) : layer3.status === "error" ? (
              <span className="text-xs px-3 py-1 bg-red-900/50 text-red-400 rounded border border-red-800">
                Error
              </span>
            ) : (
              <span className="text-xs px-3 py-1 bg-green-900/50 text-green-400 rounded border border-green-800">
                {layer3.status === "monitoring" ? "Monitoring Active" : "Analysis Complete"}
              </span>
            )}
          </div>
        </CardHeader>
        {layer3.status === "threat_detected" && (
          <CardContent className="pt-0 space-y-3">
            <div className="grid grid-cols-3 gap-2">
              <div className="bg-slate-800/50 rounded p-2">
                <p className="text-xs text-slate-500 mb-1">Threat Level</p>
                <p className="text-sm font-bold text-red-400">
                  {layer3.threat_level || "N/A"}
                </p>
              </div>
              <div className="bg-slate-800/50 rounded p-2">
                <p className="text-xs text-slate-500 mb-1">Confidence</p>
                <p className="text-sm font-bold text-slate-200">
                  {formatConfidence(layer3.confidence)}
                </p>
              </div>
              <div className="bg-slate-800/50 rounded p-2">
                <p className="text-xs text-slate-500 mb-1">Files Affected</p>
                <p className="text-sm font-bold text-slate-200">
                  {layer3.affected_files || "—"}
                </p>
              </div>
            </div>

            {layer3.indicators?.length > 0 && (
              <div>
                <p className="text-xs text-slate-500 mb-2">Why Detected</p>
                <div className="space-y-1">
                  {layer3.indicators.map((indicator, idx) => (
                    <div
                      key={idx}
                      className="flex items-start gap-2 text-xs text-slate-300 bg-slate-800/30 rounded p-2"
                    >
                      <span className="text-red-400 mt-0.5">•</span>
                      <span>
                        {indicator === "High file modification rate detected" && "Abnormal encryption rate exceeding threshold"}
                        {indicator === "Suspicious file extension changes" && "Matched ransomware-like file extension patterns"}
                        {indicator === "Shadow copy interference detected" && "High entropy changes in files detected"}
                        {indicator === "Known ransomware extensions found" && "Known ransomware file extensions identified"}
                        {indicator}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {layer3.recommended_action && (
              <div className="border-t border-slate-700 pt-3">
                <p className="text-xs text-slate-500 mb-2">Recommended Action</p>
                <p className="text-sm font-semibold text-orange-400 bg-orange-900/20 px-3 py-2 rounded border border-orange-800/50">
                  {layer3.recommended_action.replace(/_/g, " ")}
                </p>
              </div>
            )}

            {layer3.is_backup_safe !== undefined && (
              <div className="text-xs">
                <span
                  className={`px-2 py-1 rounded ${
                    layer3.is_backup_safe
                      ? "bg-green-900/30 text-green-400"
                      : "bg-red-900/30 text-red-400"
                  }`}
                >
                  {layer3.is_backup_safe
                    ? "✓ Backup-Safe Activity"
                    : "⚠ Not Backup-Safe"}
                </span>
              </div>
            )}
          </CardContent>
        )}
      </Card>

      {/* Metadata */}
      {result.processing_time_ms && (
        <div className="text-xs text-slate-500 text-center pt-2 border-t border-slate-800">
          <span>Processing time: {result.processing_time_ms}ms</span>
        </div>
      )}
    </div>
  );
};

export default ThreeLayerDetectionVisualization;
