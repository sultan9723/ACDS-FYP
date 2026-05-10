import React, { useState } from "react";
import RansomwareList from "../components/Ransomware/RansomwareList";
import RansomwareThreatDetails from "../components/Ransomware/RansomwareThreatDetails";
import ThreeLayerDetectionScanner from "../components/Ransomware/ThreeLayerDetectionScanner";

const RansomwareModule = () => {
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [activeTab, setActiveTab] = useState("scanner");
  const [recentScans, setRecentScans] = useState([]);

  const normalizeScanHistoryItem = (result) => {
    const detection = result.pipeline_results?.detection || {};
    const layer3 = result.layers?.layer3_mass_encryption || {};
    const isRansomware =
      detection.is_ransomware ||
      result.overall_verdict === "RANSOMWARE_DETECTED" ||
      layer3.status === "threat_detected";

    return {
      id:
        result.incident_id ||
        result.threat_id ||
        result.scan_id ||
        result.sample?.sha256 ||
        `${Date.now()}`,
      raw_result: result,
      command_preview:
        result.command ||
        result.pipeline_results?.detection?.command ||
        result.filename ||
        result.sample?.filename ||
        result.triggered_layers?.join(", ") ||
        "Layered ransomware analysis",
      source_host: result.source_host || "TEST-WORKSTATION",
      prediction: isRansomware ? "Ransomware" : "Safe",
      confidence:
        result.detection_confidence ??
        detection.confidence ??
        layer3.confidence ??
        0,
      severity: result.severity || layer3.threat_level || "LOW",
      behavior_categories:
        result.pipeline_results?.explainability?.behavior_categories ||
        result.triggered_layers ||
        layer3.indicators ||
        [],
      scanned_at: result.timestamp || new Date().toISOString(),
    };
  };

  const handleThreeLayerDetection = (result) => {
    setSelectedThreat(result);
    setRecentScans((prev) => [normalizeScanHistoryItem(result), ...prev].slice(0, 50));
    setActiveTab("history");
  };

  return (
    <div className="space-y-6 min-h-[calc(100vh-100px)] pb-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-slate-100">
          Ransomware Detection System
          </h1>
          <div className="flex gap-2">
            <span className="px-3 py-1 bg-green-900/50 text-green-400 rounded-full text-xs border border-green-900">
            3-Layer Detection Active
            </span>
          <span className="px-3 py-1 bg-blue-900/50 text-blue-400 rounded-full text-xs border border-blue-900">
            ML + Rules
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        <div className="lg:col-span-2 min-w-0 flex flex-col space-y-4">
          <div className="flex gap-2">
            <button
              onClick={() => setActiveTab("scanner")}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                activeTab === "scanner"
                  ? "bg-emerald-600 text-white"
                  : "bg-slate-800 text-slate-400 hover:text-slate-200"
              }`}
            >
              3-Layer Scanner
            </button>
            <button
              onClick={() => setActiveTab("history")}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                activeTab === "history"
                  ? "bg-emerald-600 text-white"
                  : "bg-slate-800 text-slate-400 hover:text-slate-200"
              }`}
            >
              Scan History
            </button>
          </div>

          {activeTab === "scanner" && (
            <div className="min-w-0">
              <ThreeLayerDetectionScanner
                onDetectionResult={handleThreeLayerDetection}
              />
            </div>
          )}

          {activeTab === "history" && (
            <div className="min-w-0">
              <RansomwareList
                onSelectThreat={setSelectedThreat}
                recentScans={recentScans}
                onScanComplete={handleThreeLayerDetection}
              />
            </div>
          )}
        </div>
        <div className="min-w-0 lg:sticky lg:top-4 lg:max-h-[calc(100vh-140px)] lg:overflow-y-auto">
          <RansomwareThreatDetails threat={selectedThreat} />
        </div>
      </div>
    </div>
  );
};

export default RansomwareModule;
