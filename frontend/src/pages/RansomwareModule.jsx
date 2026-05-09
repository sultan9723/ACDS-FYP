import React, { useState } from "react";
import RansomwareList from "../components/Ransomware/RansomwareList";
import RansomwareThreatDetails from "../components/Ransomware/RansomwareThreatDetails";
import ThreeLayerDetectionScanner from "../components/Ransomware/ThreeLayerDetectionScanner";

const RansomwareModule = () => {
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [activeTab, setActiveTab] = useState("scanner");

  const handleThreeLayerDetection = (result) => {
    setSelectedThreat(result);
    setActiveTab("history");
  };

  return (
    <div className="space-y-6 h-[calc(100vh-100px)]">
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

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-full pb-6">
        <div className="lg:col-span-2 h-full overflow-hidden flex flex-col space-y-4">
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
            <div className="flex-1 overflow-hidden">
              <ThreeLayerDetectionScanner
                onDetectionResult={handleThreeLayerDetection}
              />
            </div>
          )}

          {activeTab === "history" && (
            <div className="flex-1 overflow-hidden">
              <RansomwareList onSelectThreat={setSelectedThreat} />
            </div>
          )}
        </div>
        <div className="h-full overflow-hidden">
          <RansomwareThreatDetails threat={selectedThreat} />
        </div>
      </div>
    </div>
  );
};

export default RansomwareModule;
