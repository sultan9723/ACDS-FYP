import React, { useState } from "react";
import { useDashboard } from "../../context/DashboardContext";
import {
  PlayIcon,
  ArrowPathIcon,
  ShieldExclamationIcon,
  CheckCircleIcon,
  XCircleIcon,
  BoltIcon,
  DocumentTextIcon,
} from "@heroicons/react/24/outline";

const LiveTestingPanel = () => {
  const dashboardData = useDashboard() || {};
  const {
    testRunning = false,
    runLiveTest = async () => ({ success: false }),
    testResults = [],
    liveThreats = [],
    responseActions = [],
    currentTestSession = null,
  } = dashboardData;

  const [testCount, setTestCount] = useState(10);
  const [lastTestSummary, setLastTestSummary] = useState(null);
  const [error, setError] = useState(null);

  const handleRunTest = async () => {
    setError(null);
    try {
      const result = await runLiveTest(testCount);
      if (result && result.success) {
        setLastTestSummary(result.summary);
      }
    } catch (err) {
      console.error("Test failed:", err);
      setError("Test failed. Please try again.");
    }
  };

  // Calculate stats from results - with safe access
  const safeResults = Array.isArray(testResults) ? testResults : [];
  const correctPredictions = safeResults.filter((r) => r && r.correct).length;
  const accuracy =
    safeResults.length > 0
      ? Math.round((correctPredictions / safeResults.length) * 100)
      : 0;

  return (
    <div className="relative bg-slate-900/70 backdrop-blur-sm border border-slate-800/80 hover:border-emerald-500/30 rounded-xl p-5 sm:p-6 transition-all duration-300 group overflow-hidden">
      {/* Decorative corner accent */}
      <div className="absolute top-0 right-0 w-24 h-24 bg-gradient-to-bl from-emerald-500/10 to-transparent rounded-bl-full opacity-0 group-hover:opacity-100 transition-opacity duration-500" />

      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between mb-6 relative">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-gradient-to-br from-emerald-500/30 to-emerald-600/20 rounded-lg border border-emerald-500/20">
            <BoltIcon className="h-6 w-6 text-emerald-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-slate-100">
              Live Threat Detection Testing
            </h2>
            <p className="text-sm text-slate-400">
              Test system with real phishing samples from dataset
            </p>
          </div>
        </div>
        {currentTestSession && (
          <span className="text-xs text-slate-500 bg-slate-700/50 px-2 py-1 rounded">
            Session: {currentTestSession}
          </span>
        )}
      </div>

      {/* Controls */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:gap-4 mb-6">
        <div className="flex items-center gap-2">
          <label className="text-sm text-slate-400">Samples:</label>
          <select
            value={testCount}
            onChange={(e) => setTestCount(Number(e.target.value))}
            disabled={testRunning}
            className="bg-slate-950/60 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500/40"
          >
            <option value={5}>5 emails</option>
            <option value={10}>10 emails</option>
            <option value={15}>15 emails</option>
            <option value={20}>20 emails</option>
          </select>
        </div>

        <button
          onClick={handleRunTest}
          disabled={testRunning}
          className={`flex items-center justify-center gap-2 px-4 py-2 rounded-lg font-medium transition-all ${
            testRunning
              ? "bg-slate-700 text-slate-400 cursor-not-allowed"
              : "border border-emerald-500/30 bg-emerald-500/20 text-emerald-100 hover:bg-emerald-500/30"
          }`}
        >
          {testRunning ? (
            <>
              <ArrowPathIcon className="h-5 w-5 animate-spin" />
              <span>Running Detection...</span>
            </>
          ) : (
            <>
              <PlayIcon className="h-5 w-5" />
              <span>Run Live Test</span>
            </>
          )}
        </button>
      </div>

      {/* Stats Cards */}
      {safeResults.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div className="bg-gradient-to-br from-slate-800/60 to-slate-800/30 rounded-lg p-4 border border-slate-700/50 hover:border-slate-600/70 transition-colors">
            <div className="flex items-center space-x-2 text-slate-400 mb-1">
              <DocumentTextIcon className="h-4 w-4" />
              <span className="text-xs uppercase tracking-wider">
                Processed
              </span>
            </div>
            <p className="text-2xl font-bold bg-gradient-to-r from-slate-100 to-slate-300 bg-clip-text text-transparent">
              {safeResults.length}
            </p>
          </div>

          <div className="bg-gradient-to-br from-red-900/20 to-slate-800/30 rounded-lg p-4 border border-red-500/20 hover:border-red-500/40 transition-colors">
            <div className="flex items-center space-x-2 text-red-400 mb-1">
              <ShieldExclamationIcon className="h-4 w-4" />
              <span className="text-xs uppercase tracking-wider">
                Threats Found
              </span>
            </div>
            <p className="text-2xl font-bold text-red-400">
              {(Array.isArray(liveThreats) ? liveThreats : []).length}
            </p>
          </div>

          <div className="bg-gradient-to-br from-green-900/20 to-slate-800/30 rounded-lg p-4 border border-green-500/20 hover:border-green-500/40 transition-colors">
            <div className="flex items-center space-x-2 text-green-400 mb-1">
              <CheckCircleIcon className="h-4 w-4" />
              <span className="text-xs uppercase tracking-wider">
                Auto-Resolved
              </span>
            </div>
            <p className="text-2xl font-bold text-green-400">
              {(Array.isArray(responseActions) ? responseActions : []).length}
            </p>
          </div>

          <div className="bg-gradient-to-br from-emerald-900/20 to-slate-800/30 rounded-lg p-4 border border-emerald-500/20 hover:border-emerald-500/40 transition-colors">
            <div className="flex items-center space-x-2 text-emerald-400 mb-1">
              <CheckCircleIcon className="h-4 w-4" />
              <span className="text-xs uppercase tracking-wider">Accuracy</span>
            </div>
            <p className="text-2xl font-bold text-emerald-400">{accuracy}%</p>
          </div>
        </div>
      )}

      {/* Realtime Results */}
      {safeResults.length > 0 && (
        <div className="space-y-3 max-h-[300px] overflow-y-auto custom-scrollbar">
          <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider sticky top-0 bg-slate-800/90 py-2">
            Detection Results
          </h3>
          {safeResults.slice(0, 10).map((result, idx) => (
            <div
              key={idx}
              className={`flex items-center justify-between p-3 rounded-lg border ${
                result && result.is_phishing
                  ? "bg-red-500/10 border-red-500/30"
                  : "bg-green-500/10 border-green-500/30"
              }`}
            >
              <div className="flex items-center space-x-3">
                {result && result.is_phishing ? (
                  <ShieldExclamationIcon className="h-5 w-5 text-red-400" />
                ) : (
                  <CheckCircleIcon className="h-5 w-5 text-green-400" />
                )}
                <div>
                  <p className="text-sm font-medium text-slate-100 truncate max-w-[200px]">
                    {(result && result.subject) || `Email #${idx + 1}`}
                  </p>
                  <p className="text-xs text-slate-400">
                    {result.sender || "Unknown sender"}
                  </p>
                </div>
              </div>

              <div className="flex items-center space-x-4">
                <div className="text-right">
                  <p
                    className={`text-sm font-semibold ${
                      result.is_phishing ? "text-red-400" : "text-green-400"
                    }`}
                  >
                    {result.is_phishing ? "PHISHING" : "SAFE"}
                  </p>
                  <p className="text-xs text-slate-500">
                    {Math.round(((result && result.confidence) || 0) * 100)}%
                    confidence
                  </p>
                </div>

                {/* Prediction correctness */}
                <div
                  className={`p-1 rounded ${
                    result && result.correct
                      ? "bg-green-500/20"
                      : "bg-red-500/20"
                  }`}
                >
                  {result && result.correct ? (
                    <CheckCircleIcon className="h-4 w-4 text-green-400" />
                  ) : (
                    <XCircleIcon className="h-4 w-4 text-red-400" />
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Empty State */}
      {safeResults.length === 0 && !testRunning && (
        <div className="text-center py-8 text-slate-500">
          <BoltIcon className="h-12 w-12 mx-auto mb-3 opacity-50 text-emerald-500/50" />
          <p>Click "Run Live Test" to start automated threat detection</p>
          <p className="text-sm mt-1">
            Tests use real phishing samples from the dataset
          </p>
        </div>
      )}
    </div>
  );
};

export default LiveTestingPanel;
