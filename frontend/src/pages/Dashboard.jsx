import React, { useState } from "react";
import StatsCard from "../components/Dashboard/StatsCard";
import ThreatsOverTimeChart from "../components/Dashboard/ThreatsOverTimeChart";
import ThreatTypesChart from "../components/Dashboard/ThreatTypesChart";
import ThreatMonitoringTable from "../components/Dashboard/ThreatMonitoringTable";
import IncidentDetails from "../components/Dashboard/IncidentDetails";
import ModelPerformanceMetrics from "../components/Dashboard/ModelPerformanceMetrics";
import ModelPerformanceLogs from "../components/Dashboard/ModelPerformanceLogs";
import LiveTestingPanel from "../components/Dashboard/LiveTestingPanel";
import ThreatResponseFeed from "../components/Dashboard/ThreatResponseFeed";
import SystemActivityLogs from "../components/Dashboard/SystemActivityLogs";
import { useDashboard } from "../context/DashboardContext";

const Dashboard = () => {
  const dashboardData = useDashboard();
  const [batchLoading, setBatchLoading] = useState(false);

  // Check for loading state
  const loading = dashboardData?.loading;

  // Provide safe defaults to prevent crashes
  const stats = dashboardData?.stats || {
    phishingDetected: 0,
    activeThreats: 0,
    autoResolved: 0,
    accuracy: 0,
    totalThreats: 0,
    resolvedThreats: 0,
  };
  const liveThreats = dashboardData?.liveThreats || [];
  const responseActions = dashboardData?.responseActions || [];
  const testResults = dashboardData?.testResults || [];

  // Demo mode
  const demoRunning = dashboardData?.demoRunning || false;
  const startDemo = dashboardData?.startDemo;
  const stopDemo = dashboardData?.stopDemo;
  const runBatch = dashboardData?.runBatch;
  const refreshData = dashboardData?.refreshData;

  const handleStartDemo = async () => {
    try {
      await startDemo(300); // 5 minutes = 300 seconds
    } catch (error) {
      console.error("Failed to start demo:", error);
    }
  };

  const handleStopDemo = async () => {
    try {
      await stopDemo();
    } catch (error) {
      console.error("Failed to stop demo:", error);
    }
  };

  const handleRunBatch = async () => {
    setBatchLoading(true);
    try {
      await runBatch(5);
    } catch (error) {
      console.error("Failed to run batch:", error);
    } finally {
      setBatchLoading(false);
    }
  };

  const handleRefresh = async () => {
    try {
      await refreshData();
    } catch (error) {
      console.error("Failed to refresh:", error);
    }
  };

  // Show loading skeleton if still loading
  if (loading) {
    return (
      <div className="space-y-8 animate-pulse">
        <div className="h-8 bg-slate-700 rounded w-1/3"></div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-24 bg-slate-700 rounded-xl"></div>
          ))}
        </div>
        <div className="h-64 bg-slate-700 rounded-xl"></div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="h-80 bg-slate-700 rounded-xl"></div>
          <div className="h-80 bg-slate-700 rounded-xl"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Header with Status Banner */}
      <div className="bg-gradient-to-r from-slate-800/80 to-slate-900/80 rounded-2xl p-6 border border-slate-700/50 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <div className="w-10 h-10 bg-emerald-500/20 rounded-xl flex items-center justify-center">
                <span className="text-2xl">🛡️</span>
              </div>
              <h1 className="text-3xl font-bold bg-gradient-to-r from-emerald-400 to-cyan-400 bg-clip-text text-transparent tracking-tight">
                Autonomous Cyber Defense System
              </h1>
            </div>
            <p className="text-slate-400 text-sm ml-13">
              Real-time threat detection, analysis, and automated response
            </p>
          </div>

          {/* Demo Mode Controls */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
            <div className="flex items-center gap-3 bg-slate-900/60 rounded-xl px-4 py-2.5 border border-slate-700/50">
              <div className="flex items-center gap-2">
                <span
                  className={`w-2.5 h-2.5 rounded-full ${
                    demoRunning ? "bg-emerald-500 animate-pulse shadow-lg shadow-emerald-500/50" : "bg-slate-500"
                  }`}
                />
                <span className="text-xs font-medium text-slate-300">
                  System Status:
                </span>
                <span
                  className={`text-xs font-bold ${
                    demoRunning ? "text-emerald-400" : "text-slate-400"
                  }`}
                >
                  {demoRunning ? "DEMO ACTIVE" : "STANDBY"}
                </span>
              </div>

            </div>

            <div className="flex items-center gap-2">
              {!demoRunning ? (
                <button
                  onClick={handleStartDemo}
                  className="px-4 py-2 bg-emerald-500/20 text-emerald-400 rounded-lg text-sm font-semibold hover:bg-emerald-500/30 transition-all border border-emerald-500/30 hover:border-emerald-500/50 shadow-lg hover:shadow-emerald-500/20"
                >
                  ▶ Start Demo
                </button>
              ) : (
                <button
                  onClick={handleStopDemo}
                  className="px-4 py-2 bg-red-500/20 text-red-400 rounded-lg text-sm font-semibold hover:bg-red-500/30 transition-all border border-red-500/30 hover:border-red-500/50 shadow-lg hover:shadow-red-500/20"
                >
                  ■ Stop Demo
                </button>
              )}

              <button
                onClick={handleRunBatch}
                disabled={batchLoading}
                className="px-4 py-2 bg-blue-500/20 text-blue-400 rounded-lg text-sm font-semibold hover:bg-blue-500/30 transition-all border border-blue-500/30 hover:border-blue-500/50 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg hover:shadow-blue-500/20"
              >
                {batchLoading ? "⏳ Processing..." : "🔄 Run Test Batch"}
              </button>

              <button
                onClick={handleRefresh}
                className="px-4 py-2 bg-slate-600/20 text-slate-300 rounded-lg text-sm font-semibold hover:bg-slate-600/30 transition-all border border-slate-600/30 hover:border-slate-600/50 shadow-lg"
                title="Refresh dashboard data"
              >
                ⟳
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Overview Section */}
      <div className="animate-fade-in-delay-1">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-bold text-slate-200 uppercase tracking-wide flex items-center gap-3">
            <div className="w-1 h-6 bg-gradient-to-b from-emerald-500 to-cyan-500 rounded-full" />
            System Overview
          </h2>
          <span className="text-xs text-slate-500 bg-slate-800/50 px-3 py-1 rounded-full border border-slate-700/50">
            Live Metrics
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatsCard
            title="Total Threats Detected"
            value={
              stats.totalThreats || stats.phishingDetected + liveThreats.length
            }
          />
          <StatsCard
            title="Active Threats"
            value={stats.activeThreats || liveThreats.length}
          />
          <StatsCard
            title="Resolved Threats"
            value={
              stats.resolvedThreats ||
              stats.autoResolved + responseActions.length
            }
          />
          <StatsCard
            title="Detection Accuracy"
            value={
              testResults.length > 0
                ? `${Math.round(
                    (testResults.filter((r) => r && r.correct).length /
                      testResults.length) *
                      100
                  )}%`
                : `${stats.accuracy || 97.2}%`
            }
          />
        </div>
      </div>

      {/* Live Testing Panel */}
      <div className="animate-fade-in-delay-2">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-bold text-slate-200 uppercase tracking-wide flex items-center gap-3">
            <div className="w-1 h-6 bg-gradient-to-b from-blue-500 to-purple-500 rounded-full" />
            Live Testing & Simulation
          </h2>
          <span className="text-xs text-slate-500 bg-slate-800/50 px-3 py-1 rounded-full border border-slate-700/50">
            Automated Testing
          </span>
        </div>
        <LiveTestingPanel />
      </div>

      {/* Threat Response & Activity Section */}
      <div className="animate-fade-in-delay-3">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-bold text-slate-200 uppercase tracking-wide flex items-center gap-3">
            <div className="w-1 h-6 bg-gradient-to-b from-red-500 to-orange-500 rounded-full" />
            Real-Time Threat Intelligence
          </h2>
          <span className="text-xs text-slate-500 bg-slate-800/50 px-3 py-1 rounded-full border border-slate-700/50">
            Active Monitoring
          </span>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <ThreatResponseFeed />
          <SystemActivityLogs />
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <ThreatsOverTimeChart />
        <ThreatTypesChart />
      </div>

      {/* Threat Monitoring & Incident Details */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        <div className="lg:col-span-3">
          <ThreatMonitoringTable />
        </div>
        <div className="lg:col-span-2">
          <IncidentDetails />
        </div>
      </div>

      {/* Model Performance Section */}
      <ModelPerformanceMetrics />

      {/* Model Performance Logs */}
      <ModelPerformanceLogs />
    </div>
  );
};

export default Dashboard;
