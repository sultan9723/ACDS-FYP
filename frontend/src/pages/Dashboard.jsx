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
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold bg-gradient-to-r from-emerald-400 to-emerald-200 bg-clip-text text-transparent tracking-wide uppercase">
            Autonomous Cyber Defense System
          </h1>
          <p className="text-slate-500 text-sm mt-1">
            Real-time threat monitoring and response
          </p>
        </div>

        {/* Demo Mode Controls */}
        <div className="flex items-center gap-3 bg-slate-800/50 rounded-xl px-4 py-3 border border-slate-700/50">
          <div className="flex items-center gap-2">
            <span
              className={`w-2 h-2 rounded-full ${
                demoRunning ? "bg-emerald-500 animate-pulse" : "bg-slate-500"
              }`}
            />
            <span className="text-sm text-slate-400">
              Demo Mode:{" "}
              <span
                className={demoRunning ? "text-emerald-400" : "text-slate-500"}
              >
                {demoRunning ? "Active" : "Inactive"}
              </span>
            </span>
          </div>

          <div className="h-6 w-px bg-slate-700" />

          {!demoRunning ? (
            <button
              onClick={handleStartDemo}
              className="px-3 py-1.5 bg-emerald-500/20 text-emerald-400 rounded-lg text-sm font-medium hover:bg-emerald-500/30 transition-colors"
            >
              Start Demo
            </button>
          ) : (
            <button
              onClick={handleStopDemo}
              className="px-3 py-1.5 bg-red-500/20 text-red-400 rounded-lg text-sm font-medium hover:bg-red-500/30 transition-colors"
            >
              Stop Demo
            </button>
          )}

          <button
            onClick={handleRunBatch}
            disabled={batchLoading}
            className="px-3 py-1.5 bg-blue-500/20 text-blue-400 rounded-lg text-sm font-medium hover:bg-blue-500/30 transition-colors disabled:opacity-50"
          >
            {batchLoading ? "Processing..." : "Run Batch"}
          </button>

          <button
            onClick={handleRefresh}
            className="px-3 py-1.5 bg-slate-500/20 text-slate-400 rounded-lg text-sm font-medium hover:bg-slate-500/30 transition-colors"
          >
            ⟳ Refresh
          </button>
        </div>
      </div>

      {/* Overview Section */}
      <div className="animate-fade-in-delay-1">
        <h2 className="text-sm font-semibold text-emerald-400/80 uppercase tracking-wider mb-4 flex items-center gap-2">
          <span className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
          Overview
        </h2>
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

      {/* Live Testing Panel - NEW */}
      <div className="animate-fade-in-delay-2">
        <LiveTestingPanel />
      </div>

      {/* Threat Response & Activity Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 animate-fade-in-delay-3">
        <ThreatResponseFeed />
        <SystemActivityLogs />
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
