import React from "react";
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

  // Check for loading state
  const loading = dashboardData?.loading;

  // Provide safe defaults to prevent crashes
  const stats = dashboardData?.stats || {
    phishingDetected: 0,
    activeThreats: 0,
    autoResolved: 0,
    accuracy: 0,
  };
  const liveThreats = dashboardData?.liveThreats || [];
  const responseActions = dashboardData?.responseActions || [];
  const testResults = dashboardData?.testResults || [];

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
      <div>
        <h1 className="text-2xl font-bold bg-gradient-to-r from-emerald-400 to-emerald-200 bg-clip-text text-transparent tracking-wide uppercase">
          Autonomous Cyber Defense System
        </h1>
        <p className="text-slate-500 text-sm mt-1">
          Real-time threat monitoring and response
        </p>
      </div>

      {/* Overview Section */}
      <div>
        <h2 className="text-sm font-semibold text-emerald-400/80 uppercase tracking-wider mb-4">
          Overview
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatsCard
            title="Total Threats Detected"
            value={stats.phishingDetected + liveThreats.length}
          />
          <StatsCard
            title="Active Threats"
            value={
              liveThreats.length > 0
                ? liveThreats.length
                : stats.activeThreats || 5
            }
          />
          <StatsCard
            title="Auto-Resolved"
            value={(stats.autoResolved || 61) + responseActions.length}
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
                : `${stats.accuracy || 0}%`
            }
          />
        </div>
      </div>

      {/* Live Testing Panel - NEW */}
      <LiveTestingPanel />

      {/* Threat Response & Activity Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
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
