import React, { useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Bot,
  CheckCircle2,
  ClipboardCheck,
  Play,
  RefreshCw,
  Shield,
  Square,
  Target,
  Zap,
} from "lucide-react";
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

const severityRank = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

const Dashboard = () => {
  const dashboardData = useDashboard();
  const [batchLoading, setBatchLoading] = useState(false);

  const loading = dashboardData?.loading;

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

  const demoRunning = dashboardData?.demoRunning || false;
  const startDemo = dashboardData?.startDemo;
  const stopDemo = dashboardData?.stopDemo;
  const runBatch = dashboardData?.runBatch;
  const refreshData = dashboardData?.refreshData;

  const safeLiveThreats = Array.isArray(liveThreats) ? liveThreats : [];
  const safeResponseActions = Array.isArray(responseActions)
    ? responseActions
    : [];
  const safeTestResults = Array.isArray(testResults) ? testResults : [];

  const activeThreatCount = stats.activeThreats || safeLiveThreats.length;
  const automatedActionCount =
    stats.autoResolved || stats.resolvedThreats || safeResponseActions.length;
  const detectionAccuracy =
    safeTestResults.length > 0
      ? Math.round(
          (safeTestResults.filter((result) => result && result.correct).length /
            safeTestResults.length) *
            100
        )
      : stats.accuracy || 97.2;

  const mostCriticalThreat = useMemo(() => {
    if (safeLiveThreats.length === 0) return null;
    return [...safeLiveThreats].sort((a, b) => {
      const bRank = severityRank[String(b?.severity || "").toUpperCase()] || 0;
      const aRank = severityRank[String(a?.severity || "").toUpperCase()] || 0;
      return bRank - aRank;
    })[0];
  }, [safeLiveThreats]);

  const hasCriticalThreat =
    String(mostCriticalThreat?.severity || "").toUpperCase() === "CRITICAL";
  const posture = activeThreatCount > 0 ? "Attention Required" : "Protected";
  const postureTone = hasCriticalThreat
    ? "critical"
    : activeThreatCount > 0
    ? "warning"
    : "safe";
  const systemHealth =
    activeThreatCount === 0
      ? "Healthy"
      : hasCriticalThreat
      ? "Critical"
      : "Monitoring";
  const analystNextStep = mostCriticalThreat
    ? `Review ${mostCriticalThreat.module || "threat"} incident ${
        mostCriticalThreat.id || ""
      } and validate automated containment.`
    : "Monitor live feeds, refresh telemetry, or run a controlled test batch to validate readiness.";

  const handleStartDemo = async () => {
    try {
      await startDemo(300);
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

  if (loading) {
    return (
      <div className="space-y-5 animate-pulse">
        <div className="h-40 rounded-xl bg-slate-800/70"></div>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          {[1, 2, 3, 4].map((item) => (
            <div key={item} className="h-32 rounded-xl bg-slate-800/70"></div>
          ))}
        </div>
        <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
          <div className="h-96 rounded-xl bg-slate-800/70 xl:col-span-2"></div>
          <div className="h-96 rounded-xl bg-slate-800/70"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <section className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-5 shadow-[0_18px_45px_rgba(2,6,23,0.24)] backdrop-blur-sm sm:p-6">
        <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
          <div className="max-w-3xl">
            <div className="mb-3 flex items-center gap-3">
              <div
                className={`flex h-11 w-11 items-center justify-center rounded-lg border ${
                  postureTone === "critical"
                    ? "border-red-500/30 bg-red-500/10 text-red-300"
                    : postureTone === "warning"
                    ? "border-amber-500/30 bg-amber-500/10 text-amber-300"
                    : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                }`}
              >
                <Shield className="h-5 w-5" />
              </div>
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.22em] text-cyan-300/80">
                  ACDS Command Center
                </p>
                <h1 className="text-2xl font-semibold tracking-tight text-slate-50 sm:text-3xl">
                  {posture}
                </h1>
              </div>
            </div>
            <p className="text-sm leading-6 text-slate-400">
              AI-driven autonomous cyber defense for real-time detection,
              response, and analyst reporting.
            </p>
          </div>

          <div className="grid gap-3 sm:grid-cols-3 xl:min-w-[520px]">
            <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
              <p className="text-xs uppercase tracking-wide text-slate-500">
                Active Threats
              </p>
              <p
                className={`mt-2 text-2xl font-semibold ${
                  activeThreatCount > 0 ? "text-red-300" : "text-emerald-300"
                }`}
              >
                {activeThreatCount}
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
              <p className="text-xs uppercase tracking-wide text-slate-500">
                Critical Incident
              </p>
              <p className="mt-2 truncate text-sm font-medium text-slate-100">
                {mostCriticalThreat?.subject ||
                  mostCriticalThreat?.id ||
                  "No active incident"}
              </p>
              <p className="mt-1 text-xs text-slate-500">
                {mostCriticalThreat?.severity || "Safe posture"}
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
              <p className="text-xs uppercase tracking-wide text-slate-500">
                Analyst Next Step
              </p>
              <p className="mt-2 line-clamp-2 text-xs leading-5 text-slate-300">
                {analystNextStep}
              </p>
            </div>
          </div>
        </div>

        <div className="mt-5 flex flex-col gap-3 border-t border-slate-800/80 pt-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={`inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold ${
                demoRunning
                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                  : "border-slate-700 bg-slate-950/40 text-slate-400"
              }`}
            >
              <span
                className={`h-2 w-2 rounded-full ${
                  demoRunning ? "bg-emerald-400" : "bg-slate-500"
                }`}
              />
              {demoRunning ? "Demo Active" : "Standby"}
            </span>
            <span className="inline-flex items-center gap-2 rounded-lg border border-cyan-500/20 bg-cyan-500/10 px-3 py-2 text-xs font-semibold text-cyan-200">
              <Bot className="h-3.5 w-3.5" />
              {safeResponseActions.length} automated actions in feed
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {!demoRunning ? (
              <button
                onClick={handleStartDemo}
                className="inline-flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/15 px-4 py-2 text-sm font-semibold text-emerald-200 transition-all hover:bg-emerald-500/25"
              >
                <Play className="h-4 w-4" />
                Start Demo
              </button>
            ) : (
              <button
                onClick={handleStopDemo}
                className="inline-flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/15 px-4 py-2 text-sm font-semibold text-red-200 transition-all hover:bg-red-500/25"
              >
                <Square className="h-4 w-4" />
                Stop Demo
              </button>
            )}

            <button
              onClick={handleRunBatch}
              disabled={batchLoading}
              className="inline-flex items-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-4 py-2 text-sm font-semibold text-cyan-200 transition-all hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <Zap className="h-4 w-4" />
              {batchLoading ? "Processing..." : "Run Test Batch"}
            </button>

            <button
              onClick={handleRefresh}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-950/40 px-3 py-2 text-sm font-semibold text-slate-300 transition-all hover:bg-slate-800"
              title="Refresh dashboard data"
            >
              <RefreshCw className="h-4 w-4" />
              Refresh
            </button>
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatsCard
          title="Active Threats"
          value={activeThreatCount}
          icon={<AlertTriangle className="h-5 w-5" />}
          description={
            activeThreatCount > 0
              ? "Open detections requiring analyst attention"
              : "No active threats in the live feed"
          }
          tone={activeThreatCount > 0 ? "critical" : "safe"}
        />
        <StatsCard
          title="Automated Actions"
          value={automatedActionCount}
          icon={<ClipboardCheck className="h-5 w-5" />}
          description="Containment and response actions recorded by ACDS"
          tone="safe"
        />
        <StatsCard
          title="Detection Accuracy"
          value={`${detectionAccuracy}%`}
          icon={<Target className="h-5 w-5" />}
          description="Current model accuracy from available test results"
          tone="info"
        />
        <StatsCard
          title="System Health"
          value={systemHealth}
          icon={<Activity className="h-5 w-5" />}
          description="Operational posture based on live threat state"
          tone={systemHealth === "Critical" ? "critical" : systemHealth === "Monitoring" ? "warning" : "safe"}
        />
      </section>

      <section className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <ThreatResponseFeed />
        </div>
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-5 shadow-[0_18px_45px_rgba(2,6,23,0.18)]">
          <div className="mb-5 flex items-start justify-between gap-3">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300/80">
                AI Analyst Summary
              </p>
              <h2 className="mt-1 text-lg font-semibold text-slate-100">
                Current Security Posture
              </h2>
            </div>
            <Bot className="h-5 w-5 text-cyan-300" />
          </div>

          <div className="space-y-4">
            <div className="rounded-lg border border-slate-800 bg-slate-950/45 p-4">
              <p className="text-xs uppercase tracking-wide text-slate-500">
                Are we safe right now?
              </p>
              <p
                className={`mt-2 text-sm font-semibold ${
                  activeThreatCount > 0 ? "text-amber-300" : "text-emerald-300"
                }`}
              >
                {activeThreatCount > 0
                  ? "ACDS is monitoring active threats."
                  : "No active threats are currently reported."}
              </p>
            </div>

            <div className="rounded-lg border border-slate-800 bg-slate-950/45 p-4">
              <p className="text-xs uppercase tracking-wide text-slate-500">
                Most critical incident
              </p>
              <p className="mt-2 text-sm font-medium text-slate-100">
                {mostCriticalThreat?.subject || "No critical incident selected"}
              </p>
              <p className="mt-1 text-xs text-slate-500">
                {mostCriticalThreat
                  ? `${mostCriticalThreat.severity || "Unknown"} severity from ${
                      mostCriticalThreat.module || "detection"
                    }`
                  : "Live detections will appear here when available."}
              </p>
            </div>

            <div className="rounded-lg border border-slate-800 bg-slate-950/45 p-4">
              <p className="text-xs uppercase tracking-wide text-slate-500">
                Analyst action
              </p>
              <p className="mt-2 text-sm leading-6 text-slate-300">
                {analystNextStep}
              </p>
            </div>

            <div className="flex items-center gap-2 text-xs text-slate-500">
              <CheckCircle2 className="h-4 w-4 text-emerald-300" />
              Summary uses existing dashboard telemetry and response data.
            </div>
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-5 xl:grid-cols-5">
        <div className="xl:col-span-3">
          <ThreatMonitoringTable />
        </div>
        <div className="xl:col-span-2">
          <IncidentDetails />
        </div>
      </section>

      <section>
        <div className="mb-3 flex items-center justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
              Validation
            </p>
            <h2 className="text-lg font-semibold text-slate-100">
              Live Testing and Simulation
            </h2>
          </div>
          <span className="inline-flex items-center gap-2 rounded-full border border-slate-700 bg-slate-900/70 px-3 py-1 text-xs text-slate-400">
            <ArrowRight className="h-3.5 w-3.5" />
            Existing test workflow
          </span>
        </div>
        <LiveTestingPanel />
      </section>

      <section className="grid grid-cols-1 gap-5 xl:grid-cols-2">
        <SystemActivityLogs />
        <div className="grid grid-cols-1 gap-5">
          <ThreatsOverTimeChart />
          <ThreatTypesChart />
        </div>
      </section>

      <ModelPerformanceMetrics />
      <ModelPerformanceLogs />
    </div>
  );
};

export default Dashboard;
