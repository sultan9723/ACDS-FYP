import React from "react";
import ModelPerformanceLogs from "../components/Dashboard/ModelPerformanceLogs";

const Logs = () => {
  return (
    <div className="space-y-5 pb-6">
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/70 p-5 shadow-[0_18px_45px_rgba(2,6,23,0.18)]">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300/80">
          Audit Workspace
        </p>
        <h1 className="mt-1 text-2xl font-semibold tracking-tight text-slate-100">
          System Logs
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
          Review historical model decisions, detection events, response
          actions, confidence values, and model versions in an audit-grade SOC
          timeline.
        </p>
      </div>
      <ModelPerformanceLogs />
    </div>
  );
};

export default Logs;
