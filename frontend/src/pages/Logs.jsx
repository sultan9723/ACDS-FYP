import React from "react";
import ModelPerformanceLogs from "../components/Dashboard/ModelPerformanceLogs";

const Logs = () => {
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-slate-100">System Logs</h1>
      <ModelPerformanceLogs />
    </div>
  );
};

export default Logs;
