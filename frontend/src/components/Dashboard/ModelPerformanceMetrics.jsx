import React from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { useDashboard } from "../../context/DashboardContext";

const ModelPerformanceMetrics = () => {
  const dashboardData = useDashboard() || {};
  const {
    accuracyOverTimeData = [],
    confusionMatrixData = { tp: 0, fp: 0, fn: 0, tn: 0 },
  } = dashboardData;

  // Ensure data is safe
  const safeAccuracyData = Array.isArray(accuracyOverTimeData)
    ? accuracyOverTimeData
    : [];
  const safeConfusionData = confusionMatrixData || {
    tp: 0,
    fp: 0,
    fn: 0,
    tn: 0,
  };

  return (
    <div>
      <h2 className="text-sm font-semibold text-emerald-400/80 uppercase tracking-wider mb-4">
        Model Performance
      </h2>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Accuracy Over Time */}
        <div className="bg-slate-900/50 backdrop-blur-sm border border-slate-800 rounded-xl p-4">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">
            Accuracy Over Time
          </h3>
          <div className="h-[160px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={safeAccuracyData}>
                <defs>
                  <linearGradient
                    id="colorAccuracy"
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="#1e293b"
                  vertical={false}
                />
                <XAxis dataKey="time" hide />
                <YAxis
                  domain={[60, 100]}
                  stroke="#475569"
                  tick={{ fill: "#64748b", fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    borderColor: "#10b981",
                    color: "#f1f5f9",
                    fontSize: 12,
                    borderRadius: 8,
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="accuracy"
                  stroke="#10b981"
                  strokeWidth={2}
                  fill="url(#colorAccuracy)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Confusion Matrix */}
        <div className="bg-slate-900/50 backdrop-blur-sm border border-slate-800 rounded-xl p-4">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">
            Confusion Matrix
          </h3>
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-emerald-500/10 border border-emerald-500/20 p-4 rounded-lg text-center">
              <p className="text-emerald-400/80 text-xs uppercase tracking-wider mb-1">
                TP
              </p>
              <p className="text-2xl font-bold text-emerald-400">
                {safeConfusionData.tp || 0}
              </p>
            </div>
            <div className="bg-red-500/10 border border-red-500/20 p-4 rounded-lg text-center">
              <p className="text-red-400/80 text-xs uppercase tracking-wider mb-1">
                FP
              </p>
              <p className="text-2xl font-bold text-red-400">
                {safeConfusionData.fp || 0}
              </p>
            </div>
            <div className="bg-orange-500/10 border border-orange-500/20 p-4 rounded-lg text-center">
              <p className="text-orange-400/80 text-xs uppercase tracking-wider mb-1">
                FN
              </p>
              <p className="text-2xl font-bold text-orange-400">
                {safeConfusionData.fn || 0}
              </p>
            </div>
            <div className="bg-emerald-500/10 border border-emerald-500/20 p-4 rounded-lg text-center">
              <p className="text-emerald-400/80 text-xs uppercase tracking-wider mb-1">
                TN
              </p>
              <p className="text-2xl font-bold text-emerald-400">
                {safeConfusionData.tn || 0}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ModelPerformanceMetrics;
