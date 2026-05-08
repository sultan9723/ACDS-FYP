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

const ThreatsOverTimeChart = () => {
  const dashboardData = useDashboard() || {};
  const { threatsOverTimeData = [] } = dashboardData;

  // Ensure data is an array
  const safeData = Array.isArray(threatsOverTimeData)
    ? threatsOverTimeData
    : [];

  return (
    <div className="col-span-2 relative bg-slate-900/50 backdrop-blur-sm border border-slate-800 hover:border-emerald-500/20 rounded-xl p-4 transition-all duration-300 overflow-hidden">
      {/* Decorative accent */}
      <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-emerald-500/50 via-teal-500/30 to-transparent" />

      <h3 className="text-sm font-semibold text-emerald-400/80 mb-4 flex items-center gap-2">
        <span className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
        Threats Over Time
      </h3>
      <div className="h-[180px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={safeData}>
            <defs>
              <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#1e293b"
              vertical={false}
            />
            <XAxis
              dataKey="time"
              stroke="#475569"
              tick={{ fill: "#64748b", fontSize: 11 }}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              stroke="#475569"
              tick={{ fill: "#64748b", fontSize: 11 }}
              tickLine={false}
              axisLine={false}
              domain={[0, 14]}
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
              dataKey="value"
              stroke="#10b981"
              strokeWidth={2}
              fill="url(#colorThreats)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default ThreatsOverTimeChart;
