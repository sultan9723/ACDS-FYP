import React from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import { useDashboard } from "../../context/DashboardContext";

const ThreatTypesChart = () => {
  const dashboardData = useDashboard() || {};
  const { threatTypesData = [] } = dashboardData;
  const colors = ["#10b981", "#34d399", "#6ee7b7"];

  // Ensure data is an array
  const safeData = Array.isArray(threatTypesData) ? threatTypesData : [];

  // Take top 3 for the legend display
  const topThreats = safeData.slice(0, 3);

  return (
    <div className="relative bg-slate-900/70 backdrop-blur-sm border border-slate-800/80 hover:border-emerald-500/20 rounded-xl p-4 transition-all duration-300 overflow-hidden">
      {/* Decorative accent */}
      <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-teal-500/50 via-emerald-500/30 to-transparent" />

      <h3 className="text-sm font-semibold text-emerald-400/80 mb-4">
        Top Threat Types
      </h3>
      <div className="flex flex-col gap-4 sm:flex-row sm:gap-6">
        {/* Legend */}
        <div className="flex flex-wrap gap-3 sm:flex-col sm:justify-center sm:space-y-3 sm:gap-0">
          {topThreats.map((item, index) => (
            <div key={item?.name || index} className="flex items-center gap-2">
              <div
                className="w-3 h-3 rounded-sm"
                style={{ backgroundColor: colors[index] }}
              />
              <span className="text-xs text-slate-400">
                {item?.name || "Unknown"}
              </span>
            </div>
          ))}
        </div>
        {/* Chart */}
        <div className="h-[150px] flex-1">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={topThreats}>
              <XAxis dataKey="name" hide />
              <YAxis hide />
              <Tooltip
                cursor={{ fill: "#1e293b" }}
                contentStyle={{
                  backgroundColor: "#0f172a",
                  borderColor: "#10b981",
                  color: "#f1f5f9",
                  fontSize: 12,
                  borderRadius: 8,
                }}
              />
              <Bar dataKey="value" radius={[4, 4, 0, 0]} barSize={40}>
                {topThreats.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={colors[index % colors.length]}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};

export default ThreatTypesChart;
