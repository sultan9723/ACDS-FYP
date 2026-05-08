import React from "react";

const StatsCard = ({ title, value }) => {
  return (
    <div className="relative bg-slate-900/50 backdrop-blur-sm border border-slate-800 hover:border-emerald-500/30 rounded-xl p-6 text-center transition-all duration-300 group overflow-hidden">
      {/* Subtle glow effect on hover */}
      <div className="absolute inset-0 bg-gradient-to-br from-emerald-500/0 to-emerald-500/0 group-hover:from-emerald-500/5 group-hover:to-transparent transition-all duration-500" />

      {/* Top accent line */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-0 h-0.5 bg-gradient-to-r from-emerald-500 to-teal-500 group-hover:w-full transition-all duration-300" />

      <p className="relative text-xs font-medium text-slate-500 uppercase tracking-wider mb-2 group-hover:text-emerald-400/80 transition-colors">
        {title}
      </p>
      <h3 className="relative text-4xl font-bold bg-gradient-to-r from-slate-100 to-slate-300 bg-clip-text text-transparent group-hover:from-emerald-400 group-hover:to-emerald-200 transition-all duration-300">
        {value}
      </h3>
    </div>
  );
};

export default StatsCard;
