import React from "react";

const StatsCard = ({ title, value }) => {
  return (
    <div className="bg-slate-900/50 backdrop-blur-sm border border-slate-800 hover:border-emerald-500/30 rounded-xl p-6 text-center transition-all duration-300 group">
      <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2 group-hover:text-emerald-400/80 transition-colors">
        {title}
      </p>
      <h3 className="text-4xl font-bold bg-gradient-to-r from-slate-100 to-slate-300 bg-clip-text text-transparent group-hover:from-emerald-400 group-hover:to-emerald-200 transition-all duration-300">
        {value}
      </h3>
    </div>
  );
};

export default StatsCard;
