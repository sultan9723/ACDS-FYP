import React from "react";

const StatsCard = ({ title, value, icon, description, trend }) => {
  // Icon mapping for different card types
  const getIcon = () => {
    if (icon) return icon;
    
    if (title.toLowerCase().includes("total")) return "🎯";
    if (title.toLowerCase().includes("active")) return "⚠️";
    if (title.toLowerCase().includes("resolved")) return "✅";
    if (title.toLowerCase().includes("accuracy")) return "📊";
    return "📈";
  };

  // Color scheme based on title
  const getColorScheme = () => {
    if (title.toLowerCase().includes("active")) {
      return {
        border: "hover:border-orange-500/30",
        glow: "group-hover:from-orange-500/5",
        accent: "from-orange-500 to-red-500",
        text: "group-hover:text-orange-400/80",
        value: "group-hover:from-orange-400 group-hover:to-red-300"
      };
    }
    if (title.toLowerCase().includes("resolved")) {
      return {
        border: "hover:border-green-500/30",
        glow: "group-hover:from-green-500/5",
        accent: "from-green-500 to-emerald-500",
        text: "group-hover:text-green-400/80",
        value: "group-hover:from-green-400 group-hover:to-emerald-300"
      };
    }
    if (title.toLowerCase().includes("accuracy")) {
      return {
        border: "hover:border-blue-500/30",
        glow: "group-hover:from-blue-500/5",
        accent: "from-blue-500 to-cyan-500",
        text: "group-hover:text-blue-400/80",
        value: "group-hover:from-blue-400 group-hover:to-cyan-300"
      };
    }
    return {
      border: "hover:border-emerald-500/30",
      glow: "group-hover:from-emerald-500/5",
      accent: "from-emerald-500 to-teal-500",
      text: "group-hover:text-emerald-400/80",
      value: "group-hover:from-emerald-400 group-hover:to-emerald-200"
    };
  };

  const colors = getColorScheme();

  return (
    <div 
      className={`relative bg-gradient-to-br from-slate-900/80 to-slate-800/50 backdrop-blur-sm border border-slate-700/50 ${colors.border} rounded-xl p-6 transition-all duration-300 group overflow-hidden shadow-lg hover:shadow-xl`}
      title={description || title}
    >
      {/* Subtle glow effect on hover */}
      <div className={`absolute inset-0 bg-gradient-to-br from-emerald-500/0 to-emerald-500/0 ${colors.glow} group-hover:to-transparent transition-all duration-500`} />

      {/* Top accent line */}
      <div className={`absolute top-0 left-1/2 -translate-x-1/2 w-0 h-0.5 bg-gradient-to-r ${colors.accent} group-hover:w-full transition-all duration-300`} />

      {/* Icon */}
      <div className="relative flex items-center justify-between mb-3">
        <span className="text-2xl opacity-60 group-hover:opacity-100 transition-opacity">
          {getIcon()}
        </span>
        {trend && (
          <span className={`text-xs font-semibold px-2 py-1 rounded-full ${
            trend > 0 ? 'bg-green-500/20 text-green-400' : 
            trend < 0 ? 'bg-red-500/20 text-red-400' : 
            'bg-slate-500/20 text-slate-400'
          }`}>
            {trend > 0 ? '↑' : trend < 0 ? '↓' : '→'} {Math.abs(trend)}%
          </span>
        )}
      </div>

      <p className={`relative text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 ${colors.text} transition-colors`}>
        {title}
      </p>
      <h3 className={`relative text-4xl font-bold bg-gradient-to-r from-slate-100 to-slate-300 bg-clip-text text-transparent ${colors.value} transition-all duration-300`}>
        {value}
      </h3>

      {description && (
        <p className="relative text-xs text-slate-500 mt-2 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
          {description}
        </p>
      )}
    </div>
  );
};

export default StatsCard;
