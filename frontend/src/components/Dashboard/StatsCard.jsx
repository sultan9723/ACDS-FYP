import React from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  CheckCircle2,
} from "lucide-react";
import { cn } from "../../utils/cn";

const toneStyles = {
  safe: {
    border: "hover:border-emerald-500/35",
    icon: "border-emerald-500/25 bg-emerald-500/10 text-emerald-300",
    accent: "from-emerald-400 to-teal-400",
    value: "text-emerald-100",
  },
  critical: {
    border: "hover:border-red-500/35",
    icon: "border-red-500/25 bg-red-500/10 text-red-300",
    accent: "from-red-400 to-rose-400",
    value: "text-red-100",
  },
  warning: {
    border: "hover:border-amber-500/35",
    icon: "border-amber-500/25 bg-amber-500/10 text-amber-300",
    accent: "from-amber-300 to-orange-400",
    value: "text-amber-100",
  },
  info: {
    border: "hover:border-cyan-500/35",
    icon: "border-cyan-500/25 bg-cyan-500/10 text-cyan-300",
    accent: "from-cyan-300 to-blue-400",
    value: "text-cyan-100",
  },
  neutral: {
    border: "hover:border-slate-600",
    icon: "border-slate-700 bg-slate-800/80 text-slate-300",
    accent: "from-slate-400 to-slate-500",
    value: "text-slate-100",
  },
};

const StatsCard = ({ title, value, icon, description, trend, tone }) => {
  const normalizedTitle = String(title || "").toLowerCase();
  const resolvedTone =
    tone ||
    (normalizedTitle.includes("active")
      ? "critical"
      : normalizedTitle.includes("resolved") ||
        normalizedTitle.includes("action") ||
        normalizedTitle.includes("health")
      ? "safe"
      : normalizedTitle.includes("accuracy")
      ? "info"
      : "neutral");
  const styles = toneStyles[resolvedTone] || toneStyles.neutral;

  const fallbackIcon = normalizedTitle.includes("active") ? (
    <AlertTriangle className="h-5 w-5" />
  ) : normalizedTitle.includes("resolved") || normalizedTitle.includes("action") ? (
    <CheckCircle2 className="h-5 w-5" />
  ) : normalizedTitle.includes("accuracy") ? (
    <BarChart3 className="h-5 w-5" />
  ) : (
    <Activity className="h-5 w-5" />
  );

  return (
    <div
      className={cn(
        "group relative overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/70 p-5 shadow-[0_18px_45px_rgba(2,6,23,0.18)] transition-all duration-300",
        styles.border
      )}
      title={description || title}
    >
      <div
        className={cn(
          "absolute left-0 top-0 h-0.5 w-full bg-gradient-to-r opacity-80",
          styles.accent
        )}
      />

      <div className="mb-5 flex items-start justify-between gap-4">
        <div
          className={cn(
            "flex h-10 w-10 items-center justify-center rounded-lg border",
            styles.icon
          )}
        >
          {icon || fallbackIcon}
        </div>
        {trend !== undefined && trend !== null && (
          <span
            className={cn(
              "rounded-full border px-2 py-1 text-xs font-semibold",
              trend > 0
                ? "border-emerald-500/25 bg-emerald-500/10 text-emerald-300"
                : trend < 0
                ? "border-red-500/25 bg-red-500/10 text-red-300"
                : "border-slate-700 bg-slate-800/70 text-slate-400"
            )}
          >
            {trend > 0 ? "+" : ""}
            {trend}%
          </span>
        )}
      </div>

      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
        {title}
      </p>
      <h3 className={cn("mt-3 text-3xl font-semibold tracking-tight", styles.value)}>
        {value}
      </h3>

      {description && (
        <p className="mt-3 text-xs leading-5 text-slate-500">{description}</p>
      )}
    </div>
  );
};

export default StatsCard;
