import React from "react";
import { cn } from "../../utils/cn";

const Badge = React.forwardRef(
  ({ className, variant = "default", ...props }, ref) => {
    const variants = {
      default:
        "border-cyan-500/20 bg-cyan-500/10 text-cyan-200 hover:bg-cyan-500/15",
      secondary:
        "border-slate-700/70 bg-slate-800/80 text-slate-200 hover:bg-slate-800",
      destructive:
        "border-red-500/25 bg-red-500/10 text-red-200 hover:bg-red-500/15",
      outline: "border-slate-700/80 text-slate-200",
      success:
        "border-emerald-500/25 bg-emerald-500/10 text-emerald-200 hover:bg-emerald-500/15",
      warning:
        "border-amber-500/25 bg-amber-500/10 text-amber-200 hover:bg-amber-500/15",
      critical:
        "border-red-500/30 bg-red-500/15 text-red-200 hover:bg-red-500/20",
    };

    return (
      <div
        ref={ref}
        className={cn(
          "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold tracking-wide transition-colors focus:outline-none focus:ring-2 focus:ring-emerald-400/70 focus:ring-offset-2 focus:ring-offset-slate-950",
          variants[variant],
          className
        )}
        {...props}
      />
    );
  }
);
Badge.displayName = "Badge";

export { Badge };
