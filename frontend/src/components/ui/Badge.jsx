import React from "react";
import { cn } from "../../utils/cn";

const Badge = React.forwardRef(
  ({ className, variant = "default", ...props }, ref) => {
    const variants = {
      default:
        "border-transparent bg-blue-900/50 text-blue-100 hover:bg-blue-900/80",
      secondary:
        "border-transparent bg-slate-800 text-slate-100 hover:bg-slate-800/80",
      destructive:
        "border-transparent bg-red-900/50 text-red-100 hover:bg-red-900/80",
      outline: "text-slate-100",
      success:
        "border-transparent bg-green-900/50 text-green-100 hover:bg-green-900/80",
    };

    return (
      <div
        ref={ref}
        className={cn(
          "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
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
