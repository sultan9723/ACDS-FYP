import React from "react";
import { cn } from "../../utils/cn";

const Button = React.forwardRef(
  ({ className, variant = "default", size = "default", ...props }, ref) => {
    const variants = {
      default:
        "bg-emerald-500 text-slate-950 shadow-sm shadow-emerald-950/20 hover:bg-emerald-400",
      outline:
        "border border-slate-700/80 bg-slate-950/20 text-slate-100 hover:border-slate-600 hover:bg-slate-800/70",
      ghost: "text-slate-200 hover:bg-slate-800/70 hover:text-white",
      destructive:
        "bg-red-950/70 text-red-100 border border-red-900/70 hover:bg-red-900/80",
      secondary:
        "bg-slate-800/90 text-slate-100 border border-slate-700/70 hover:bg-slate-700/90",
    };

    const sizes = {
      default: "h-10 px-4 py-2",
      sm: "h-9 rounded-md px-3",
      lg: "h-11 rounded-md px-8",
      icon: "h-10 w-10",
    };

    return (
      <button
        ref={ref}
        className={cn(
          "inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400/70 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-950 disabled:pointer-events-none disabled:opacity-50",
          variants[variant],
          sizes[size],
          className
        )}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";

export { Button };
