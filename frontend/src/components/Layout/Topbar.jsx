import React from "react";
import { useLocation } from "react-router-dom";
import { Bell, Search } from "lucide-react";

const Topbar = () => {
  const { pathname } = useLocation();

  const pageTitles = {
    "/dashboard": "Security Operations",
    "/dashboard/phishing": "Email Phishing",
    "/dashboard/ransomware": "Ransomware Defense",
    "/dashboard/malware": "Malware Analysis",
    "/dashboard/credential-stuffing": "Credential Stuffing",
    "/dashboard/reports": "AI Reports",
    "/dashboard/logs": "System Logs",
  };

  return (
    <header className="sticky top-[136px] z-10 mt-[136px] border-b border-slate-800/80 bg-slate-950/80 px-4 py-3 backdrop-blur-xl sm:px-6 lg:top-0 lg:ml-64 lg:mt-0 lg:px-8">
      <div className="mx-auto flex w-full max-w-[1600px] flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-[0.18em] text-emerald-300/80">
            Enterprise AI SOC
          </p>
          <h2 className="text-lg font-semibold tracking-tight text-slate-100">
            {pageTitles[pathname] || "Security Operations"}
          </h2>
        </div>

        <div className="flex items-center gap-3">
          <div className="relative w-full sm:w-auto">
            <Search
              className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
              size={16}
            />
            <input
              type="text"
              placeholder="Search threats, IPs..."
              className="w-full rounded-lg border border-slate-800/90 bg-slate-950/70 py-2 pl-10 pr-4 text-sm text-slate-200 placeholder:text-slate-600 transition-all focus:outline-none focus:border-emerald-500/80 focus:ring-2 focus:ring-emerald-500/20 sm:w-64"
            />
          </div>

          <button
            className="relative rounded-lg border border-slate-800/90 bg-slate-950/60 p-2 text-slate-400 transition-colors hover:border-slate-700 hover:text-emerald-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400/70 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-950"
            aria-label="Notifications"
          >
            <Bell size={18} />
            <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-emerald-400 shadow-sm shadow-emerald-400/60"></span>
          </button>
        </div>
      </div>
    </header>
  );
};

export default Topbar;
