import React from "react";
import { Bell, Search } from "lucide-react";

const Topbar = () => {
  return (
    <header className="h-14 bg-slate-900/50 backdrop-blur-md border-b border-slate-800 flex items-center justify-end px-6 sticky top-0 z-10 ml-64">
      <div className="flex items-center gap-4">
        <div className="relative">
          <Search
            className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
            size={16}
          />
          <input
            type="text"
            placeholder="Search threats, IPs..."
            className="bg-slate-950/50 border border-slate-800 rounded-full pl-10 pr-4 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/20 w-56 transition-all"
          />
        </div>

        <button className="relative p-2 text-slate-400 hover:text-emerald-400 transition-colors">
          <Bell size={18} />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></span>
        </button>
      </div>
    </header>
  );
};

export default Topbar;
