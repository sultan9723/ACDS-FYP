import React from "react";
import { NavLink, useNavigate, Link } from "react-router-dom";
import {
  LayoutDashboard,
  ShieldAlert,
  FileText,
  Sparkles,
  LogOut,
  Shield,
  Bug,
  KeyRound,
} from "lucide-react";
import { cn } from "../../utils/cn";
import { useAuth } from "../../context/AuthContext";

const Sidebar = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const navItems = [
    { icon: LayoutDashboard, label: "Dashboard",      path: "/dashboard" },
    { icon: ShieldAlert,     label: "Email Phishing", path: "/dashboard/phishing" },
    { icon: Bug,             label: "Ransomware",     path: "/dashboard/ransomware" },
    { icon: ShieldAlert,     label: "Malware",        path: "/dashboard/malware" },
    { icon: KeyRound,        label: "Credential Stuffing", path: "/dashboard/credential-stuffing" },
    { icon: Sparkles,        label: "AI Reports",     path: "/dashboard/reports" },
    { icon: FileText,        label: "Logs",           path: "/dashboard/logs" },
  ];

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <aside className="fixed left-0 top-0 z-20 flex h-auto w-full flex-col border-b border-slate-800/80 bg-slate-950/90 backdrop-blur-xl lg:h-screen lg:w-64 lg:border-b-0 lg:border-r">
      <div className="border-b border-slate-800/80 px-4 py-4 lg:p-6">
        <Link to="/" className="flex items-center space-x-3">
          <div className="w-10 h-10 bg-gradient-to-br from-emerald-400 to-teal-500 rounded-lg flex items-center justify-center shadow-lg shadow-emerald-950/30">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-tight text-slate-100">
              ACDS
            </h1>
            <p className="text-xs text-slate-500">Autonomous Cyber Defense</p>
          </div>
        </Link>
      </div>

      <nav className="flex gap-2 overflow-x-auto px-4 py-3 lg:flex-1 lg:flex-col lg:space-y-1.5 lg:overflow-x-visible lg:p-4">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.path === "/dashboard"}
            className={({ isActive }) =>
              cn(
                "flex shrink-0 items-center gap-3 rounded-lg border px-3 py-2.5 text-sm font-medium transition-all duration-200 lg:w-full lg:px-4",
                isActive
                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300 shadow-sm shadow-emerald-950/30"
                  : "border-transparent text-slate-400 hover:border-slate-700/70 hover:bg-slate-900 hover:text-slate-100"
              )
            }
          >
            <item.icon size={18} />
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="hidden border-t border-slate-800/80 p-4 lg:block">
        <div className="flex items-center gap-3 px-4 py-2 mb-2">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-emerald-500 to-teal-500 flex items-center justify-center text-xs font-bold text-white shadow-lg shadow-emerald-950/30">
            {user?.name
              ?.split(" ")
              .map((n) => n[0])
              .join("") || "AD"}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-slate-200 truncate">
              {user?.name || "Admin User"}
            </p>
            <p className="text-xs text-slate-500 truncate">
              {user?.email || "admin@acds.com"}
            </p>
          </div>
        </div>
        <button
          onClick={handleLogout}
          className="w-full flex items-center gap-3 px-4 py-2 rounded-lg text-sm font-medium text-red-300 hover:bg-red-500/10 hover:text-red-200 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-400/60 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-950"
        >
          <LogOut size={18} />
          Sign Out
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
