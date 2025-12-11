import React from "react";
import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";
import Topbar from "./Topbar";

const Layout = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-emerald-950 text-slate-200 font-sans">
      <Sidebar />
      <Topbar />
      <main className="ml-64 p-6">
        <Outlet />
      </main>
    </div>
  );
};

export default Layout;
