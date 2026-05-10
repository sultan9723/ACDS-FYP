import React from "react";
import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";
import Topbar from "./Topbar";

const Layout = () => {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans">
      <Sidebar />
      <Topbar />
      <main className="px-4 pb-8 pt-6 sm:px-6 lg:ml-64 lg:px-8 lg:pb-10 lg:pt-8">
        <div className="mx-auto w-full max-w-[1600px]">
          <Outlet />
        </div>
      </main>
    </div>
  );
};

export default Layout;
