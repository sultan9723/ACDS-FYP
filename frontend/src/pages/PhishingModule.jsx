import React from "react";
import EmailList from "../components/Phishing/EmailList";
import IncidentDetails from "../components/Dashboard/IncidentDetails";

const PhishingModule = () => {
  return (
    <div className="space-y-6 h-[calc(100vh-100px)]">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-slate-100">
          Email Phishing Detection
        </h1>
        <div className="flex gap-2">
          <span className="px-3 py-1 bg-green-900/50 text-green-400 rounded-full text-xs border border-green-900">
            System Active
          </span>
          <span className="px-3 py-1 bg-blue-900/50 text-blue-400 rounded-full text-xs border border-blue-900">
            Real-time Monitoring
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-full pb-6">
        <div className="lg:col-span-2 h-full overflow-hidden">
          <EmailList />
        </div>
        <div className="h-full overflow-hidden">
          <IncidentDetails />
        </div>
      </div>
    </div>
  );
};

export default PhishingModule;
