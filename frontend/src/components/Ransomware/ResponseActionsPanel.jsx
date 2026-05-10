import React, { useEffect, useMemo, useState } from "react";
import api from "../../utils/api";
import { Card, CardContent } from "../ui/Card";

const ACTION_LABELS = {
  quarantine_file: "Quarantine",
  isolate_file: "Isolate File",
  terminate_process: "Simulate Stop",
  recommend_network_isolation: "Network Review",
  block_hash: "Block Hash",
  alert_soc: "Alert SOC",
};

const FALLBACK_RECOMMENDATIONS = [
  {
    action_type: "alert_soc",
    label: "Alert SOC",
    description: "Record a SOC alert dispatch event for analyst review.",
    mode: "simulated",
    priority: 1,
    safe_mode: true,
  },
];

const getIncidentId = (threat) =>
  threat?.incident_id ||
  threat?.threat_id ||
  threat?.id ||
  threat?.scan_id ||
  threat?.sample?.sha256 ||
  "ransomware-investigation";

const buildContext = (threat) => ({
  incident_id: getIncidentId(threat),
  threat_id: threat?.threat_id || threat?.id,
  scan_id: threat?.scan_id,
  severity: threat?.severity,
  confidence:
    threat?.confidence ??
    threat?.pipeline_results?.detection?.confidence ??
    threat?.detection_confidence,
  detection_confidence: threat?.detection_confidence,
  source_host: threat?.source_host,
  process_name: threat?.process_name || threat?.sample?.filename,
  process_pid: threat?.process_pid,
  file_path:
    threat?.file_path ||
    threat?.sample?.path ||
    threat?.layers?.layer2_pe_header?.binary_path,
  binary_path: threat?.layers?.layer2_pe_header?.binary_path,
  sha256:
    threat?.sha256 ||
    threat?.sample?.sha256 ||
    threat?.layers?.layer2_static_executable_analysis?.sha256 ||
    threat?.iocs?.sha256,
});

const ResponseActionsPanel = ({ threat, embedded = false }) => {
  const [history, setHistory] = useState([]);
  const [loadingAction, setLoadingAction] = useState(null);
  const [report, setReport] = useState(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [error, setError] = useState("");
  const [reportError, setReportError] = useState("");

  const recommendations = useMemo(() => {
    const items = threat?.response_recommendations;
    return Array.isArray(items) && items.length ? items : FALLBACK_RECOMMENDATIONS;
  }, [threat]);

  const incidentId = getIncidentId(threat);

  useEffect(() => {
    let cancelled = false;
    if (!threat) return undefined;

    api
      .get("/ransomware/response/history", {
        params: { incident_id: incidentId, limit: 25 },
      })
      .then((response) => {
        if (!cancelled) {
          setHistory(response.data?.timeline || response.data?.history || []);
        }
      })
      .catch(() => {
        if (!cancelled) setHistory([]);
      });

    return () => {
      cancelled = true;
    };
  }, [incidentId, threat]);

  if (!threat) return null;

  const handleAction = async (actionType) => {
    setLoadingAction(actionType);
    setError("");
    try {
      const response = await api.post("/ransomware/response/action", {
        ...buildContext(threat),
        action_type: actionType,
        requested_by: "soc-console",
      });
      setHistory(response.data?.timeline || [response.data?.action].filter(Boolean));
    } catch (err) {
      setError(err.response?.data?.detail || "Unable to record response action");
    } finally {
      setLoadingAction(null);
    }
  };

  const handleGenerateReport = async () => {
    setReportLoading(true);
    setReportError("");
    try {
      const response = await api.post("/ransomware/reports/generate", {
        detection_result: threat,
        report_type: "technical",
        requested_by: "soc-console",
      });
      setReport(response.data?.report || null);
    } catch (err) {
      setReportError(err.response?.data?.detail || "Unable to generate ransomware report");
    } finally {
      setReportLoading(false);
    }
  };

  const handleDownloadReport = async () => {
    if (!report?.report_id) return;
    setReportError("");
    try {
      const response = await api.get(
        `/ransomware/reports/${report.report_id}/download`,
        { responseType: "blob" }
      );
      const blobUrl = URL.createObjectURL(new Blob([response.data], { type: "application/pdf" }));
      const link = document.createElement("a");
      link.href = blobUrl;
      link.download = report.filename || `${report.report_id}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(blobUrl);
    } catch (err) {
      setReportError(err.response?.data?.detail || "Unable to download ransomware report");
    }
  };

  const content = (
    <>
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className={embedded ? "text-xs text-slate-500 uppercase" : "text-base font-semibold text-slate-200"}>
            Automated Response
          </p>
          <p className="text-xs text-slate-500 mt-1">
            Safe simulated SOC workflow
          </p>
        </div>
        <span className="text-xs px-2 py-1 rounded border border-emerald-900/60 bg-emerald-900/20 text-emerald-300">
          Safe Mode
        </span>
      </div>
      <div className={embedded ? "space-y-4" : ""}>
        <div>
          <p className="text-xs text-slate-500 uppercase mb-2">
            Recommended Mitigation
          </p>
          <div className="space-y-2">
            {recommendations.map((item) => (
              <div
                key={`${item.action_type}-${item.priority}`}
                className="rounded border border-slate-800 bg-slate-800/40 p-3"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-slate-200">
                      {item.label || ACTION_LABELS[item.action_type]}
                    </p>
                    <p className="text-xs text-slate-400 mt-1">
                      {item.description}
                    </p>
                  </div>
                  <span className="text-xs text-slate-500 whitespace-nowrap">
                    {item.mode || "simulated"}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div>
          <p className="text-xs text-slate-500 uppercase mb-2">
            Response Actions
          </p>
          <div className="grid grid-cols-2 gap-2">
            {recommendations.map((item) => {
              const label = ACTION_LABELS[item.action_type] || item.label;
              return (
                <button
                  key={item.action_type}
                  type="button"
                  onClick={() => handleAction(item.action_type)}
                  disabled={Boolean(loadingAction)}
                  className="rounded border border-slate-700 bg-slate-800/70 px-3 py-2 text-xs font-semibold text-slate-200 hover:border-cyan-700 hover:text-cyan-300 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {loadingAction === item.action_type ? "Recording..." : label}
                </button>
              );
            })}
          </div>
          {error && (
            <p className="text-xs text-red-400 mt-2 bg-red-900/20 border border-red-900/40 rounded px-2 py-1">
              {error}
            </p>
          )}
        </div>

        <div>
          <p className="text-xs text-slate-500 uppercase mb-2">
            Response History
          </p>
          {history.length === 0 ? (
            <p className="text-xs text-slate-500 bg-slate-800/30 rounded p-3">
              No response actions recorded for this incident yet.
            </p>
          ) : (
            <div className="space-y-2">
              {history.slice(-6).map((item) => (
                <div
                  key={item.action_id || `${item.timestamp}-${item.action_type}`}
                  className="flex items-start gap-2 text-xs bg-slate-800/30 rounded p-2"
                >
                  <span className="mt-1 h-2 w-2 rounded-full bg-cyan-400"></span>
                  <div>
                    <p className="text-slate-300">
                      {item.description || item.timeline_event || item.label}
                    </p>
                    <p className="text-slate-500 mt-1">
                      {item.status || "recorded"} | {item.timestamp}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div>
          <p className="text-xs text-slate-500 uppercase mb-2">
            Incident Report
          </p>
          <div className="rounded border border-slate-800 bg-slate-800/30 p-3 space-y-3">
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={handleGenerateReport}
                disabled={reportLoading}
                className="rounded border border-slate-700 bg-slate-800/70 px-3 py-2 text-xs font-semibold text-slate-200 hover:border-cyan-700 hover:text-cyan-300 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {reportLoading ? "Generating..." : "Generate Report"}
              </button>
              <button
                type="button"
                onClick={handleDownloadReport}
                disabled={!report?.report_id || reportLoading}
                className="rounded border border-slate-700 bg-slate-800/70 px-3 py-2 text-xs font-semibold text-slate-200 hover:border-emerald-700 hover:text-emerald-300 disabled:cursor-not-allowed disabled:opacity-60"
              >
                Download PDF
              </button>
            </div>
            {report && (
              <div className="text-xs text-slate-400 space-y-1">
                <p>
                  <span className="text-slate-500">Report:</span>{" "}
                  <span className="font-mono text-slate-300">{report.report_id}</span>
                </p>
                <p>
                  <span className="text-slate-500">Summary:</span>{" "}
                  {report.ai_summary}
                </p>
              </div>
            )}
            {reportError && (
              <p className="text-xs text-red-400 bg-red-900/20 border border-red-900/40 rounded px-2 py-1">
                {reportError}
              </p>
            )}
          </div>
        </div>
      </div>
    </>
  );

  if (embedded) {
    return <div className="space-y-4 pt-2 border-t border-slate-800">{content}</div>;
  }

  return (
    <Card className="bg-slate-900/50 border-slate-800">
      <CardContent className="space-y-4 pt-6">{content}</CardContent>
    </Card>
  );
};

export default ResponseActionsPanel;
