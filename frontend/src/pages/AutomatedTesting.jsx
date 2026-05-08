import { useState, useEffect } from "react";
import api from "../utils/api";

/**
 * Automated Testing Page
 * Complete workflow testing: Detection → Response → Reports → Logs
 */
const AutomatedTesting = () => {
  const [status, setStatus] = useState(null);
  const [samples, setSamples] = useState([]);
  const [testResult, setTestResult] = useState(null);
  const [quickScan, setQuickScan] = useState(null);
  const [logs, setLogs] = useState([]);
  const [reports, setReports] = useState([]);
  const [selectedReport, setSelectedReport] = useState(null);
  const [loading, setLoading] = useState({
    status: false,
    samples: false,
    test: false,
    quickScan: false,
    logs: false,
    reports: false,
  });
  const [testConfig, setTestConfig] = useState({
    count: 10,
    includeResponse: true,
  });

  // Fetch testing status on mount
  useEffect(() => {
    fetchStatus();
    fetchLogs();
    fetchReports();
  }, []);

  const fetchStatus = async () => {
    setLoading((prev) => ({ ...prev, status: true }));
    try {
      const response = await api.get("/testing/status");
      setStatus(response.data);
    } catch (err) {
      console.error("Error fetching status:", err);
    }
    setLoading((prev) => ({ ...prev, status: false }));
  };

  const fetchSamples = async (type = "mixed") => {
    setLoading((prev) => ({ ...prev, samples: true }));
    try {
      const response = await api.get(
        `/testing/samples?sample_type=${type}&count=5`
      );
      setSamples(response.data.samples);
    } catch (err) {
      console.error("Error fetching samples:", err);
    }
    setLoading((prev) => ({ ...prev, samples: false }));
  };

  const runQuickScan = async (type = "phishing") => {
    setLoading((prev) => ({ ...prev, quickScan: true }));
    setQuickScan(null);
    try {
      const response = await api.post(
        `/testing/quick-scan?sample_type=${type}`
      );
      setQuickScan(response.data);
      fetchLogs(); // Refresh logs after scan
    } catch (err) {
      console.error("Error in quick scan:", err);
    }
    setLoading((prev) => ({ ...prev, quickScan: false }));
  };

  const runAutomatedTest = async () => {
    setLoading((prev) => ({ ...prev, test: true }));
    setTestResult(null);
    try {
      const response = await api.post(
        `/testing/run?count=${testConfig.count}&include_response=${testConfig.includeResponse}`
      );
      setTestResult(response.data);
      fetchStatus(); // Refresh status
      fetchLogs(); // Refresh logs
      fetchReports(); // Refresh reports
    } catch (err) {
      console.error("Error running test:", err);
    }
    setLoading((prev) => ({ ...prev, test: false }));
  };

  const fetchLogs = async () => {
    setLoading((prev) => ({ ...prev, logs: true }));
    try {
      const response = await api.get("/testing/logs?limit=50");
      setLogs(response.data.logs || []);
    } catch (err) {
      console.error("Error fetching logs:", err);
    }
    setLoading((prev) => ({ ...prev, logs: false }));
  };

  const fetchReports = async () => {
    setLoading((prev) => ({ ...prev, reports: true }));
    try {
      const response = await api.get("/testing/reports?limit=10");
      setReports(response.data.reports || []);
    } catch (err) {
      console.error("Error fetching reports:", err);
    }
    setLoading((prev) => ({ ...prev, reports: false }));
  };

  const viewReport = async (reportId) => {
    try {
      const response = await api.get(`/testing/reports/${reportId}`);
      setSelectedReport(response.data.report);
    } catch (err) {
      console.error("Error fetching report:", err);
    }
  };

  const resetSystem = async () => {
    if (window.confirm("Are you sure you want to reset all test data?")) {
      try {
        await api.post("/testing/reset");
        fetchStatus();
        fetchLogs();
        fetchReports();
        setTestResult(null);
        setQuickScan(null);
        setSamples([]);
      } catch (err) {
        console.error("Error resetting:", err);
      }
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-3xl font-bold">🧪 Automated Testing</h1>
            <p className="text-gray-400 mt-1">
              Test phishing detection, threat response, and report generation
            </p>
          </div>
          <button
            onClick={resetSystem}
            className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded text-sm"
          >
            Reset All Data
          </button>
        </div>

        {/* Status Card */}
        <div className="bg-gray-800 rounded-lg p-6 mb-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-xl font-semibold">System Status</h2>
            <button
              onClick={fetchStatus}
              disabled={loading.status}
              className="text-blue-400 hover:text-blue-300 text-sm"
            >
              {loading.status ? "Loading..." : "Refresh"}
            </button>
          </div>
          {status && (
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <div className="bg-gray-700 p-4 rounded">
                <p className="text-gray-400 text-sm">Status</p>
                <p className="text-green-400 font-bold text-lg">
                  {status.status?.toUpperCase()}
                </p>
              </div>
              <div className="bg-gray-700 p-4 rounded">
                <p className="text-gray-400 text-sm">Phishing Samples</p>
                <p className="text-white font-bold text-lg">
                  {status.available_samples?.phishing || 0}
                </p>
              </div>
              <div className="bg-gray-700 p-4 rounded">
                <p className="text-gray-400 text-sm">Legitimate Samples</p>
                <p className="text-white font-bold text-lg">
                  {status.available_samples?.legitimate || 0}
                </p>
              </div>
              <div className="bg-gray-700 p-4 rounded">
                <p className="text-gray-400 text-sm">Tests Run</p>
                <p className="text-white font-bold text-lg">
                  {status.test_sessions_run || 0}
                </p>
              </div>
              <div className="bg-gray-700 p-4 rounded">
                <p className="text-gray-400 text-sm">Reports Generated</p>
                <p className="text-white font-bold text-lg">
                  {status.reports_generated || 0}
                </p>
              </div>
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Quick Scan Section */}
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-xl font-semibold mb-4">⚡ Quick Scan Test</h2>
            <p className="text-gray-400 text-sm mb-4">
              Scan a single random email sample to verify detection is working.
            </p>
            <div className="flex gap-2 mb-4">
              <button
                onClick={() => runQuickScan("phishing")}
                disabled={loading.quickScan}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded disabled:opacity-50"
              >
                {loading.quickScan ? "Scanning..." : "🎣 Scan Phishing"}
              </button>
              <button
                onClick={() => runQuickScan("legitimate")}
                disabled={loading.quickScan}
                className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded disabled:opacity-50"
              >
                {loading.quickScan ? "Scanning..." : "✅ Scan Legitimate"}
              </button>
            </div>

            {quickScan && (
              <div
                className={`p-4 rounded ${
                  quickScan.correct ? "bg-green-900/50" : "bg-red-900/50"
                }`}
              >
                <div className="flex justify-between items-start mb-2">
                  <h3 className="font-bold">{quickScan.sample?.subject}</h3>
                  <span
                    className={`px-2 py-1 rounded text-xs ${
                      quickScan.correct ? "bg-green-500" : "bg-red-500"
                    }`}
                  >
                    {quickScan.correct ? "CORRECT" : "INCORRECT"}
                  </span>
                </div>
                <p className="text-sm text-gray-300 mb-2">
                  From: {quickScan.sample?.sender}
                </p>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-gray-400">Actual:</p>
                    <p
                      className={
                        quickScan.sample?.actual_label === "PHISHING"
                          ? "text-red-400"
                          : "text-green-400"
                      }
                    >
                      {quickScan.sample?.actual_label}
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-400">Predicted:</p>
                    <p
                      className={
                        quickScan.prediction?.predicted_label === "PHISHING"
                          ? "text-red-400"
                          : "text-green-400"
                      }
                    >
                      {quickScan.prediction?.predicted_label}
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-400">Confidence:</p>
                    <p>
                      {(quickScan.prediction?.confidence * 100).toFixed(1)}%
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-400">Severity:</p>
                    <p>{quickScan.prediction?.severity}</p>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Full Test Section */}
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-xl font-semibold mb-4">
              🔬 Full Automated Test
            </h2>
            <p className="text-gray-400 text-sm mb-4">
              Run a complete test with detection, response actions, and report
              generation.
            </p>

            <div className="space-y-4 mb-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">
                  Number of Samples
                </label>
                <input
                  type="range"
                  min="5"
                  max="50"
                  value={testConfig.count}
                  onChange={(e) =>
                    setTestConfig((prev) => ({
                      ...prev,
                      count: parseInt(e.target.value),
                    }))
                  }
                  className="w-full"
                />
                <span className="text-sm">{testConfig.count} emails</span>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="includeResponse"
                  checked={testConfig.includeResponse}
                  onChange={(e) =>
                    setTestConfig((prev) => ({
                      ...prev,
                      includeResponse: e.target.checked,
                    }))
                  }
                  className="rounded"
                />
                <label htmlFor="includeResponse" className="text-sm">
                  Include threat response actions
                </label>
              </div>
            </div>

            <button
              onClick={runAutomatedTest}
              disabled={loading.test}
              className="w-full px-4 py-3 bg-purple-600 hover:bg-purple-700 rounded font-bold disabled:opacity-50"
            >
              {loading.test ? "🔄 Running Test..." : "🚀 Run Full Test"}
            </button>

            {testResult && (
              <div className="mt-4 p-4 bg-gray-700 rounded">
                <h3 className="font-bold text-green-400 mb-2">
                  ✅ Test Completed
                </h3>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <p>
                    Session ID:{" "}
                    <span className="text-blue-400">
                      {testResult.session_id}
                    </span>
                  </p>
                  <p>
                    Accuracy:{" "}
                    <span className="text-yellow-400">
                      {(testResult.summary?.accuracy * 100).toFixed(1)}%
                    </span>
                  </p>
                  <p>
                    Threats Found:{" "}
                    <span className="text-red-400">
                      {testResult.threats_detected}
                    </span>
                  </p>
                  <p>
                    Actions Taken:{" "}
                    <span className="text-green-400">
                      {testResult.actions_taken}
                    </span>
                  </p>
                  <p>
                    Precision:{" "}
                    <span className="text-blue-400">
                      {(testResult.summary?.precision * 100).toFixed(1)}%
                    </span>
                  </p>
                  <p>
                    Recall:{" "}
                    <span className="text-blue-400">
                      {(testResult.summary?.recall * 100).toFixed(1)}%
                    </span>
                  </p>
                </div>
                <button
                  onClick={() => viewReport(testResult.report_id)}
                  className="mt-2 text-purple-400 hover:text-purple-300 text-sm"
                >
                  📄 View Full Report →
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Logs Section */}
        <div className="bg-gray-800 rounded-lg p-6 mt-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-xl font-semibold">📋 Test Logs</h2>
            <button
              onClick={fetchLogs}
              disabled={loading.logs}
              className="text-blue-400 hover:text-blue-300 text-sm"
            >
              {loading.logs ? "Loading..." : "Refresh"}
            </button>
          </div>
          <div className="max-h-64 overflow-y-auto">
            {logs.length === 0 ? (
              <p className="text-gray-500 text-center py-4">
                No logs yet. Run a test to generate logs.
              </p>
            ) : (
              <table className="w-full text-sm">
                <thead className="text-gray-400 border-b border-gray-700">
                  <tr>
                    <th className="text-left py-2">Time</th>
                    <th className="text-left py-2">Event</th>
                    <th className="text-left py-2">Details</th>
                    <th className="text-left py-2">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {logs
                    .slice()
                    .reverse()
                    .map((log, i) => (
                      <tr key={i} className="border-b border-gray-700/50">
                        <td className="py-2 text-gray-400">
                          {new Date(log.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="py-2">
                          <span
                            className={`px-2 py-1 rounded text-xs ${
                              log.event === "email_scanned"
                                ? "bg-blue-600"
                                : log.event === "threat_response"
                                ? "bg-red-600"
                                : log.event === "test_completed"
                                ? "bg-green-600"
                                : log.event === "quick_scan"
                                ? "bg-purple-600"
                                : "bg-gray-600"
                            }`}
                          >
                            {log.event}
                          </span>
                        </td>
                        <td className="py-2 text-gray-300 max-w-xs truncate">
                          {log.subject ||
                            log.threat_id ||
                            `Session: ${log.session_id}`}
                        </td>
                        <td className="py-2">
                          {log.correct !== undefined && (
                            <span
                              className={
                                log.correct ? "text-green-400" : "text-red-400"
                              }
                            >
                              {log.correct ? "✓" : "✗"}
                            </span>
                          )}
                          {log.status && (
                            <span
                              className={
                                log.status === "completed"
                                  ? "text-green-400"
                                  : "text-yellow-400"
                              }
                            >
                              {log.status}
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Reports Section */}
        <div className="bg-gray-800 rounded-lg p-6 mt-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-xl font-semibold">📊 Generated Reports</h2>
            <button
              onClick={fetchReports}
              disabled={loading.reports}
              className="text-blue-400 hover:text-blue-300 text-sm"
            >
              {loading.reports ? "Loading..." : "Refresh"}
            </button>
          </div>

          {reports.length === 0 ? (
            <p className="text-gray-500 text-center py-4">
              No reports yet. Run a full test to generate a report.
            </p>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {reports.map((report) => (
                <div
                  key={report.report_id}
                  className="bg-gray-700 p-4 rounded cursor-pointer hover:bg-gray-600 transition"
                  onClick={() => setSelectedReport(report)}
                >
                  <p className="font-bold text-sm">{report.report_id}</p>
                  <p className="text-gray-400 text-xs">
                    {new Date(report.generated_at).toLocaleString()}
                  </p>
                  <div className="mt-2 grid grid-cols-2 gap-1 text-xs">
                    <p>
                      Emails: {report.executive_summary?.total_emails_tested}
                    </p>
                    <p>Threats: {report.executive_summary?.threats_detected}</p>
                    <p>Accuracy: {report.executive_summary?.accuracy}</p>
                    <p>F1: {report.executive_summary?.f1_score}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Report Detail Modal */}
        {selectedReport && (
          <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
            <div className="bg-gray-800 rounded-lg max-w-4xl w-full max-h-[90vh] overflow-y-auto">
              <div className="sticky top-0 bg-gray-800 p-4 border-b border-gray-700 flex justify-between items-center">
                <h2 className="text-xl font-bold">📄 {selectedReport.title}</h2>
                <button
                  onClick={() => setSelectedReport(null)}
                  className="text-gray-400 hover:text-white text-2xl"
                >
                  ×
                </button>
              </div>
              <div className="p-6">
                {/* Executive Summary */}
                <div className="mb-6">
                  <h3 className="text-lg font-semibold mb-3 text-blue-400">
                    Executive Summary
                  </h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {Object.entries(selectedReport.executive_summary || {}).map(
                      ([key, value]) => (
                        <div key={key} className="bg-gray-700 p-3 rounded">
                          <p className="text-gray-400 text-xs capitalize">
                            {key.replace(/_/g, " ")}
                          </p>
                          <p className="font-bold">{value}</p>
                        </div>
                      )
                    )}
                  </div>
                </div>

                {/* Performance Metrics */}
                <div className="mb-6">
                  <h3 className="text-lg font-semibold mb-3 text-green-400">
                    Confusion Matrix
                  </h3>
                  <div className="grid grid-cols-2 gap-4 max-w-md">
                    <div className="bg-green-900/50 p-3 rounded text-center">
                      <p className="text-xs text-gray-400">True Positives</p>
                      <p className="text-2xl font-bold text-green-400">
                        {selectedReport.performance_metrics?.true_positives ||
                          0}
                      </p>
                    </div>
                    <div className="bg-red-900/50 p-3 rounded text-center">
                      <p className="text-xs text-gray-400">False Positives</p>
                      <p className="text-2xl font-bold text-red-400">
                        {selectedReport.performance_metrics?.false_positives ||
                          0}
                      </p>
                    </div>
                    <div className="bg-yellow-900/50 p-3 rounded text-center">
                      <p className="text-xs text-gray-400">False Negatives</p>
                      <p className="text-2xl font-bold text-yellow-400">
                        {selectedReport.performance_metrics?.false_negatives ||
                          0}
                      </p>
                    </div>
                    <div className="bg-blue-900/50 p-3 rounded text-center">
                      <p className="text-xs text-gray-400">True Negatives</p>
                      <p className="text-2xl font-bold text-blue-400">
                        {selectedReport.performance_metrics?.true_negatives ||
                          0}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Recommendations */}
                <div className="mb-6">
                  <h3 className="text-lg font-semibold mb-3 text-yellow-400">
                    Recommendations
                  </h3>
                  <ul className="space-y-2">
                    {(selectedReport.recommendations || []).map((rec, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm">
                        <span className="text-yellow-400">→</span>
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Threats */}
                {selectedReport.threat_analysis?.threats?.length > 0 && (
                  <div>
                    <h3 className="text-lg font-semibold mb-3 text-red-400">
                      Detected Threats (
                      {selectedReport.threat_analysis.total_threats})
                    </h3>
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {selectedReport.threat_analysis.threats.map(
                        (threat, i) => (
                          <div
                            key={i}
                            className="bg-gray-700 p-3 rounded text-sm"
                          >
                            <div className="flex justify-between">
                              <span className="font-bold">{threat.id}</span>
                              <span
                                className={`px-2 py-1 rounded text-xs ${
                                  threat.severity === "CRITICAL"
                                    ? "bg-red-600"
                                    : threat.severity === "HIGH"
                                    ? "bg-orange-600"
                                    : "bg-yellow-600"
                                }`}
                              >
                                {threat.severity}
                              </span>
                            </div>
                            <p className="text-gray-400 truncate">
                              {threat.subject}
                            </p>
                          </div>
                        )
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AutomatedTesting;
