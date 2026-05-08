import { useState, useEffect } from "react";
import { checkBackendHealth, scanEmail, fetchStats } from "../utils/api";

/**
 * Connection Test Component
 * Use this to verify frontend-backend connection
 */
const ConnectionTest = () => {
  const [health, setHealth] = useState(null);
  const [stats, setStats] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [testEmail, setTestEmail] = useState(
    "Dear Customer, Your account has been compromised. Click here immediately to verify: http://suspicious-link.com/login"
  );
  const [loading, setLoading] = useState({
    health: false,
    stats: false,
    scan: false,
  });
  const [error, setError] = useState(null);

  // Check backend health on mount
  useEffect(() => {
    checkHealth();
  }, []);

  const checkHealth = async () => {
    setLoading((prev) => ({ ...prev, health: true }));
    try {
      const result = await checkBackendHealth();
      setHealth(result);
    } catch (err) {
      setError(err.message);
    }
    setLoading((prev) => ({ ...prev, health: false }));
  };

  const testStats = async () => {
    setLoading((prev) => ({ ...prev, stats: true }));
    setError(null);
    try {
      const result = await fetchStats();
      setStats(result);
    } catch (err) {
      setError(`Stats Error: ${err.message}`);
    }
    setLoading((prev) => ({ ...prev, stats: false }));
  };

  const testScan = async () => {
    setLoading((prev) => ({ ...prev, scan: true }));
    setError(null);
    try {
      const result = await scanEmail(
        testEmail,
        "Urgent: Account Verification",
        "security@suspicious.com"
      );
      setScanResult(result);
    } catch (err) {
      setError(`Scan Error: ${err.message || JSON.stringify(err)}`);
    }
    setLoading((prev) => ({ ...prev, scan: false }));
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-3xl font-bold mb-8">🔌 Backend Connection Test</h1>

        {/* Health Check */}
        <div className="bg-gray-800 rounded-lg p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-semibold">Backend Health</h2>
            <button
              onClick={checkHealth}
              disabled={loading.health}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded disabled:opacity-50"
            >
              {loading.health ? "Checking..." : "Refresh"}
            </button>
          </div>
          {health && (
            <div
              className={`p-4 rounded ${
                health.connected ? "bg-green-900/50" : "bg-red-900/50"
              }`}
            >
              <p className="flex items-center gap-2">
                <span
                  className={`w-3 h-3 rounded-full ${
                    health.connected ? "bg-green-500" : "bg-red-500"
                  }`}
                ></span>
                <strong>Status:</strong>{" "}
                {health.connected ? "Connected ✅" : "Disconnected ❌"}
              </p>
              {health.connected && (
                <>
                  <p>
                    <strong>Service:</strong> {health.service}
                  </p>
                  <p>
                    <strong>Version:</strong> {health.version}
                  </p>
                </>
              )}
              {!health.connected && (
                <p>
                  <strong>Error:</strong> {health.error}
                </p>
              )}
            </div>
          )}
        </div>

        {/* Stats Test */}
        <div className="bg-gray-800 rounded-lg p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-semibold">Dashboard Stats API</h2>
            <button
              onClick={testStats}
              disabled={loading.stats}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded disabled:opacity-50"
            >
              {loading.stats ? "Loading..." : "Test Stats"}
            </button>
          </div>
          {stats && (
            <div className="bg-gray-700 p-4 rounded">
              <pre className="text-sm overflow-auto">
                {JSON.stringify(stats, null, 2)}
              </pre>
            </div>
          )}
        </div>

        {/* Email Scan Test */}
        <div className="bg-gray-800 rounded-lg p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4">
            Email Phishing Scan API
          </h2>
          <textarea
            value={testEmail}
            onChange={(e) => setTestEmail(e.target.value)}
            className="w-full h-32 bg-gray-700 text-white p-4 rounded mb-4 resize-none"
            placeholder="Enter email content to scan..."
          />
          <button
            onClick={testScan}
            disabled={loading.scan}
            className="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded disabled:opacity-50"
          >
            {loading.scan ? "Scanning..." : "🔍 Scan Email"}
          </button>
          {scanResult && (
            <div
              className={`mt-4 p-4 rounded ${
                scanResult.is_phishing ? "bg-red-900/50" : "bg-green-900/50"
              }`}
            >
              <h3 className="font-bold text-lg mb-2">Scan Result:</h3>
              <p>
                <strong>Is Phishing:</strong>{" "}
                {scanResult.is_phishing ? "⚠️ YES" : "✅ NO"}
              </p>
              <p>
                <strong>Confidence:</strong>{" "}
                {(scanResult.confidence * 100).toFixed(1)}%
              </p>
              <p>
                <strong>Severity:</strong> {scanResult.severity}
              </p>
              <p>
                <strong>Scan ID:</strong> {scanResult.scan_id}
              </p>
            </div>
          )}
        </div>

        {/* Error Display */}
        {error && (
          <div className="bg-red-900/50 border border-red-500 rounded-lg p-4 mb-6">
            <p className="text-red-300">⚠️ {error}</p>
          </div>
        )}

        {/* API Endpoints Reference */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-xl font-semibold mb-4">
            📚 Available API Endpoints
          </h2>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <h3 className="font-bold text-blue-400 mb-2">Auth</h3>
              <ul className="space-y-1 text-gray-300">
                <li>POST /api/v1/auth/login</li>
                <li>POST /api/v1/auth/register</li>
                <li>POST /api/v1/auth/verify</li>
              </ul>
            </div>
            <div>
              <h3 className="font-bold text-green-400 mb-2">Threats</h3>
              <ul className="space-y-1 text-gray-300">
                <li>POST /api/v1/threats/scan</li>
                <li>POST /api/v1/threats/scan/batch</li>
                <li>GET /api/v1/threats/list</li>
              </ul>
            </div>
            <div>
              <h3 className="font-bold text-yellow-400 mb-2">Dashboard</h3>
              <ul className="space-y-1 text-gray-300">
                <li>GET /api/v1/dashboard/stats</li>
                <li>GET /api/v1/dashboard/recent-threats</li>
                <li>GET /api/v1/dashboard/model-status</li>
              </ul>
            </div>
            <div>
              <h3 className="font-bold text-purple-400 mb-2">
                Feedback & Reports
              </h3>
              <ul className="space-y-1 text-gray-300">
                <li>POST /api/v1/feedback/</li>
                <li>POST /api/v1/reports/generate</li>
                <li>GET /api/v1/reports/types</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ConnectionTest;
