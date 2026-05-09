import React, { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "../ui/Card";
import { Badge } from "../ui/Badge";

const API_BASE = "http://localhost:8000/api/v1";

const ThreeLayerDetectionScanner = ({ onDetectionResult }) => {
  const [commandInput, setCommandInput] = useState("");
  const [binaryPath, setBinaryPath] = useState("");
  const [fileCount, setFileCount] = useState(50);
  const [detectingMode, setDetectingMode] = useState("command"); // "command", "encryption", "full"
  const [detecting, setDetecting] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  // New realism features
  const [activityLogs, setActivityLogs] = useState([]);
  const [fileActivitySpike, setFileActivitySpike] = useState(0);
  const [detectionTimeline, setDetectionTimeline] = useState([]);
  const [autoResponseSteps, setAutoResponseSteps] = useState([]);
  const [isMonitoring, setIsMonitoring] = useState(true);

  // Fake monitoring logs
  const fakeLogs = [
    "Monitoring file system...",
    "Scanning process activity...",
    "Analyzing network connections...",
    "Checking shadow copy status...",
    "Monitoring registry changes...",
    "Scanning for suspicious extensions...",
    "Analyzing file entropy changes...",
    "Checking for backup interference...",
  ];

  // Start monitoring on mount
  useEffect(() => {
    if (!isMonitoring) return;

    const interval = setInterval(() => {
      const randomLog = fakeLogs[Math.floor(Math.random() * fakeLogs.length)];
      const timestamp = new Date().toLocaleTimeString();
      setActivityLogs(prev => [...prev.slice(-9), `[${timestamp}] ${randomLog}`]);
    }, 1500);

    return () => clearInterval(interval);
  }, [isMonitoring]);

  // Simulate file activity spike during detection
  useEffect(() => {
    if (!detecting) {
      setFileActivitySpike(0);
      return;
    }

    const interval = setInterval(() => {
      setFileActivitySpike(prev => {
        const increment = Math.floor(Math.random() * 15) + 5;
        return Math.min(prev + increment, fileCount);
      });
    }, 200);

    return () => clearInterval(interval);
  }, [detecting, fileCount]);

  const handleThreeLayerDetection = async () => {
    if (detectingMode === "command" && !commandInput.trim()) return;
    if (detectingMode === "full" && (!commandInput.trim() || !binaryPath.trim())) return;
    
    setDetecting(true);
    setError(null);
    setDetectionTimeline([]);
    setAutoResponseSteps([]);

    // Add initial timeline step
    setDetectionTimeline(["🟢 Analysis Started"]);

    try {
      // Simulate timeline progression
      setTimeout(() => setDetectionTimeline(prev => [...prev, "🟡 Scanning Command Patterns"]), 500);
      setTimeout(() => setDetectionTimeline(prev => [...prev, "🟠 Analyzing File Activities"]), 1000);
      setTimeout(() => setDetectionTimeline(prev => [...prev, "🔴 Cross-Referencing Layers"]), 1500);

      const payload = {
        command: detectingMode !== "encryption" ? commandInput : null,
        binary_path: binaryPath.trim() || null,
        process_name: "test_process.exe",
        process_pid: 1234,
        source_host: "TEST-WORKSTATION",
        user: "test@domain.com",
        file_activities:
          detectingMode !== "command"
            ? Array.from({ length: fileCount }, (_, i) => ({
                path: `C:/Users/Documents/file_${String(i).padStart(4, '0')}.${i % 3 === 0 ? "xlsx" : "docx"}`,
                operation: "modify",
                extension: detectingMode === "encryption" ? ".encrypted" : `.ext${i}`,
                process_pid: 1234,
                process_name: detectingMode === "encryption" ? "malware.exe" : "test_process.exe",
                source_host: "TEST-WORKSTATION",
              }))
            : null,
      };

      const res = await fetch(`${API_BASE}/ransomware/detect-layers`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await res.json();

      if (data.success) {
        setResult(data.result);
        setDetectionTimeline(prev => [...prev, "✅ Analysis Complete"]);

        // Simulate auto-response if threat detected
        if (data.result.overall_verdict === "RANSOMWARE_DETECTED") {
          setTimeout(() => setAutoResponseSteps(["Terminating malicious process..."]), 2000);
          setTimeout(() => setAutoResponseSteps(prev => [...prev, "Blocking file access..."]), 3000);
          setTimeout(() => setAutoResponseSteps(prev => [...prev, "System isolated from network"]), 4000);
          setTimeout(() => setAutoResponseSteps(prev => [...prev, "Backup initiated"]), 5000);
        }

        if (onDetectionResult) onDetectionResult(data.result);
      } else {
        setError(data.detail || "Detection failed");
        setDetectionTimeline(prev => [...prev, "❌ Analysis Failed"]);
      }
    } catch (e) {
      setError(`Error: ${e.message}`);
      setDetectionTimeline(prev => [...prev, "❌ Analysis Failed"]);
    } finally {
      setDetecting(false);
    }
  };

  const formatConfidence = (value) => {
    if (!value && value !== 0) return "N/A";
    if (value > 1) return `${Math.round(value)}%`;
    return `${Math.round(value * 100)}%`;
  };

  return (
    <div className="space-y-4">
      {/* Mode Selection */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-slate-200 text-base">
            3-Layer Detection Mode
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-3 gap-2">
            {[
              {
                id: "command",
                label: "Layer 1 Only",
                desc: "Command behavior analysis",
              },
              {
                id: "encryption",
                label: "Layer 3 Only",
                desc: "Encryption detection",
              },
              { id: "full", label: "All 3 Layers", desc: "Full analysis" },
            ].map((mode) => (
              <button
                key={mode.id}
                onClick={() => {
                  setDetectingMode(mode.id);
                  setResult(null);
                }}
                className={`p-3 rounded-lg border-2 transition-all text-left ${
                  detectingMode === mode.id
                    ? "border-emerald-500 bg-emerald-900/20"
                    : "border-slate-700 bg-slate-800/20 hover:border-slate-600"
                }`}
              >
                <p className="text-sm font-semibold text-slate-200">
                  {mode.label}
                </p>
                <p className="text-xs text-slate-500">{mode.desc}</p>
              </button>
            ))}
          </div>

          {/* Input Fields */}
          {(detectingMode === "command" || detectingMode === "full") && (
            <div>
              <label className="text-xs text-slate-500 uppercase block mb-2">
                Command to Analyze
              </label>
              <input
                type="text"
                value={commandInput}
                onChange={(e) => setCommandInput(e.target.value)}
                placeholder="e.g., cmd.exe /c vssadmin delete shadows /all"
                className="w-full bg-slate-800 border border-slate-700 text-slate-200 text-sm rounded-lg px-3 py-2 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
              />
              <p className="text-xs text-slate-500 mt-1">
                {commandInput.length} characters
              </p>
            </div>
          )}

          {(detectingMode === "full") && (
            <div>
              <label className="text-xs text-slate-500 uppercase block mb-2">
                Binary Path (for Layer 2 PE Analysis)
              </label>
              <input
                type="text"
                value={binaryPath}
                onChange={(e) => setBinaryPath(e.target.value)}
                placeholder="e.g., C:\Windows\System32\malware.exe"
                className="w-full bg-slate-800 border border-slate-700 text-slate-200 text-sm rounded-lg px-3 py-2 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
              />
              <p className="text-xs text-slate-500 mt-1">
                Path to executable file for PE header analysis
              </p>
            </div>
          )}

          {(detectingMode === "encryption" || detectingMode === "full") && (
            <div>
              <label className="text-xs text-slate-500 uppercase block mb-2">
                Simulated File Activities
              </label>
              <div className="flex items-center gap-3">
                <input
                  type="range"
                  min="10"
                  max="200"
                  step="10"
                  value={fileCount}
                  onChange={(e) => setFileCount(parseInt(e.target.value))}
                  className="flex-1 h-2 bg-slate-700 rounded-lg appearance-none cursor-pointer"
                />
                <span className="text-sm font-semibold text-slate-300 min-w-[50px]">
                  {fileCount} files
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-2">
                Simulates {fileCount} rapid file modifications with .encrypted
                extension
              </p>
            </div>
          )}

          {/* Error Display */}
          {error && (
            <div className="bg-red-900/30 border border-red-800 text-red-400 text-sm rounded-lg px-3 py-2">
              {error}
            </div>
          )}

          {/* Scan Button */}
          <button
            onClick={handleThreeLayerDetection}
            disabled={detecting || (detectingMode === "command" && !commandInput.trim()) || (detectingMode === "full" && (!commandInput.trim() || !binaryPath.trim()))}
            className="w-full px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-700 disabled:text-slate-500 text-white text-sm font-medium rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            {detecting ? (
              <>
                <div className="animate-spin rounded-full h-3 w-3 border-b-2 border-white"></div>
                Analyzing...
              </>
            ) : (
              `Analyze with 3-Layer Detection`
            )}
          </button>
        </CardContent>
      </Card>

      {/* Result Summary */}
      {result && (
        <Card
          className={`border-2 ${
            result.overall_verdict === "RANSOMWARE_DETECTED"
              ? "border-red-800 bg-red-900/20"
              : result.overall_verdict === "SUSPICIOUS"
              ? "border-yellow-800 bg-yellow-900/20"
              : "border-green-800 bg-green-900/20"
          }`}
        >
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-slate-200">Detection Result</CardTitle>
              <Badge
                variant={
                  result.overall_verdict === "RANSOMWARE_DETECTED"
                    ? "destructive"
                    : result.overall_verdict === "SUSPICIOUS"
                    ? "warning"
                    : "success"
                }
              >
                {result.overall_verdict?.replace(/_/g, " ")}
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-slate-800/50 rounded-lg p-3">
                <p className="text-xs text-slate-500 mb-1">Confidence</p>
                <p className="text-lg font-bold text-slate-200">
                  {formatConfidence(result.detection_confidence)}
                </p>
              </div>
              <div className="bg-slate-800/50 rounded-lg p-3">
                <p className="text-xs text-slate-500 mb-1">Processing Time</p>
                <p className="text-lg font-bold text-slate-200">
                  {result.processing_time_ms}ms
                </p>
              </div>
            </div>

            {/* Layers Triggered */}
            <div>
              <p className="text-xs text-slate-500 uppercase mb-2">Layers</p>
              <div className="space-y-2">
                {result.layers?.layer1_command_behavior && (
                  <div className="flex items-center justify-between p-2 bg-slate-800/30 rounded">
                    <span className="text-sm text-slate-300">
                      Layer 1: Command Behavior
                    </span>
                    {result.layers.layer1_command_behavior.is_ransomware ? (
                      <Badge variant="destructive">Detected</Badge>
                    ) : result.layers.layer1_command_behavior.status === "error" ? (
                      <Badge variant="secondary">Error</Badge>
                    ) : (
                      <Badge variant="success">Safe</Badge>
                    )}
                  </div>
                )}
                {result.layers?.layer3_mass_encryption && (
                  <div className="flex items-center justify-between p-2 bg-slate-800/30 rounded">
                    <span className="text-sm text-slate-300">
                      Layer 3: Mass-Encryption
                    </span>
                    {result.layers.layer3_mass_encryption.status ===
                    "threat_detected" ? (
                      <Badge variant="destructive">Detected</Badge>
                    ) : result.layers.layer3_mass_encryption.status === "error" ? (
                      <Badge variant="secondary">Error</Badge>
                    ) : (
                      <Badge variant="success">Clear</Badge>
                    )}
                  </div>
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default ThreeLayerDetectionScanner;
