import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef,
} from "react";
import {
  fetchStats,
  fetchThreatsOverTime,
  fetchThreatTypes,
  fetchAccuracyOverTime,
  fetchConfusionMatrix,
  fetchThreats,
  fetchIncidentDetails,
  fetchModelLogs,
  fetchAllEmails,
  runAutomatedTest,
  getTestSession,
  getTestLogs,
  getTestReports,
  getDemoStatus,
  startDemoMode,
  stopDemoMode,
  runDemoBatch,
  fetchActivityLogs,
} from "../utils/api";

const DashboardContext = createContext();

export const useDashboard = () => useContext(DashboardContext);

export const DashboardProvider = ({ children }) => {
  const [stats, setStats] = useState({
    totalEmails: 0,
    phishingDetected: 0,
    safeEmails: 0,
    accuracy: 0,
    totalThreats: 0,
    activeThreats: 0,
    resolvedThreats: 0,
    autoResolved: 0,
  });
  const [threats, setThreats] = useState([]);
  const [allEmails, setAllEmails] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [logs, setLogs] = useState([]);
  const [threatsOverTimeData, setThreatsOverTimeData] = useState([]);
  const [threatTypesData, setThreatTypesData] = useState([]);
  const [accuracyOverTimeData, setAccuracyOverTimeData] = useState([]);
  const [confusionMatrixData, setConfusionMatrixData] = useState({
    tp: 0,
    fp: 0,
    fn: 0,
    tn: 0,
  });
  const [loading, setLoading] = useState(true);

  // Testing state
  const [testRunning, setTestRunning] = useState(false);
  const [currentTestSession, setCurrentTestSession] = useState(null);
  const [testResults, setTestResults] = useState([]);
  const [testLogs, setTestLogs] = useState([]);
  const [liveThreats, setLiveThreats] = useState([]);
  const [responseActions, setResponseActions] = useState([]);
  const [testReports, setTestReports] = useState([]);

  // Demo mode state
  const [demoRunning, setDemoRunning] = useState(false);
  const [demoStats, setDemoStats] = useState(null);
  const [activityLogs, setActivityLogs] = useState([]);

  // Polling interval ref
  const pollingRef = useRef(null);

  // Load all dashboard data
  const loadData = useCallback(async () => {
    try {
      const [
        statsData,
        threatsData,
        allEmailsData,
        logsData,
        totData,
        ttData,
        aotData,
        cmData,
        activityData,
        demoStatusData,
      ] = await Promise.all([
        fetchStats(),
        fetchThreats(),
        fetchAllEmails(),
        fetchModelLogs(),
        fetchThreatsOverTime(),
        fetchThreatTypes(),
        fetchAccuracyOverTime(),
        fetchConfusionMatrix(),
        fetchActivityLogs(50),
        getDemoStatus(),
      ]);

      // Parse stats from API response
      const apiStats = statsData?.stats || statsData || {};
      setStats({
        totalEmails: apiStats.emails_scanned_today || apiStats.totalEmails || 0,
        phishingDetected:
          apiStats.total_threats || apiStats.phishingDetected || 0,
        safeEmails: apiStats.safeEmails || 0,
        accuracy: apiStats.model_accuracy || apiStats.accuracy || 97.2,
        totalThreats: apiStats.total_threats || 0,
        activeThreats: apiStats.active_threats || 0,
        resolvedThreats:
          apiStats.threats_blocked || apiStats.resolvedThreats || 0,
        autoResolved: apiStats.threats_blocked || 0,
        detectionRate: apiStats.detection_rate || 0,
      });

      setThreats(threatsData || []);
      setAllEmails(allEmailsData || []);

      // Populate liveThreats from actual threats for ThreatResponseFeed
      if (threatsData && threatsData.length > 0) {
        const threatsFeed = threatsData.slice(0, 20).map((t) => ({
          id: t.id,
          severity: t.severity || "MEDIUM",
          confidence: t.confidence || 0,
          sender: t.source || t.sender || "Unknown",
          subject: t.description || t.subject || "Suspicious email",
          detected_at: t.detected_at || t.timestamp || new Date().toISOString(),
        }));
        setLiveThreats(threatsFeed);
        
        // Generate response actions for resolved threats
        const resolvedActions = threatsData
          .filter((t) => t.status === "Resolved" || t.status === "resolved")
          .slice(0, 10)
          .map((t) => ({
            threat_id: t.id,
            action: "quarantine_email",
            actions: ["quarantine_email", "block_sender"],
            timestamp: t.detected_at || new Date().toISOString(),
            status: "completed",
          }));
        setResponseActions(resolvedActions);
      }

      // Fetch first incident details if threats exist
      if (threatsData && threatsData.length > 0) {
        try {
          const firstIncident = await fetchIncidentDetails(threatsData[0].id);
          setSelectedIncident(firstIncident);
        } catch (e) {
          console.error("Failed to fetch incident details:", e);
        }
      }

      setLogs(logsData || []);
      setThreatsOverTimeData(totData || []);
      setThreatTypesData(ttData || []);
      setAccuracyOverTimeData(aotData || []);
      setConfusionMatrixData(cmData || { tp: 0, fp: 0, fn: 0, tn: 0 });

      // Set activity logs
      setActivityLogs(activityData?.logs || []);

      // Set demo status
      if (demoStatusData) {
        setDemoRunning(demoStatusData.running || false);
        setDemoStats(demoStatusData.stats || null);
      }
    } catch (error) {
      console.error("Failed to fetch dashboard data", error);
    }
  }, []);

  // Initial load
  useEffect(() => {
    const init = async () => {
      setLoading(true);
      await loadData();
      setLoading(false);
    };
    init();
  }, [loadData]);

  // Auto-refresh data every 10 seconds when demo is running (faster refresh for real-time updates)
  useEffect(() => {
    if (demoRunning) {
      pollingRef.current = setInterval(async () => {
        await loadData();
      }, 10000); // Reduced to 10 seconds for better real-time updates
    } else if (pollingRef.current) {
      clearInterval(pollingRef.current);
    }

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
      }
    };
  }, [demoRunning, loadData]);

  // Refresh data manually
  const refreshData = useCallback(async () => {
    setLoading(true);
    await loadData();
    setLoading(false);
  }, [loadData]);

  // Refresh activity logs
  const refreshActivityLogs = useCallback(async () => {
    try {
      const data = await fetchActivityLogs(50);
      setActivityLogs(data?.logs || []);
    } catch (error) {
      console.error("Failed to refresh activity logs:", error);
    }
  }, []);

  // Start demo mode
  const startDemo = useCallback(
    async (intervalSeconds = 300) => {
      try {
        const result = await startDemoMode(intervalSeconds);
        if (result.success) {
          setDemoRunning(true);
          // Log demo start activity
          const demoStartLog = {
            event: "demo_started",
            action_type: "demo_started",
            message: `Demo mode started - processing every ${intervalSeconds} seconds`,
            timestamp: new Date().toISOString()
          };
          setActivityLogs((prev) => [demoStartLog, ...prev].slice(0, 50));
          await loadData();
        }
        return result;
      } catch (error) {
        console.error("Failed to start demo:", error);
        throw error;
      }
    },
    [loadData]
  );

  // Stop demo mode
  const stopDemo = useCallback(async () => {
    try {
      const result = await stopDemoMode();
      if (result.success) {
        setDemoRunning(false);
        // Log demo stop activity
        const demoStopLog = {
          event: "demo_stopped",
          action_type: "demo_stopped",
          message: "Demo mode stopped",
          timestamp: new Date().toISOString()
        };
        setActivityLogs((prev) => [demoStopLog, ...prev].slice(0, 50));
      }
      return result;
    } catch (error) {
      console.error("Failed to stop demo:", error);
      throw error;
    }
  }, []);

  // Run manual batch
  const runBatch = useCallback(
    async (count = 5) => {
      try {
        const result = await runDemoBatch(count);
        if (result.success) {
          // Refresh all data including activity logs
          await loadData();
          
          // Also explicitly refresh activity logs for immediate update
          await refreshActivityLogs();

          // Parse results to populate live threats and response actions
          if (result.results) {
            const newThreats = result.results
              .filter((r) => r.is_phishing || r.pipeline_results?.detection?.is_phishing)
              .map((r, i) => ({
                id: r.threat_id || r.incident_id || `demo-${Date.now()}-${i}`,
                severity: r.severity || r.pipeline_results?.detection?.severity || "MEDIUM",
                confidence: r.confidence || r.pipeline_results?.detection?.confidence || 0,
                sender: r.sender || "Unknown",
                subject: r.subject || "Demo email",
                detected_at: r.timestamp || new Date().toISOString(),
              }));
            setLiveThreats((prev) => [...newThreats, ...prev].slice(0, 20));
            
            // Extract response actions from results
            const newActions = result.results
              .filter((r) => r.is_phishing || r.pipeline_results?.detection?.is_phishing)
              .map((r) => {
                const responseData = r.pipeline_results?.response || {};
                return {
                  threat_id: r.threat_id || r.incident_id,
                  action: responseData.actions_executed?.[0] || "quarantine_email",
                  actions: r.actions_taken || ["quarantine_email", "block_sender"],
                  timestamp: r.timestamp || new Date().toISOString(),
                  status: "completed"
                };
              });
            setResponseActions((prev) => [...newActions, ...prev].slice(0, 20));
          }
        }
        return result;
      } catch (error) {
        console.error("Failed to run batch:", error);
        throw error;
      }
    },
    [loadData, refreshActivityLogs]
  );

  // Run automated test
  const runLiveTest = useCallback(async (count = 10) => {
    setTestRunning(true);
    setLiveThreats([]);
    setResponseActions([]);
    setTestResults([]);

    try {
      const result = await runAutomatedTest(count, true);

      if (result.success) {
        setCurrentTestSession(result.session_id);

        // Fetch full session details
        const sessionData = await getTestSession(result.session_id);
        if (sessionData.success && sessionData.session) {
          const session = sessionData.session;
          setTestResults(session.results || []);
          setLiveThreats(session.threats_detected || []);
          setResponseActions(session.actions_taken || []);
          setTestLogs(session.logs || []);

          // Update dashboard stats with new data
          if (session.summary) {
            setStats((prev) => ({
              ...prev,
              phishingDetected:
                prev.phishingDetected + (session.threats_detected?.length || 0),
              accuracy: session.summary.accuracy
                ? Math.round(session.summary.accuracy * 100)
                : prev.accuracy,
            }));
          }

          // Add detected threats to main threats list
          if (session.threats_detected?.length > 0) {
            const newThreats = session.threats_detected.map((t) => ({
              id: t.id,
              type: "Phishing",
              severity: t.severity,
              status: "Resolved",
              sender: t.sender,
              subject: t.subject,
              timestamp: t.detected_at,
            }));
            setThreats((prev) => [...newThreats, ...prev].slice(0, 20));
          }
        }

        // Fetch updated reports
        const reportsData = await getTestReports(5);
        setTestReports(reportsData.reports || []);
      }

      return result;
    } catch (error) {
      console.error("Test run failed:", error);
      throw error;
    } finally {
      setTestRunning(false);
    }
  }, []);

  // Refresh test logs
  const refreshTestLogs = useCallback(async () => {
    try {
      const logsData = await getTestLogs(null, null, 50);
      setTestLogs(logsData.logs || []);
    } catch (error) {
      console.error("Failed to refresh test logs:", error);
    }
  }, []);

  const value = {
    stats,
    threats,
    allEmails,
    selectedIncident,
    setSelectedIncident,
    logs,
    loading,
    threatsOverTimeData,
    threatTypesData,
    accuracyOverTimeData,
    confusionMatrixData,
    // Testing values
    testRunning,
    currentTestSession,
    testResults,
    testLogs,
    liveThreats,
    responseActions,
    testReports,
    runLiveTest,
    refreshTestLogs,
    // Demo mode values
    demoRunning,
    demoStats,
    activityLogs,
    startDemo,
    stopDemo,
    runBatch,
    refreshActivityLogs,
    refreshData,
  };

  return (
    <DashboardContext.Provider value={value}>
      {children}
    </DashboardContext.Provider>
  );
};
