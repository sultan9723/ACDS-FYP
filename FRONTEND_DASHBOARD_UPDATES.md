"""
FRONTEND DASHBOARD UPDATES: 3-Layer Ransomware Detection
=========================================================

This document describes the new frontend components and integration
for displaying 3-layer ransomware detection results.

NEW COMPONENTS
==============

1. ThreeLayerDetectionVisualization.jsx
   Location: frontend/src/components/Ransomware/
   
   Purpose: Visualizes the results of 3-layer detection analysis
   
   Features:
   - Overall verdict display (RANSOMWARE_DETECTED, SUSPICIOUS, BENIGN)
   - Confidence score and progress bar
   - Individual layer results with status indicators:
     * Layer 1: Command Behavior (ML model results)
     * Layer 2: PE Header Binary (Model ready state)
     * Layer 3: Mass-Encryption (Threat detection with indicators)
   - Detected patterns and threat indicators
   - Recommended actions
   - Backup-safe filtering status
   
   Props:
   - result: Object containing 3-layer detection result from API
   
   Example result object:
   {
     "overall_verdict": "RANSOMWARE_DETECTED",
     "detection_confidence": 0.95,
     "threat_id": "RAN-1234",
     "layers": {
       "layer1_command_behavior": {
         "status": "success",
         "is_ransomware": true,
         "confidence": 0.83,
         "detected_patterns": ["shadow_deletion"]
       },
       "layer3_mass_encryption": {
         "status": "threat_detected",
         "threat_level": "CRITICAL",
         "confidence": 1.0,
         "indicators": ["High file modification rate"]
       }
     },
     "processing_time_ms": 245
   }


2. ThreeLayerDetectionScanner.jsx
   Location: frontend/src/components/Ransomware/
   
   Purpose: Input form for running 3-layer detection analysis
   
   Features:
   - Three detection modes:
     * Layer 1 Only: Command behavior analysis
     * Layer 3 Only: Encryption monitoring
     * All 3 Layers: Full multi-layer analysis
   - Dynamic input fields based on selected mode
   - File count slider for simulating file activities
   - Result summary with verdict and layer indicators
   - Error handling and display
   
   Props:
   - onDetectionResult: Callback function triggered when analysis completes
   
   Example callback data:
   {
     "success": true,
     "result": {
       "overall_verdict": "RANSOMWARE_DETECTED",
       "detection_confidence": 0.95,
       "layers": { ... },
       "timestamp": "2026-05-06T12:34:56+00:00"
     }
   }


3. ThreeLayerDetectionDashboard.jsx
   Location: frontend/src/components/Dashboard/
   
   Purpose: Dashboard widget showing 3-layer system status and threats
   
   Features:
   - Overall system status indicator
   - Individual layer status (operational, degraded, unavailable)
   - Layer 3 feature list display
   - Threat statistics (total, critical, high, medium)
   - Recent threats table
   - Real-time status updates
   
   Usage:
   Import and include in main Dashboard:
   ```
   import ThreeLayerDetectionDashboard from "../components/Dashboard/ThreeLayerDetectionDashboard";
   
   <ThreeLayerDetectionDashboard />
   ```


UPDATED COMPONENTS
==================

1. RansomwareModule.jsx
   Updated: Added tab-based interface
   
   Changes:
   - Added two tabs: "3-Layer Scanner" and "Scan History"
   - Integrated ThreeLayerDetectionScanner component
   - Updated header to show "3-Layer Detection Active"
   - Maintained backward compatibility with RansomwareList
   
   UI Layout:
   ```
   ┌─ Header: Ransomware Detection System ─────────────────────┐
   │ Tabs: [3-Layer Scanner] [Scan History]                   │
   ├──────────────────────────────┬──────────────────────────┤
   │ Scanner/History (2/3 width)  │ Threat Details (1/3)     │
   │                              │                           │
   │ - ThreeLayerDetectionScanner │ - Visualization/Details   │
   │   or RansomwareList          │   (auto-switches based on │
   │                              │    threat type)           │
   └──────────────────────────────┴──────────────────────────┘
   ```


2. RansomwareThreatDetails.jsx
   Updated: Automatic format detection
   
   Changes:
   - Detects if threat object contains "layers" field
   - If 3-layer result: Renders ThreeLayerDetectionVisualization
   - Otherwise: Shows traditional detection results
   - Maintains full backward compatibility
   
   Detection logic:
   ```javascript
   if (threat.layers) {
     // Render 3-layer visualization
     return <ThreeLayerDetectionVisualization result={threat} />;
   }
   // Otherwise render traditional format
   ```


3. RansomwareList.jsx
   Updated: Added detection result banner
   
   Changes:
   - Displays inline result summary after scan
   - Shows verdict, severity, and confidence
   - Added incident ID for tracking
   - Maintains original history table functionality


INTEGRATION POINTS
==================

API Endpoints Used:
- POST /api/v1/ransomware/detect-layers
  Request 3-layer analysis with optional command and file activities
  
- GET /api/v1/ransomware/layers/status
  Get operational status of all 3 detection layers
  
- GET /api/v1/ransomware/list
  Fetch threat history for dashboard


DATA FLOW
=========

Scanner to Details Flow:
1. User inputs command and/or file activities in ThreeLayerDetectionScanner
2. Component calls POST /api/v1/ransomware/detect-layers
3. API returns result object with 3-layer analysis
4. onDetectionResult callback triggered → updates selectedThreat state
5. RansomwareThreatDetails component receives updated threat
6. Detects "layers" field → renders ThreeLayerDetectionVisualization
7. User sees full 3-layer analysis with visualization


STYLING & COLORS
================

Verdict Colors:
- RANSOMWARE_DETECTED: Red (bg-red-900/50, text-red-400)
- SUSPICIOUS: Yellow (bg-yellow-900/50, text-yellow-400)
- BENIGN: Green (bg-green-900/50, text-green-400)

Layer Status Colors:
- Threat Detected: Red with strong borders
- Monitoring/Ready: Green
- Error: Red
- Not Available: Gray

Confidence Progress Bar:
- Red: > 70% confidence
- Yellow: 40-70% confidence
- Green: < 40% confidence


USAGE EXAMPLES
==============

Example 1: Using 3-Layer Scanner
---------------------------------
User navigates to Ransomware Module → Clicks "3-Layer Scanner" tab
Selects "All 3 Layers" detection mode
Enters command: "cmd.exe /c vssadmin delete shadows /all"
Sets file count to 75
Clicks "Analyze with 3-Layer Detection"
Scanner calls POST /detect-layers
Results display in visualization with:
  - RANSOMWARE_DETECTED verdict (red)
  - 95% detection confidence
  - Layer 1 detected command behavior (83% confidence)
  - Layer 3 detected mass-encryption (100% confidence)
  - Detailed indicators from both layers


Example 2: Viewing Threat Details
----------------------------------
User clicks on a result in the scanner
selectedThreat updates with result object
RansomwareThreatDetails receives threat with "layers" field
Automatically renders ThreeLayerDetectionVisualization
User sees:
  - Overall verdict and confidence bar
  - Layer 1 card with detected patterns
  - Layer 2 card with model status
  - Layer 3 card with threat indicators and recommended actions


Example 3: Dashboard Overview
-----------------------------
Admin views main Dashboard page
ThreeLayerDetectionDashboard widget shows:
  - Overall system status: "OPERATIONAL"
  - Three layer cards with individual status
  - Layer 3 features list
  - Statistics: 42 total threats, 5 critical, 12 high
  - Recent threats table with top 10


TESTING THE FRONTEND
====================

1. Start FastAPI Backend:
   ```
   cd c:\Users\HP\ACDS-FYP
   python backend/main.py
   ```
   Server runs on http://localhost:8000

2. Start React Frontend (if not already running):
   ```
   cd frontend
   npm run dev
   ```
   Frontend runs on http://localhost:5173 (Vite default)

3. Open browser to frontend URL
   Navigate to Ransomware Detection module
   Click "3-Layer Scanner" tab
   Select detection mode and enter data
   Click "Analyze with 3-Layer Detection"
   View results in visualization

4. Test with different inputs:
   - Ransomware command: "vssadmin delete shadows"
   - Benign command: "notepad.exe"
   - High file count: 150+ files
   - Backup-safe activity: BackupService.exe


RESPONSIVE DESIGN
=================

Mobile/Tablet:
- Single column layout on screens < 1024px
- Scanner and history stack vertically
- Threat details move to separate view/modal
- Cards adapt to smaller screens

Desktop (1024px+):
- 3-column grid layout
- Scanner/History take 2 columns
- Threat details take 1 column
- Full visualization of all layers


PERFORMANCE NOTES
=================

- ThreeLayerDetectionVisualization: Pure presentational component
  No state management, uses props only
  
- ThreeLayerDetectionScanner: Manages local state for:
  - Input values
  - Detection mode
  - Loading state
  - Results display
  
- ThreeLayerDetectionDashboard: 
  Fetches data on mount and periodic refresh
  Caches results to avoid excessive API calls
  Shows loading spinner during fetch


ERROR HANDLING
==============

Network Errors:
- Display error banner in scanner
- Show error message from API response
- Maintain previous results in display
- Retry button available

API Errors:
- 503 Service Unavailable → Show "Service not available"
- 500 Server Error → Show "Detection failed, try again"
- 400 Bad Request → Show validation error
- Network timeout → Show "Connection timeout"


FUTURE ENHANCEMENTS
====================

- [ ] Real-time file activity monitoring dashboard
- [ ] Historical trend charts (threats over time)
- [ ] Layer-specific performance metrics
- [ ] Export detection results as PDF/JSON
- [ ] Custom detection mode with weighted layers
- [ ] Alert notification system for critical threats
- [ ] Integration with SOAR for automated response
- [ ] Machine learning confidence calibration UI
"""

# This is a documentation-only file
# Implementation is in: frontend/src/pages/ and frontend/src/components/
