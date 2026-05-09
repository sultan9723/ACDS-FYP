"""
Layer 3: Mass-Encryption Detection Orchestrator
UC-04 Ransomware Detection - File System Activity Analysis

This module detects ransomware by analyzing file system anomalies:
- Rapid file encryption/modification rate
- Mass file extensions changes
- Shadow copy deletion + file activity patterns
- Safe backup filtering

Part of 3-layer detection architecture:
1. Model 1: Runtime command behavior (TF-IDF + Random Forest)
2. Model 2: Static PE header detection (Gradient Boosting)
3. **Orchestrator: Mass-encryption detection (this module)**
"""

import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class ThreatLevel(Enum):
    """Threat severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class FileActivity:
    """Single file activity event"""
    timestamp: float
    path: str
    operation: str  # 'create', 'modify', 'delete', 'rename'
    extension: str
    process_pid: int
    process_name: str


@dataclass
class EncryptionAlert:
    """Alert raised by the detector"""
    timestamp: str
    threat_level: str
    confidence: float
    detected_indicators: List[str]
    affected_files_count: int
    detection_method: str
    process_name: str
    process_pid: int
    recommended_action: str
    backup_safe: bool = False


class BackupSafeFilter:
    """Identifies legitimate backup operations"""
    
    # Known backup/sync application signatures
    BACKUP_PROCESSES = {
        'vssadmin.exe',  # Volume Shadow Copy service
        'svchost.exe',   # Windows system service
        'wbadmin.exe',   # Windows Backup
        'robocopy.exe',  # File replication
        'rclone.exe',    # Cloud sync
        'rsync.exe',     # Linux/Unix backup
        'carbonite.exe', # Backup software
        'backuppc',      # BackupPC
        'bacula-fd.exe', # Bacula backup
        'veeam.exe',     # Veeam backup
        'acronis.exe',   # Acronis backup
    }
    
    # Known backup destination patterns
    BACKUP_DESTINATIONS = [
        '\\backup',
        '\\backups',
        '\\snapshot',
        '\\snapshots',
        '\\archive',
        '\\archives',
        'd:\\backup',
        'e:\\backup',
        '/mnt/backup',
        '/var/backups',
        'nas',
        'backup_share',
    ]
    
    # Legitimate operation indicators
    HIGH_READ_RATIO = 0.7  # Backups read more than write
    
    @classmethod
    def is_likely_backup(cls, 
                        activity: List[FileActivity],
                        process_name: str,
                        file_write_count: int,
                        file_read_count: int) -> bool:
        """
        Determine if activity looks like legitimate backup
        
        Args:
            activity: List of file activities
            process_name: Name of the process
            file_write_count: Total files written
            file_read_count: Total files read
            
        Returns:
            True if activity matches backup signature
        """
        # Check process name
        if process_name.lower() in cls.BACKUP_PROCESSES:
            return True
        
        # Check if backup destination is used
        destination_paths = [a.path.lower() for a in activity]
        for dest in cls.BACKUP_DESTINATIONS:
            if any(dest in path for path in destination_paths):
                return True
        
        # Check read/write ratio (backups read more)
        if file_read_count > 0:
            read_ratio = file_read_count / (file_read_count + file_write_count)
            if read_ratio >= cls.HIGH_READ_RATIO:
                return True
        
        return False


class MassEncryptionDetector:
    """
    Detects ransomware through file system anomaly analysis
    Maps to UC-04 requirements
    """
    
    def __init__(self,
                 window_size: int = 60,  # seconds
                 file_threshold: int = 100,  # files in window
                 extension_change_ratio: float = 0.7,  # % files with extension changes
                 shadow_copy_sensitivity: float = 0.8):  # confidence multiplier
        """
        Initialize detector with thresholds
        
        Args:
            window_size: Time window for analysis (seconds)
            file_threshold: Alert if N files modified in window
            extension_change_ratio: Alert if ratio of files with changed extensions
            shadow_copy_sensitivity: Boost threat level if shadow copy deletion detected
        """
        self.window_size = window_size
        self.file_threshold = file_threshold
        self.extension_change_ratio = extension_change_ratio
        self.shadow_copy_sensitivity = shadow_copy_sensitivity
        
        # Session state
        self.session_start = time.time()
        self.file_activity_history: List[FileActivity] = []
        self.original_extensions: Dict[str, str] = {}  # path -> original_ext
        self.shadow_copy_commands: List[str] = []
        
    def add_activity(self, activity: FileActivity):
        """
        Record a file activity event
        
        Args:
            activity: FileActivity event to record
        """
        self.file_activity_history.append(activity)
        
        # Track original extension
        if activity.operation == 'create':
            self.original_extensions[activity.path] = activity.extension
    
    def add_command(self, command: str):
        """
        Record a suspicious command (e.g., vssadmin delete shadows)
        
        Args:
            command: Command string from Layer 1 detection
        """
        if any(shadow_cmd in command.lower() for shadow_cmd in 
               ['vssadmin delete', 'wmic shadowcopy delete', 'wbadmin delete']):
            self.shadow_copy_commands.append(command)
    
    def get_recent_activity(self, seconds: int = None) -> List[FileActivity]:
        """
        Get file activity within the recent time window
        
        Args:
            seconds: Lookback window (defaults to self.window_size)
            
        Returns:
            List of recent FileActivity events
        """
        if seconds is None:
            seconds = self.window_size
        
        cutoff_time = time.time() - seconds
        return [a for a in self.file_activity_history if a.timestamp >= cutoff_time]
    
    def _analyze_file_modification_rate(self) -> Tuple[float, List[str]]:
        """
        Analyze rate of file modifications
        
        UC-04: "System analyzes rate of file changes/encryption"
        
        Returns:
            (confidence_score, indicators)
        """
        recent = self.get_recent_activity()
        
        if not recent:
            return 0.0, []
        
        indicators = []
        modifications = [a for a in recent if a.operation in ['modify', 'create']]
        
        if len(modifications) >= self.file_threshold:
            indicators.append(
                f"High file modification rate: {len(modifications)} files "
                f"in {self.window_size}s window"
            )
            confidence = min(1.0, len(modifications) / (self.file_threshold * 2))
            return confidence, indicators
        
        return 0.0, []
    
    def _analyze_extension_changes(self) -> Tuple[float, List[str]]:
        """
        Detect if files have been renamed/encrypted with new extensions
        
        UC-04: "Detect anomalous file encryption behavior"
        
        Returns:
            (confidence_score, indicators)
        """
        recent = self.get_recent_activity()
        
        if not recent:
            return 0.0, []
        
        indicators = []
        extensions_changed = 0
        
        for activity in recent:
            if activity.operation == 'rename' or activity.operation == 'modify':
                original_ext = self.original_extensions.get(activity.path, '')
                if original_ext and original_ext != activity.extension:
                    extensions_changed += 1
        
        if len(recent) > 0:
            change_ratio = extensions_changed / len(recent)
            
            if change_ratio >= self.extension_change_ratio:
                indicators.append(
                    f"Mass file extension changes: {extensions_changed}/{len(recent)} "
                    f"files ({change_ratio*100:.1f}%)"
                )
                return change_ratio, indicators
        
        return 0.0, []
    
    def _analyze_shadow_copy_context(self) -> Tuple[float, List[str]]:
        """
        Check if shadow copy deletion was followed by file activity
        
        Ransomware often: 1) delete shadow copies, 2) encrypt files
        
        Returns:
            (confidence_score, indicators)
        """
        if not self.shadow_copy_commands:
            return 0.0, []
        
        indicators = []
        
        # Recent shadow copy deletions?
        latest_shadow_cmd = self.shadow_copy_commands[-1]
        
        # Check if file activity followed shadow copy deletion
        recent_activity = self.get_recent_activity(seconds=300)  # 5-min window
        if len(recent_activity) > self.file_threshold * 0.5:
            indicators.append(
                "Shadow copy deletion followed by mass file modification"
            )
            confidence = 0.8 * self.shadow_copy_sensitivity
            return confidence, indicators
        
        return 0.0, []
    
    def _detect_known_ransomware_extensions(self) -> Tuple[float, List[str]]:
        """
        Check for known ransomware file extensions
        
        Returns:
            (confidence_score, indicators)
        """
        recent = self.get_recent_activity()
        
        # Known ransomware file extensions
        RANSOMWARE_EXTENSIONS = {
            '.locked', '.encrypted', '.rancrypt', '.cerber',
            '.cryptolocker', '.locky', '.zerocrypt', '.xyz',
            '.zzz', '.ttt', '.aaa', '.vvv', '.ecc', '.zzz',
            '.exx', '.vtlock', '.duvpext', '.crptxt', '.crpt',
        }
        
        indicators = []
        suspicious_extensions = 0
        
        for activity in recent:
            if activity.extension.lower() in RANSOMWARE_EXTENSIONS:
                suspicious_extensions += 1
        
        if suspicious_extensions > 0:
            indicators.append(
                f"Detected {suspicious_extensions} files with known ransomware extensions"
            )
            return min(1.0, suspicious_extensions / 10), indicators
        
        return 0.0, []
    
    def detect(self) -> Optional[EncryptionAlert]:
        """
        Perform mass-encryption detection analysis
        
        Maps to UC-04:
        - 1. System monitors file access logs
        - 2. System analyzes rate of file changes/encryption
        - 3. If mass encryption detected, System flags activity
        - 4. System triggers immediate alert to SOAR module
        
        Returns:
            EncryptionAlert if threat detected, None otherwise
        """
        recent_activity = self.get_recent_activity()
        
        if not recent_activity:
            return None
        
        # Run all detection methods
        mod_confidence, mod_indicators = self._analyze_file_modification_rate()
        ext_confidence, ext_indicators = self._analyze_extension_changes()
        shadow_confidence, shadow_indicators = self._analyze_shadow_copy_context()
        suspicious_ext_conf, suspicious_ext_ind = self._detect_known_ransomware_extensions()
        
        # Combine scores
        all_indicators = (mod_indicators + ext_indicators + 
                         shadow_indicators + suspicious_ext_ind)
        all_confidences = [
            mod_confidence, ext_confidence, 
            shadow_confidence, suspicious_ext_conf
        ]
        
        # Require at least 2 indicators or confidence > 0.7
        max_confidence = max(all_confidences)
        n_indicators = len(all_indicators)
        
        if n_indicators < 2 and max_confidence < 0.7:
            return None  # No threat detected
        
        # Determine threat level
        if max_confidence >= 0.9:
            threat_level = ThreatLevel.CRITICAL
        elif max_confidence >= 0.7:
            threat_level = ThreatLevel.HIGH
        elif max_confidence >= 0.5:
            threat_level = ThreatLevel.MEDIUM
        else:
            threat_level = ThreatLevel.LOW
        
        # Get process info from latest activity
        latest = recent_activity[-1]
        
        # Check if safe backup
        process_reads = len([a for a in recent_activity if a.operation == 'read'])
        process_writes = len([a for a in recent_activity if a.operation in ['create', 'modify']])
        is_backup_safe = BackupSafeFilter.is_likely_backup(
            recent_activity, latest.process_name, process_writes, process_reads
        )
        
        if is_backup_safe:
            # Alternative flow UC-04: Legitimate backup detected
            return None
        
        # Create alert
        alert = EncryptionAlert(
            timestamp=datetime.now().isoformat(),
            threat_level=threat_level.name,
            confidence=max_confidence,
            detected_indicators=all_indicators,
            affected_files_count=len(recent_activity),
            detection_method="Mass Encryption Rate Analysis",
            process_name=latest.process_name,
            process_pid=latest.process_pid,
            recommended_action="ISOLATE_AND_QUARANTINE" if threat_level.value >= 3 else "ALERT_SOC",
            backup_safe=is_backup_safe
        )
        
        return alert
    
    def to_soar_event(self, alert: EncryptionAlert) -> Dict:
        """
        Convert alert to SOAR event format
        
        UC-04: "System triggers immediate alert to SOAR module"
        
        Args:
            alert: EncryptionAlert to convert
            
        Returns:
            Dictionary ready for SOAR/incident management system
        """
        return {
            'event_type': 'ransomware_detection',
            'source': 'encryption_detector',
            'severity': alert.threat_level,
            'confidence': alert.confidence,
            'timestamp': alert.timestamp,
            'affected_entity': {
                'process_name': alert.process_name,
                'process_pid': alert.process_pid,
                'file_count': alert.affected_files_count,
            },
            'detection_indicators': alert.detected_indicators,
            'recommended_action': alert.recommended_action,
            'context': {
                'detection_method': alert.detection_method,
                'requires_investigation': alert.threat_level in ['HIGH', 'CRITICAL'],
            }
        }


# Example usage / testing
if __name__ == '__main__':
    detector = MassEncryptionDetector(
        window_size=60,
        file_threshold=50,
    )
    
    # Simulate ransomware activity
    print("Simulating ransomware activity detection...\n")
    
    # Add some benign activities
    for i in range(10):
        activity = FileActivity(
            timestamp=time.time(),
            path=f'C:\\Users\\Documents\\file_{i}.txt',
            operation='create',
            extension='.txt',
            process_pid=1234,
            process_name='notepad.exe'
        )
        detector.add_activity(activity)
    
    # Add suspicious activities
    current_time = time.time()
    for i in range(60):  # More than threshold
        activity = FileActivity(
            timestamp=current_time + i,
            path=f'C:\\Users\\Documents\\file_{i+100}.txt',
            operation='modify',
            extension='.locked',  # Changed extension
            process_pid=5678,
            process_name='unknown.exe'
        )
        detector.add_activity(activity)
    
    # Add shadow copy deletion command
    detector.add_command('vssadmin delete shadows /all /quiet')
    
    # Detect
    alert = detector.detect()
    
    if alert:
        print("🚨 THREAT DETECTED!\n")
        print(f"Threat Level: {alert.threat_level}")
        print(f"Confidence: {alert.confidence*100:.1f}%")
        print(f"Process: {alert.process_name} (PID: {alert.process_pid})")
        print(f"Affected Files: {alert.affected_files_count}")
        print(f"\nIndicators:")
        for ind in alert.detected_indicators:
            print(f"  - {ind}")
        print(f"\nRecommended Action: {alert.recommended_action}")
        
        # Convert to SOAR event
        soar_event = detector.to_soar_event(alert)
        print(f"\nSOAR Event:")
        print(json.dumps(soar_event, indent=2))
    else:
        print("✅ No threats detected")
