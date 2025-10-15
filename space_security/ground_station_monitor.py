"""
ISRO Ground Station Security Monitor
Monitors ground station infrastructure for security threats
Tracks RF interference, network intrusions, and access control violations
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum
import ipaddress
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GroundStationType(Enum):
    """ISRO Ground Station Types"""
    MOC = "Mission_Operations_Center"
    ISTRAC = "ISRO_Telemetry_Tracking_Command_Network"
    LAUNCH = "Launch_Control_Center"
    BACKUP = "Backup_Ground_Station"


class RFThreatType(Enum):
    """RF Security Threat Types"""
    JAMMING = "RF_Jamming"
    SPOOFING = "Signal_Spoofing"
    INTERFERENCE = "Interference"
    EAVESDROPPING = "Eavesdropping"
    UNAUTHORIZED_TRANSMISSION = "Unauthorized_TX"


@dataclass
class GroundStation:
    """Ground station configuration"""
    station_id: str
    station_name: str
    station_type: GroundStationType
    location: Dict[str, float]  # lat, lon, alt
    authorized_frequencies: List[Tuple[float, float]]  # MHz ranges
    authorized_ip_ranges: List[str]  # CIDR notation
    authorized_personnel: Set[str]
    security_clearance_level: int
    
@dataclass
class RFSecurityEvent:
    """RF security event detection"""
    event_id: str
    timestamp: datetime
    station_id: str
    threat_type: RFThreatType
    frequency_mhz: float
    power_dbm: float
    duration_seconds: float
    azimuth: Optional[float]
    elevation: Optional[float]
    description: str
    confidence_score: float
    geolocation: Optional[Dict]


@dataclass
class AccessControlViolation:
    """Access control violation event"""
    violation_id: str
    timestamp: datetime
    station_id: str
    user_id: str
    source_ip: str
    attempted_action: str
    reason: str
    severity: str


class GroundStationMonitor:
    """
    Monitors ISRO ground station security across multiple sites
    Implements security controls for TT&C operations
    """
    
    def __init__(self, stations: List[GroundStation]):
        """
        Initialize ground station monitor
        
        Args:
            stations: List of GroundStation configurations
        """
        self.stations = {s.station_id: s for s in stations}
        self.rf_baseline: Dict[str, Dict] = {}
        self.access_logs: Dict[str, List] = {}
        self.active_sessions: Dict[str, Dict] = {}
        
        # RF interference detection parameters
        self.jamming_threshold_db = 10.0  # dB above baseline
        self.interference_duration_threshold = 5.0  # seconds
        
        logger.info(f"Ground Station Monitor initialized for {len(stations)} ISRO stations")
    
    def establish_rf_baseline(self, station_id: str, frequency_scan: Dict[float, float]):
        """
        Establish baseline RF environment for ground station
        
        Args:
            station_id: Ground station identifier
            frequency_scan: Dict mapping frequency (MHz) to power (dBm)
        """
        if station_id not in self.stations:
            logger.error(f"Unknown station: {station_id}")
            return
        
        self.rf_baseline[station_id] = {
            'frequencies': frequency_scan,
            'timestamp': datetime.utcnow(),
            'mean_power': sum(frequency_scan.values()) / len(frequency_scan),
            'max_power': max(frequency_scan.values())
        }
        
        logger.info(f"RF baseline established for {station_id}")
    
    def analyze_rf_spectrum(
        self,
        station_id: str,
        current_scan: Dict[float, float],
        antenna_pointing: Optional[Dict] = None
    ) -> List[RFSecurityEvent]:
        """
        Analyze RF spectrum for security threats
        
        Args:
            station_id: Ground station identifier
            current_scan: Current frequency scan results
            antenna_pointing: Optional antenna azimuth/elevation
            
        Returns:
            List of detected RF security events
        """
        events = []
        
        if station_id not in self.rf_baseline:
            logger.warning(f"No RF baseline for {station_id}, establishing now")
            self.establish_rf_baseline(station_id, current_scan)
            return events
        
        station = self.stations[station_id]
        baseline = self.rf_baseline[station_id]
        
        # Check each frequency
        for freq_mhz, power_dbm in current_scan.items():
            baseline_power = baseline['frequencies'].get(freq_mhz, baseline['mean_power'])
            power_delta = power_dbm - baseline_power
            
            # Jamming detection - significant power increase
            if power_delta > self.jamming_threshold_db:
                # Check if frequency is authorized
                in_authorized_band = any(
                    low <= freq_mhz <= high
                    for low, high in station.authorized_frequencies
                )
                
                threat_type = RFThreatType.JAMMING if in_authorized_band else RFThreatType.INTERFERENCE
                
                events.append(RFSecurityEvent(
                    event_id=f"RF-{station_id}-{int(freq_mhz)}-{int(datetime.utcnow().timestamp())}",
                    timestamp=datetime.utcnow(),
                    station_id=station_id,
                    threat_type=threat_type,
                    frequency_mhz=freq_mhz,
                    power_dbm=power_dbm,
                    duration_seconds=0.0,  # Updated by correlation
                    azimuth=antenna_pointing.get('azimuth') if antenna_pointing else None,
                    elevation=antenna_pointing.get('elevation') if antenna_pointing else None,
                    description=f"{threat_type.value} detected: {power_delta:.1f} dB above baseline",
                    confidence_score=min(power_delta / 20.0, 1.0),
                    geolocation=None
                ))
            
            # Unauthorized transmission detection
            if not any(low <= freq_mhz <= high for low, high in station.authorized_frequencies):
                if power_dbm > -80:  # Significant power on unauthorized frequency
                    events.append(RFSecurityEvent(
                        event_id=f"RF-UNAUTH-{station_id}-{int(freq_mhz)}-{int(datetime.utcnow().timestamp())}",
                        timestamp=datetime.utcnow(),
                        station_id=station_id,
                        threat_type=RFThreatType.UNAUTHORIZED_TRANSMISSION,
                        frequency_mhz=freq_mhz,
                        power_dbm=power_dbm,
                        duration_seconds=0.0,
                        azimuth=antenna_pointing.get('azimuth') if antenna_pointing else None,
                        elevation=antenna_pointing.get('elevation') if antenna_pointing else None,
                        description=f"Unauthorized transmission on {freq_mhz} MHz",
                        confidence_score=0.8,
                        geolocation=None
                    ))
        
        return events
    
    def detect_signal_spoofing(
        self,
        station_id: str,
        received_signal: Dict,
        expected_signal: Dict
    ) -> Optional[RFSecurityEvent]:
        """
        Detect GNSS/timing signal spoofing attempts
        
        Args:
            station_id: Ground station identifier
            received_signal: Received signal characteristics
            expected_signal: Expected signal characteristics
            
        Returns:
            RF security event if spoofing detected
        """
        # Check signal characteristics mismatch
        time_offset = abs(
            received_signal.get('timestamp', 0) - expected_signal.get('timestamp', 0)
        )
        
        power_delta = abs(
            received_signal.get('power_dbm', 0) - expected_signal.get('power_dbm', 0)
        )
        
        frequency_offset = abs(
            received_signal.get('frequency', 0) - expected_signal.get('frequency', 0)
        )
        
        # Spoofing indicators
        spoofing_score = 0.0
        if time_offset > 1e-3:  # > 1ms time offset
            spoofing_score += 0.4
        if power_delta > 5.0:  # > 5dB power difference
            spoofing_score += 0.3
        if frequency_offset > 1.0:  # > 1Hz frequency offset
            spoofing_score += 0.3
        
        if spoofing_score > 0.5:
            return RFSecurityEvent(
                event_id=f"SPOOF-{station_id}-{int(datetime.utcnow().timestamp())}",
                timestamp=datetime.utcnow(),
                station_id=station_id,
                threat_type=RFThreatType.SPOOFING,
                frequency_mhz=received_signal.get('frequency', 0),
                power_dbm=received_signal.get('power_dbm', 0),
                duration_seconds=0.0,
                azimuth=None,
                elevation=None,
                description=f"Potential spoofing: time_offset={time_offset:.3f}s, power_delta={power_delta:.1f}dB",
                confidence_score=spoofing_score,
                geolocation=None
            )
        
        return None
    
    def validate_access_control(
        self,
        station_id: str,
        user_id: str,
        source_ip: str,
        requested_action: str,
        required_clearance: int
    ) -> Optional[AccessControlViolation]:
        """
        Validate access control for ground station operations
        
        Args:
            station_id: Ground station identifier
            user_id: User attempting access
            source_ip: Source IP address
            requested_action: Action being attempted
            required_clearance: Required security clearance level
            
        Returns:
            AccessControlViolation if access denied
        """
        if station_id not in self.stations:
            return AccessControlViolation(
                violation_id=f"AC-{station_id}-{int(datetime.utcnow().timestamp())}",
                timestamp=datetime.utcnow(),
                station_id=station_id,
                user_id=user_id,
                source_ip=source_ip,
                attempted_action=requested_action,
                reason="Unknown ground station",
                severity="HIGH"
            )
        
        station = self.stations[station_id]
        violations = []
        
        # Check user authorization
        if user_id not in station.authorized_personnel:
            return AccessControlViolation(
                violation_id=f"AC-USER-{station_id}-{int(datetime.utcnow().timestamp())}",
                timestamp=datetime.utcnow(),
                station_id=station_id,
                user_id=user_id,
                source_ip=source_ip,
                attempted_action=requested_action,
                reason=f"User {user_id} not authorized for {station.station_name}",
                severity="CRITICAL"
            )
        
        # Check IP authorization
        try:
            source_addr = ipaddress.ip_address(source_ip)
            authorized = any(
                source_addr in ipaddress.ip_network(ip_range)
                for ip_range in station.authorized_ip_ranges
            )
            
            if not authorized:
                return AccessControlViolation(
                    violation_id=f"AC-IP-{station_id}-{int(datetime.utcnow().timestamp())}",
                    timestamp=datetime.utcnow(),
                    station_id=station_id,
                    user_id=user_id,
                    source_ip=source_ip,
                    attempted_action=requested_action,
                    reason=f"Unauthorized IP: {source_ip} not in approved ranges",
                    severity="HIGH"
                )
        except ValueError:
            logger.error(f"Invalid IP address: {source_ip}")
        
        # Check security clearance
        if required_clearance > station.security_clearance_level:
            return AccessControlViolation(
                violation_id=f"AC-CLEARANCE-{station_id}-{int(datetime.utcnow().timestamp())}",
                timestamp=datetime.utcnow(),
                station_id=station_id,
                user_id=user_id,
                source_ip=source_ip,
                attempted_action=requested_action,
                reason=f"Insufficient clearance: requires level {required_clearance}",
                severity="HIGH"
            )
        
        return None
    
    def monitor_multi_site_coordination(self) -> List[Dict]:
        """
        Monitor coordination between multiple ISRO ground stations
        Detect anomalies in handover procedures
        
        Returns:
            List of coordination anomalies
        """
        anomalies = []
        current_time = datetime.utcnow()
        
        # Check for simultaneous TT&C operations (should be coordinated)
        active_stations = [
            sid for sid, sessions in self.active_sessions.items()
            if sessions.get('ttc_active', False)
        ]
        
        if len(active_stations) > 1:
            # Multiple stations operating simultaneously - verify coordination
            anomalies.append({
                'type': 'MULTI_SITE_TTC_ACTIVE',
                'timestamp': current_time.isoformat(),
                'stations': active_stations,
                'severity': 'MEDIUM',
                'description': 'Multiple ground stations performing TT&C operations',
                'action': 'Verify handover coordination and prevent signal conflicts'
            })
        
        return anomalies
    
    def export_security_events(
        self,
        rf_events: List[RFSecurityEvent],
        access_violations: List[AccessControlViolation],
        format: str = 'json'
    ) -> str:
        """Export security events for SIEM integration"""
        if format == 'json':
            output = {
                'rf_security_events': [
                    {
                        'event_id': event.event_id,
                        'timestamp': event.timestamp.isoformat(),
                        'station_id': event.station_id,
                        'threat_type': event.threat_type.value,
                        'frequency_mhz': event.frequency_mhz,
                        'power_dbm': event.power_dbm,
                        'duration_seconds': event.duration_seconds,
                        'azimuth': event.azimuth,
                        'elevation': event.elevation,
                        'description': event.description,
                        'confidence': event.confidence_score
                    }
                    for event in rf_events
                ],
                'access_control_violations': [
                    {
                        'violation_id': v.violation_id,
                        'timestamp': v.timestamp.isoformat(),
                        'station_id': v.station_id,
                        'user_id': v.user_id,
                        'source_ip': v.source_ip,
                        'attempted_action': v.attempted_action,
                        'reason': v.reason,
                        'severity': v.severity
                    }
                    for v in access_violations
                ]
            }
            return json.dumps(output, indent=2)
        
        return f"RF Events: {len(rf_events)}, Access Violations: {len(access_violations)}"


# Example usage for ISRO ground station network
if __name__ == "__main__":
    # Configure ISRO ground stations
    stations = [
        GroundStation(
            station_id="ISRO-SHAR",
            station_name="Sriharikota Ground Station",
            station_type=GroundStationType.LAUNCH,
            location={'lat': 13.72, 'lon': 80.23, 'alt': 10.0},
            authorized_frequencies=[(2025.0, 2120.0), (2200.0, 2300.0)],
            authorized_ip_ranges=["10.1.0.0/16", "192.168.100.0/24"],
            authorized_personnel={"user001", "user002", "user003"},
            security_clearance_level=4
        ),
        GroundStation(
            station_id="ISRO-ISTRAC-BLR",
            station_name="ISTRAC Bangalore",
            station_type=GroundStationType.ISTRAC,
            location={'lat': 12.97, 'lon': 77.59, 'alt': 920.0},
            authorized_frequencies=[(2025.0, 2120.0), (8025.0, 8400.0)],
            authorized_ip_ranges=["10.2.0.0/16"],
            authorized_personnel={"user004", "user005"},
            security_clearance_level=5
        )
    ]
    
    monitor = GroundStationMonitor(stations)
    
    # Establish RF baseline
    baseline_scan = {2050.0: -85.0, 2100.0: -90.0, 2200.0: -88.0}
    monitor.establish_rf_baseline("ISRO-SHAR", baseline_scan)
    
    # Simulate RF threat detection
    current_scan = {2050.0: -70.0, 2100.0: -88.0, 2200.0: -89.0}  # Jamming on 2050 MHz
    rf_events = monitor.analyze_rf_spectrum("ISRO-SHAR", current_scan)
    
    # Test access control
    violation = monitor.validate_access_control(
        station_id="ISRO-SHAR",
        user_id="unauthorized_user",
        source_ip="203.45.67.89",
        requested_action="SEND_TELECOMMAND",
        required_clearance=3
    )
    
    violations = [violation] if violation else []
    print(monitor.export_security_events(rf_events, violations))
