"""
ISRO Satellite Communication Protocol Analyzer
Analyzes CCSDS-compliant satellite communication protocols for security threats
Supports TM (Telemetry), TC (Telecommand), AOS, and USLP protocols
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import hashlib
import struct

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CCSDSProtocol(Enum):
    """CCSDS Protocol Types"""
    TM = "Telemetry"
    TC = "Telecommand"
    AOS = "Advanced_Orbiting_Systems"
    USLP = "Unified_Space_Data_Link"


class SecurityThreatLevel(Enum):
    """Security threat severity levels"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class CCSDSFrame:
    """CCSDS Transfer Frame structure"""
    version: int
    spacecraft_id: int
    virtual_channel_id: int
    frame_count: int
    protocol_type: CCSDSProtocol
    data_field: bytes
    timestamp: datetime
    security_header: Optional[Dict] = None
    security_trailer: Optional[Dict] = None
    authenticated: bool = False
    encrypted: bool = False


@dataclass
class SecurityAlert:
    """Security alert for satellite communication anomalies"""
    alert_id: str
    timestamp: datetime
    threat_level: SecurityThreatLevel
    protocol: CCSDSProtocol
    spacecraft_id: int
    virtual_channel: int
    alert_type: str
    description: str
    indicators: Dict
    recommended_action: str
    mission_phase: Optional[str] = None


class SatelliteCommAnalyzer:
    """
    Analyzes satellite communication protocols for security violations
    Implements CCSDS Space Data Link Security Protocol (SDLS) validation
    """
    
    def __init__(self, config: Dict):
        """
        Initialize satellite communication analyzer
        
        Args:
            config: Configuration including authorized spacecraft IDs, 
                   encryption requirements, frame rate thresholds
        """
        self.config = config
        self.authorized_spacecraft = config.get('authorized_spacecraft', [])
        self.require_encryption = config.get('require_encryption', True)
        self.require_authentication = config.get('require_authentication', True)
        self.max_frame_rate = config.get('max_frame_rate', 100)  # frames/sec
        self.replay_window = config.get('replay_window', 300)  # seconds
        
        # Track frame sequences for replay detection
        self.frame_sequences: Dict[Tuple[int, int], List[int]] = {}
        self.frame_timestamps: Dict[Tuple[int, int], List[datetime]] = {}
        
        # Security Association Index tracking
        self.valid_spi_values: Dict[int, Dict] = {}
        
        logger.info("Satellite Communication Analyzer initialized for ISRO operations")
    
    def parse_ccsds_frame(self, raw_data: bytes, protocol: CCSDSProtocol) -> Optional[CCSDSFrame]:
        """
        Parse CCSDS transfer frame from raw bytes
        
        Args:
            raw_data: Raw frame bytes
            protocol: Protocol type (TM, TC, AOS, USLP)
            
        Returns:
            CCSDSFrame object or None if parsing fails
        """
        try:
            if protocol == CCSDSProtocol.TM:
                return self._parse_tm_frame(raw_data)
            elif protocol == CCSDSProtocol.TC:
                return self._parse_tc_frame(raw_data)
            elif protocol == CCSDSProtocol.AOS:
                return self._parse_aos_frame(raw_data)
            elif protocol == CCSDSProtocol.USLP:
                return self._parse_uslp_frame(raw_data)
        except Exception as e:
            logger.error(f"Frame parsing error: {e}")
            return None
    
    def _parse_tm_frame(self, data: bytes) -> CCSDSFrame:
        """Parse Telemetry (TM) frame per CCSDS 132.0-B-3"""
        if len(data) < 6:
            raise ValueError("TM frame too short")
        
        # TM Primary Header (6 bytes)
        header = struct.unpack('>HHH', data[:6])
        version = (header[0] >> 14) & 0x03
        spacecraft_id = (header[0] >> 4) & 0x3FF
        virtual_channel_id = header[0] & 0x07
        frame_count = header[1] & 0xFF
        
        # Check for security header
        security_header = None
        data_start = 6
        if len(data) > 10:
            # Security Header starts after primary header
            spi = struct.unpack('>H', data[6:8])[0]
            if spi != 0:  # Non-zero SPI indicates security
                security_header = {'spi': spi, 'present': True}
                data_start += 4  # Security header length
        
        return CCSDSFrame(
            version=version,
            spacecraft_id=spacecraft_id,
            virtual_channel_id=virtual_channel_id,
            frame_count=frame_count,
            protocol_type=CCSDSProtocol.TM,
            data_field=data[data_start:],
            timestamp=datetime.utcnow(),
            security_header=security_header,
            authenticated=security_header is not None,
            encrypted=False  # Set based on security association
        )
    
    def _parse_tc_frame(self, data: bytes) -> CCSDSFrame:
        """Parse Telecommand (TC) frame per CCSDS 232.0-B-4"""
        if len(data) < 5:
            raise ValueError("TC frame too short")
        
        # TC Primary Header (5 bytes)
        header = struct.unpack('>HHB', data[:5])
        version = (header[0] >> 14) & 0x03
        spacecraft_id = (header[0] >> 4) & 0x3FF
        virtual_channel_id = header[0] & 0x3F
        frame_count = header[1] & 0xFF
        
        security_header = None
        data_start = 5
        if len(data) > 9:
            spi = struct.unpack('>H', data[5:7])[0]
            if spi != 0:
                security_header = {'spi': spi, 'present': True}
                data_start += 4
        
        return CCSDSFrame(
            version=version,
            spacecraft_id=spacecraft_id,
            virtual_channel_id=virtual_channel_id,
            frame_count=frame_count,
            protocol_type=CCSDSProtocol.TC,
            data_field=data[data_start:],
            timestamp=datetime.utcnow(),
            security_header=security_header,
            authenticated=security_header is not None
        )
    
    def _parse_aos_frame(self, data: bytes) -> CCSDSFrame:
        """Parse AOS frame per CCSDS 732.0-B-4"""
        # Similar structure to TM
        return self._parse_tm_frame(data)
    
    def _parse_uslp_frame(self, data: bytes) -> CCSDSFrame:
        """Parse USLP frame per CCSDS 732.1-B-2"""
        if len(data) < 7:
            raise ValueError("USLP frame too short")
        
        header = struct.unpack('>IHBB', data[:7])
        spacecraft_id = (header[0] >> 16) & 0xFFFF
        virtual_channel_id = header[0] & 0x3F
        frame_count = header[1]
        
        return CCSDSFrame(
            version=1,
            spacecraft_id=spacecraft_id,
            virtual_channel_id=virtual_channel_id,
            frame_count=frame_count,
            protocol_type=CCSDSProtocol.USLP,
            data_field=data[7:],
            timestamp=datetime.utcnow()
        )
    
    def analyze_frame(self, frame: CCSDSFrame) -> List[SecurityAlert]:
        """
        Analyze CCSDS frame for security threats
        
        Args:
            frame: Parsed CCSDS frame
            
        Returns:
            List of security alerts
        """
        alerts = []
        
        # Check unauthorized spacecraft
        if frame.spacecraft_id not in self.authorized_spacecraft:
            alerts.append(self._create_alert(
                frame=frame,
                threat_level=SecurityThreatLevel.CRITICAL,
                alert_type="UNAUTHORIZED_SPACECRAFT",
                description=f"Frame from unauthorized spacecraft ID {frame.spacecraft_id}",
                indicators={'spacecraft_id': frame.spacecraft_id},
                action="Block all communications and alert mission control"
            ))
        
        # Check missing authentication
        if self.require_authentication and not frame.authenticated:
            alerts.append(self._create_alert(
                frame=frame,
                threat_level=SecurityThreatLevel.HIGH,
                alert_type="MISSING_AUTHENTICATION",
                description="Frame lacks SDLS authentication header",
                indicators={'security_header': frame.security_header},
                action="Reject frame and enforce SDLS authentication"
            ))
        
        # Check missing encryption for TC frames
        if frame.protocol_type == CCSDSProtocol.TC and self.require_encryption and not frame.encrypted:
            alerts.append(self._create_alert(
                frame=frame,
                threat_level=SecurityThreatLevel.CRITICAL,
                alert_type="UNENCRYPTED_TELECOMMAND",
                description="Telecommand frame transmitted without encryption",
                indicators={'protocol': 'TC', 'encrypted': False},
                action="Immediately reject and investigate potential command injection"
            ))
        
        # Replay attack detection
        replay_alert = self._detect_replay_attack(frame)
        if replay_alert:
            alerts.append(replay_alert)
        
        # Frame rate anomaly detection
        rate_alert = self._detect_frame_rate_anomaly(frame)
        if rate_alert:
            alerts.append(rate_alert)
        
        # SPI validation
        if frame.security_header:
            spi_alert = self._validate_spi(frame)
            if spi_alert:
                alerts.append(spi_alert)
        
        return alerts
    
    def _detect_replay_attack(self, frame: CCSDSFrame) -> Optional[SecurityAlert]:
        """Detect replay attacks using frame sequence numbers"""
        key = (frame.spacecraft_id, frame.virtual_channel_id)
        
        if key not in self.frame_sequences:
            self.frame_sequences[key] = []
            self.frame_timestamps[key] = []
        
        # Check if frame count already seen recently
        current_time = frame.timestamp
        recent_frames = [
            (seq, ts) for seq, ts in zip(
                self.frame_sequences[key], 
                self.frame_timestamps[key]
            ) if (current_time - ts).total_seconds() < self.replay_window
        ]
        
        if frame.frame_count in [seq for seq, _ in recent_frames]:
            return self._create_alert(
                frame=frame,
                threat_level=SecurityThreatLevel.CRITICAL,
                alert_type="REPLAY_ATTACK_DETECTED",
                description=f"Duplicate frame count {frame.frame_count} within replay window",
                indicators={
                    'frame_count': frame.frame_count,
                    'replay_window': self.replay_window,
                    'previous_occurrences': len([s for s, _ in recent_frames if s == frame.frame_count])
                },
                action="Block frame and investigate potential replay attack"
            )
        
        # Update tracking
        self.frame_sequences[key].append(frame.frame_count)
        self.frame_timestamps[key].append(current_time)
        
        # Cleanup old entries
        if len(self.frame_sequences[key]) > 1000:
            self.frame_sequences[key] = self.frame_sequences[key][-500:]
            self.frame_timestamps[key] = self.frame_timestamps[key][-500:]
        
        return None
    
    def _detect_frame_rate_anomaly(self, frame: CCSDSFrame) -> Optional[SecurityAlert]:
        """Detect abnormal frame transmission rates (potential DoS)"""
        key = (frame.spacecraft_id, frame.virtual_channel_id)
        
        if key not in self.frame_timestamps:
            return None
        
        # Count frames in last second
        current_time = frame.timestamp
        recent_count = sum(
            1 for ts in self.frame_timestamps[key]
            if (current_time - ts).total_seconds() < 1.0
        )
        
        if recent_count > self.max_frame_rate:
            return self._create_alert(
                frame=frame,
                threat_level=SecurityThreatLevel.HIGH,
                alert_type="FRAME_RATE_ANOMALY",
                description=f"Abnormal frame rate: {recent_count} frames/sec (threshold: {self.max_frame_rate})",
                indicators={
                    'current_rate': recent_count,
                    'threshold': self.max_frame_rate,
                    'ratio': recent_count / self.max_frame_rate
                },
                action="Implement rate limiting and investigate potential DoS attack"
            )
        
        return None
    
    def _validate_spi(self, frame: CCSDSFrame) -> Optional[SecurityAlert]:
        """Validate Security Parameter Index"""
        if not frame.security_header:
            return None
        
        spi = frame.security_header.get('spi')
        
        # Check if SPI is registered
        if spi not in self.valid_spi_values:
            return self._create_alert(
                frame=frame,
                threat_level=SecurityThreatLevel.HIGH,
                alert_type="INVALID_SPI",
                description=f"Unknown Security Parameter Index: {spi}",
                indicators={'spi': spi, 'registered_spis': list(self.valid_spi_values.keys())},
                action="Reject frame and verify security association configuration"
            )
        
        return None
    
    def _create_alert(
        self,
        frame: CCSDSFrame,
        threat_level: SecurityThreatLevel,
        alert_type: str,
        description: str,
        indicators: Dict,
        action: str
    ) -> SecurityAlert:
        """Create standardized security alert"""
        alert_id = hashlib.sha256(
            f"{frame.timestamp}{alert_type}{frame.spacecraft_id}".encode()
        ).hexdigest()[:16]
        
        return SecurityAlert(
            alert_id=alert_id,
            timestamp=frame.timestamp,
            threat_level=threat_level,
            protocol=frame.protocol_type,
            spacecraft_id=frame.spacecraft_id,
            virtual_channel=frame.virtual_channel_id,
            alert_type=alert_type,
            description=description,
            indicators=indicators,
            recommended_action=action
        )
    
    def register_security_association(self, spi: int, sa_config: Dict):
        """Register valid Security Association"""
        self.valid_spi_values[spi] = sa_config
        logger.info(f"Registered Security Association: SPI={spi}")
    
    def export_alerts(self, alerts: List[SecurityAlert], format: str = 'json') -> str:
        """Export alerts in specified format for SIEM integration"""
        if format == 'json':
            return json.dumps([
                {
                    'alert_id': alert.alert_id,
                    'timestamp': alert.timestamp.isoformat(),
                    'severity': alert.threat_level.name,
                    'severity_score': alert.threat_level.value,
                    'protocol': alert.protocol.value,
                    'spacecraft_id': alert.spacecraft_id,
                    'virtual_channel': alert.virtual_channel,
                    'type': alert.alert_type,
                    'description': alert.description,
                    'indicators': alert.indicators,
                    'recommended_action': alert.recommended_action,
                    'mission_phase': alert.mission_phase
                }
                for alert in alerts
            ], indent=2)
        return str(alerts)


# Example usage for ISRO missions
if __name__ == "__main__":
    # Configuration for ISRO satellite network
    config = {
        'authorized_spacecraft': [101, 102, 103, 201, 202],  # ISRO spacecraft IDs
        'require_encryption': True,
        'require_authentication': True,
        'max_frame_rate': 50,
        'replay_window': 300
    }
    
    analyzer = SatelliteCommAnalyzer(config)
    
    # Register ISRO Security Associations
    analyzer.register_security_association(1, {
        'algorithm': 'AES-256-GCM',
        'auth_mode': 'GMAC',
        'key_length': 256
    })
    
    # Simulate frame analysis
    test_frame_data = b'\x00\x65\x40\x00\x01\x23' + b'\x00' * 100
    frame = analyzer.parse_ccsds_frame(test_frame_data, CCSDSProtocol.TM)
    
    if frame:
        alerts = analyzer.analyze_frame(frame)
        print(analyzer.export_alerts(alerts))
