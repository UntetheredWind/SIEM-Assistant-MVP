"""
ISRO Mission Timeline Security Correlator
Correlates security events with mission phases and orbital mechanics
Identifies phase-specific security threats and anomalous behavior
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import math

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MissionPhase(Enum):
    """Space mission phases"""
    PRE_LAUNCH = "Pre_Launch"
    LAUNCH = "Launch"
    LEOP = "Launch_Early_Orbit_Phase"
    COMMISSIONING = "Commissioning"
    NOMINAL_OPERATIONS = "Nominal_Operations"
    MANEUVER = "Orbital_Maneuver"
    ECLIPSE = "Eclipse_Period"
    MAINTENANCE = "Maintenance"
    DEORBIT = "Deorbit"
    END_OF_LIFE = "End_Of_Life"


class OrbitType(Enum):
    """Orbital regime types"""
    LEO = "Low_Earth_Orbit"
    MEO = "Medium_Earth_Orbit"
    GEO = "Geostationary_Orbit"
    GTO = "Geostationary_Transfer_Orbit"
    SSO = "Sun_Synchronous_Orbit"
    HEEO = "Highly_Elliptical_Earth_Orbit"
    LUNAR = "Lunar_Orbit"
    INTERPLANETARY = "Interplanetary"


@dataclass
class OrbitalParameters:
    """Satellite orbital parameters"""
    semi_major_axis_km: float
    eccentricity: float
    inclination_deg: float
    raan_deg: float  # Right Ascension of Ascending Node
    argument_of_perigee_deg: float
    true_anomaly_deg: float
    epoch: datetime


@dataclass
class MissionTimeline:
    """Mission timeline configuration"""
    mission_id: str
    spacecraft_id: int
    launch_date: datetime
    current_phase: MissionPhase
    orbit_type: OrbitType
    orbital_params: OrbitalParameters
    critical_events: List[Dict]  # Scheduled events
    ground_contact_windows: List[Tuple[datetime, datetime]]


@dataclass
class PhaseSecurityProfile:
    """Security profile for mission phase"""
    phase: MissionPhase
    expected_ttc_rate: Tuple[float, float]  # Min, max frames/sec
    expected_telemetry_rate: Tuple[float, float]  # Min, max Mbps
    critical_commands: List[str]
    allowed_ground_stations: List[str]
    heightened_monitoring: bool
    alert_escalation_level: int


@dataclass
class SecurityCorrelation:
    """Correlated security event with mission context"""
    correlation_id: str
    timestamp: datetime
    mission_id: str
    mission_phase: MissionPhase
    orbital_position: Dict
    security_events: List[Dict]
    mission_context: Dict
    risk_score: float
    correlation_confidence: float
    actionable_intelligence: str


class MissionTimelineCorrelator:
    """
    Correlates security events with mission timeline and orbital mechanics
    Provides mission-aware security analysis for ISRO operations
    """
    
    def __init__(self, missions: List[MissionTimeline]):
        """
        Initialize mission timeline correlator
        
        Args:
            missions: List of active mission timelines
        """
        self.missions = {m.mission_id: m for m in missions}
        self.phase_profiles: Dict[MissionPhase, PhaseSecurityProfile] = self._initialize_phase_profiles()
        self.security_event_history: Dict[str, List] = {}
        self.correlation_rules: List[Dict] = self._initialize_correlation_rules()
        
        # Orbital mechanics constants
        self.EARTH_MU = 398600.4418  # km^3/s^2
        self.EARTH_RADIUS = 6371.0  # km
        
        logger.info(f"Mission Timeline Correlator initialized for {len(missions)} missions")
    
    def _initialize_phase_profiles(self) -> Dict[MissionPhase, PhaseSecurityProfile]:
        """Initialize security profiles for each mission phase"""
        return {
            MissionPhase.PRE_LAUNCH: PhaseSecurityProfile(
                phase=MissionPhase.PRE_LAUNCH,
                expected_ttc_rate=(0.0, 0.1),
                expected_telemetry_rate=(0.0, 0.01),
                critical_commands=["SYSTEM_TEST", "PRE_FLIGHT_CHECK"],
                allowed_ground_stations=["SHAR", "ISTRAC-BLR"],
                heightened_monitoring=True,
                alert_escalation_level=5
            ),
            MissionPhase.LAUNCH: PhaseSecurityProfile(
                phase=MissionPhase.LAUNCH,
                expected_ttc_rate=(10.0, 100.0),
                expected_telemetry_rate=(0.5, 5.0),
                critical_commands=["ABORT", "STAGE_SEPARATION", "PAYLOAD_FAIRING_JETTISON"],
                allowed_ground_stations=["SHAR", "ISTRAC-BLR"],
                heightened_monitoring=True,
                alert_escalation_level=5
            ),
            MissionPhase.LEOP: PhaseSecurityProfile(
                phase=MissionPhase.LEOP,
                expected_ttc_rate=(5.0, 50.0),
                expected_telemetry_rate=(0.2, 2.0),
                critical_commands=["SOLAR_PANEL_DEPLOY", "ANTENNA_DEPLOY", "ATTITUDE_CONTROL"],
                allowed_ground_stations=["SHAR", "ISTRAC-BLR", "ISTRAC-LKO"],
                heightened_monitoring=True,
                alert_escalation_level=4
            ),
            MissionPhase.NOMINAL_OPERATIONS: PhaseSecurityProfile(
                phase=MissionPhase.NOMINAL_OPERATIONS,
                expected_ttc_rate=(1.0, 10.0),
                expected_telemetry_rate=(0.1, 1.0),
                critical_commands=["PAYLOAD_OPERATION", "ORBIT_ADJUST"],
                allowed_ground_stations=["SHAR", "ISTRAC-BLR", "ISTRAC-LKO", "ISTRAC-POR"],
                heightened_monitoring=False,
                alert_escalation_level=2
            ),
            MissionPhase.MANEUVER: PhaseSecurityProfile(
                phase=MissionPhase.MANEUVER,
                expected_ttc_rate=(2.0, 20.0),
                expected_telemetry_rate=(0.2, 1.5),
                critical_commands=["THRUSTER_FIRE", "ORBIT_CORRECTION", "ATTITUDE_MANEUVER"],
                allowed_ground_stations=["SHAR", "ISTRAC-BLR"],
                heightened_monitoring=True,
                alert_escalation_level=4
            )
        }
    
    def _initialize_correlation_rules(self) -> List[Dict]:
        """Initialize security correlation rules"""
        return [
            {
                'rule_id': 'LAUNCH_JAMMING',
                'conditions': {
                    'phase': [MissionPhase.LAUNCH, MissionPhase.LEOP],
                    'event_types': ['RF_JAMMING', 'INTERFERENCE']
                },
                'risk_multiplier': 5.0,
                'description': 'RF interference during critical launch/LEOP phase'
            },
            {
                'rule_id': 'MANEUVER_UNAUTHORIZED_CMD',
                'conditions': {
                    'phase': [MissionPhase.MANEUVER],
                    'event_types': ['UNENCRYPTED_TELECOMMAND', 'UNAUTHORIZED_SPACECRAFT']
                },
                'risk_multiplier': 4.5,
                'description': 'Unauthorized commands during orbital maneuver'
            },
            {
                'rule_id': 'GROUND_CONTACT_SPOOFING',
                'conditions': {
                    'during_contact_window': True,
                    'event_types': ['SIGNAL_SPOOFING', 'REPLAY_ATTACK_DETECTED']
                },
                'risk_multiplier': 3.5,
                'description': 'Signal spoofing during ground contact window'
            },
            {
                'rule_id': 'ECLIPSE_ANOMALY',
                'conditions': {
                    'phase': [MissionPhase.ECLIPSE],
                    'event_types': ['FRAME_RATE_ANOMALY', 'MISSING_AUTHENTICATION']
                },
                'risk_multiplier': 3.0,
                'description': 'Security anomalies during eclipse (power-constrained phase)'
            }
        ]
    
    def calculate_orbital_position(
        self,
        mission_id: str,
        timestamp: datetime
    ) -> Optional[Dict]:
        """
        Calculate satellite orbital position at given time
        Simplified two-body problem solution
        
        Args:
            mission_id: Mission identifier
            timestamp: Time for position calculation
            
        Returns:
            Dictionary with orbital position details
        """
        if mission_id not in self.missions:
            return None
        
        mission = self.missions[mission_id]
        params = mission.orbital_params
        
        # Calculate time since epoch
        dt = (timestamp - params.epoch).total_seconds()
        
        # Calculate mean motion (rad/s)
        a = params.semi_major_axis_km
        n = math.sqrt(self.EARTH_MU / (a ** 3))
        
        # Calculate mean anomaly
        M = math.radians(params.true_anomaly_deg) + n * dt
        
        # Solve Kepler's equation for eccentric anomaly (simplified)
        E = M  # For low eccentricity
        for _ in range(5):  # Newton-Raphson iteration
            E = M + params.eccentricity * math.sin(E)
        
        # Calculate true anomaly
        true_anomaly = 2 * math.atan2(
            math.sqrt(1 + params.eccentricity) * math.sin(E / 2),
            math.sqrt(1 - params.eccentricity) * math.cos(E / 2)
        )
        
        # Calculate position in orbit
        r = a * (1 - params.eccentricity * math.cos(E))
        
        # Calculate altitude
        altitude_km = r - self.EARTH_RADIUS
        
        return {
            'timestamp': timestamp.isoformat(),
            'altitude_km': altitude_km,
            'true_anomaly_deg': math.degrees(true_anomaly),
            'orbit_period_minutes': 2 * math.pi / n / 60,
            'ground_track_velocity_km_s': math.sqrt(self.EARTH_MU / r)
        }
    
    def is_in_ground_contact_window(
        self,
        mission_id: str,
        timestamp: datetime
    ) -> Tuple[bool, Optional[Tuple[datetime, datetime]]]:
        """
        Check if satellite is in ground contact window
        
        Args:
            mission_id: Mission identifier
            timestamp: Time to check
            
        Returns:
            Tuple of (in_window, window_details)
        """
        if mission_id not in self.missions:
            return False, None
        
        mission = self.missions[mission_id]
        
        for start, end in mission.ground_contact_windows:
            if start <= timestamp <= end:
                return True, (start, end)
        
        return False, None
    
    def is_in_eclipse(
        self,
        mission_id: str,
        timestamp: datetime
    ) -> bool:
        """
        Determine if satellite is in Earth's shadow (eclipse)
        Simplified calculation
        
        Args:
            mission_id: Mission identifier
            timestamp: Time to check
            
        Returns:
            True if in eclipse
        """
        position = self.calculate_orbital_position(mission_id, timestamp)
        if not position:
            return False
        
        # Simplified: assume eclipse based on orbital position
        # In reality, requires sun position calculation
        true_anomaly = position['true_anomaly_deg']
        
        # Rough approximation: eclipse around 180° true anomaly
        return 150 <= true_anomaly <= 210
    
    def correlate_security_events(
        self,
        mission_id: str,
        security_events: List[Dict],
        timestamp: datetime
    ) -> Optional[SecurityCorrelation]:
        """
        Correlate security events with mission timeline and orbital context
        
        Args:
            mission_id: Mission identifier
            security_events: List of security events to correlate
            timestamp: Correlation timestamp
            
        Returns:
            SecurityCorrelation object with mission-aware analysis
        """
        if mission_id not in self.missions:
            logger.error(f"Unknown mission: {mission_id}")
            return None
        
        mission = self.missions[mission_id]
        
        # Get mission context
        orbital_position = self.calculate_orbital_position(mission_id, timestamp)
        in_contact, contact_window = self.is_in_ground_contact_window(mission_id, timestamp)
        in_eclipse = self.is_in_eclipse(mission_id, timestamp)
        
        # Get phase security profile
        phase_profile = self.phase_profiles.get(mission.current_phase)
        
        # Calculate base risk score
        base_risk = sum(event.get('severity_score', 0) for event in security_events) / len(security_events)
        
        # Apply correlation rules
        risk_multiplier = 1.0
        matched_rules = []
        
        for rule in self.correlation_rules:
            conditions = rule['conditions']
            
            # Check phase match
            if 'phase' in conditions:
                if mission.current_phase not in conditions['phase']:
                    continue
            
            # Check event type match
            if 'event_types' in conditions:
                event_types = [e.get('type') for e in security_events]
                if not any(et in event_types for et in conditions['event_types']):
                    continue
            
            # Check contact window condition
            if conditions.get('during_contact_window'):
                if not in_contact:
                    continue
            
            # Rule matched
            matched_rules.append(rule)
            risk_multiplier = max(risk_multiplier, rule['risk_multiplier'])
        
        # Calculate final risk score
        final_risk = min(base_risk * risk_multiplier * phase_profile.alert_escalation_level, 100.0)
        
        # Generate actionable intelligence
        intelligence = self._generate_intelligence(
            mission, security_events, matched_rules,
            orbital_position, in_contact, in_eclipse
        )
        
        correlation = SecurityCorrelation(
            correlation_id=f"CORR-{mission_id}-{int(timestamp.timestamp())}",
            timestamp=timestamp,
            mission_id=mission_id,
            mission_phase=mission.current_phase,
            orbital_position=orbital_position or {},
            security_events=security_events,
            mission_context={
                'orbit_type': mission.orbit_type.value,
                'in_ground_contact': in_contact,
                'contact_window': f"{contact_window[0].isoformat()} - {contact_window[1].isoformat()}" if contact_window else None,
                'in_eclipse': in_eclipse,
                'phase_criticality': phase_profile.alert_escalation_level
            },
            risk_score=final_risk,
            correlation_confidence=0.85 if matched_rules else 0.60,
            actionable_intelligence=intelligence
        )
        
        return correlation
    
    def _generate_intelligence(
        self,
        mission: MissionTimeline,
        events: List[Dict],
        matched_rules: List[Dict],
        orbital_pos: Optional[Dict],
        in_contact: bool,
        in_eclipse: bool
    ) -> str:
        """Generate actionable intelligence from correlation"""
        intelligence = []
        
        # Phase-specific guidance
        phase = mission.current_phase
        intelligence.append(f"Mission {mission.mission_id} in {phase.value} phase")
        
        if matched_rules:
            intelligence.append(f"CRITICAL: {len(matched_rules)} high-risk correlation(s) detected:")
            for rule in matched_rules:
                intelligence.append(f"  - {rule['description']}")
        
        # Orbital context
        if orbital_pos:
            intelligence.append(f"Orbital altitude: {orbital_pos['altitude_km']:.1f} km")
        
        if in_contact:
            intelligence.append("During ground contact window - verify ground station security")
        
        if in_eclipse:
            intelligence.append("In eclipse period - power-constrained operations")
        
        # Recommended actions
        if phase in [MissionPhase.LAUNCH, MissionPhase.LEOP]:
            intelligence.append("IMMEDIATE ACTION: Notify Mission Director and implement contingency procedures")
        
        critical_events = [e for e in events if e.get('severity') in ['CRITICAL', 'HIGH']]
        if critical_events:
            intelligence.append(f"{len(critical_events)} critical events require immediate response")
        
        return " | ".join(intelligence)
    
    def export_correlation(self, correlation: SecurityCorrelation, format: str = 'json') -> str:
        """Export correlation analysis for SIEM integration"""
        if format == 'json':
            return json.dumps({
                'correlation_id': correlation.correlation_id,
                'timestamp': correlation.timestamp.isoformat(),
                'mission_id': correlation.mission_id,
                'mission_phase': correlation.mission_phase.value,
                'orbital_position': correlation.orbital_position,
                'security_event_count': len(correlation.security_events),
                'security_events': correlation.security_events,
                'mission_context': correlation.mission_context,
                'risk_score': correlation.risk_score,
                'confidence': correlation.correlation_confidence,
                'intelligence': correlation.actionable_intelligence
            }, indent=2)
        
        return str(correlation)


# Example usage for ISRO missions
if __name__ == "__main__":
    # Configure ISRO mission
    chandrayaan_orbit = OrbitalParameters(
        semi_major_axis_km=6971.0,  # ~600 km altitude
        eccentricity=0.001,
        inclination_deg=97.8,
        raan_deg=120.0,
        argument_of_perigee_deg=0.0,
        true_anomaly_deg=45.0,
        epoch=datetime.utcnow()
    )
    
    mission = MissionTimeline(
        mission_id="CHANDRAYAAN-4",
        spacecraft_id=401,
        launch_date=datetime.utcnow() - timedelta(days=30),
        current_phase=MissionPhase.NOMINAL_OPERATIONS,
        orbit_type=OrbitType.LUNAR,
        orbital_params=chandrayaan_orbit,
        critical_events=[],
        ground_contact_windows=[
            (datetime.utcnow() - timedelta(minutes=10), datetime.utcnow() + timedelta(minutes=20))
        ]
    )
    
    correlator = MissionTimelineCorrelator([mission])
    
    # Simulate security event correlation
    security_events = [
        {
            'type': 'RF_JAMMING',
            'severity': 'HIGH',
            'severity_score': 4,
            'frequency_mhz': 2050.0
        }
    ]
    
    correlation = correlator.correlate_security_events(
        mission_id="CHANDRAYAAN-4",
        security_events=security_events,
        timestamp=datetime.utcnow()
    )
    
    if correlation:
        print(correlator.export_correlation(correlation))
