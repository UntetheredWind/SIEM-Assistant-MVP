"""
ISRO Supply Chain Security Monitor
Verifies integrity of space-grade components throughout supply chain
Tracks provenance, authenticity, and security of critical hardware/software
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum
import hashlib
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ComponentType(Enum):
    """Space system component types"""
    PROCESSOR = "Radiation_Hardened_Processor"
    MEMORY = "Memory_Module"
    SENSOR = "Sensor_Equipment"
    POWER = "Power_System"
    COMMUNICATION = "Communication_Module"
    PROPULSION = "Propulsion_System"
    STRUCTURE = "Structural_Component"
    SOFTWARE = "Flight_Software"
    FIRMWARE = "Firmware"


class ComponentGrade(Enum):
    """Component qualification grades"""
    SPACE_GRADE = "Space_Grade"
    MILITARY_GRADE = "Military_Grade"
    INDUSTRIAL_GRADE = "Industrial_Grade"
    COMMERCIAL_OFF_THE_SHELF = "COTS"


class VerificationStatus(Enum):
    """Component verification status"""
    VERIFIED = "Verified"
    PENDING = "Pending_Verification"
    FAILED = "Verification_Failed"
    SUSPICIOUS = "Suspicious"
    COUNTERFEIT = "Counterfeit_Suspected"


@dataclass
class Component:
    """Space-grade component specification"""
    component_id: str
    part_number: str
    component_type: ComponentType
    grade: ComponentGrade
    manufacturer: str
    authorized_suppliers: List[str]
    lot_number: str
    serial_number: str
    manufacture_date: datetime
    certifications: List[str]
    hash_checksum: Optional[str] = None
    digital_signature: Optional[str] = None


@dataclass
class SupplyChainEvent:
    """Supply chain tracking event"""
    event_id: str
    timestamp: datetime
    component_id: str
    event_type: str
    location: str
    handler: str
    verification_performed: bool
    verification_result: Optional[VerificationStatus]
    notes: str


@dataclass
class SupplyChainViolation:
    """Supply chain security violation"""
    violation_id: str
    timestamp: datetime
    component_id: str
    violation_type: str
    severity: str
    description: str
    evidence: Dict
    recommended_action: str


class SupplyChainMonitor:
    """
    Monitors space-grade component supply chain for ISRO
    Implements verification per OWASP SCVS and space industry standards
    """
    
    def __init__(self, config: Dict):
        """
        Initialize supply chain monitor
        
        Args:
            config: Configuration including approved suppliers,
                   verification requirements, acceptable component grades
        """
        self.config = config
        self.approved_manufacturers = set(config.get('approved_manufacturers', []))
        self.approved_suppliers = set(config.get('approved_suppliers', []))
        self.required_certifications = config.get('required_certifications', [])
        
        # Component tracking
        self.component_registry: Dict[str, Component] = {}
        self.supply_chain_history: Dict[str, List[SupplyChainEvent]] = {}
        self.known_counterfeits: Set[str] = set()
        
        # Verification database
        self.verified_hashes: Dict[str, Component] = {}
        self.suspicious_patterns: List[Dict] = self._initialize_suspicious_patterns()
        
        logger.info("Supply Chain Monitor initialized for ISRO space-grade components")
    
    def _initialize_suspicious_patterns(self) -> List[Dict]:
        """Initialize patterns indicative of counterfeit components"""
        return [
            {
                'pattern_id': 'REMARKED_CHIP',
                'indicators': ['surface_marks', 'label_inconsistency'],
                'description': 'Component shows signs of remarking/relabeling'
            },
            {
                'pattern_id': 'GRAY_MARKET',
                'indicators': ['unauthorized_supplier', 'missing_documentation'],
                'description': 'Component sourced from gray market supplier'
            },
            {
                'pattern_id': 'CLONED_PART',
                'indicators': ['hash_mismatch', 'performance_deviation'],
                'description': 'Component may be cloned/counterfeit'
            },
            {
                'pattern_id': 'TAMPERED_PACKAGING',
                'indicators': ['packaging_damage', 'seal_broken'],
                'description': 'Component packaging shows signs of tampering'
            }
        ]
    
    def register_component(self, component: Component) -> bool:
        """
        Register new component in supply chain
        
        Args:
            component: Component to register
            
        Returns:
            True if registration successful
        """
        # Initial verification
        violations = self.verify_component(component)
        
        if any(v.severity == 'CRITICAL' for v in violations):
            logger.error(f"Cannot register component {component.component_id}: critical violations")
            return False
        
        self.component_registry[component.component_id] = component
        self.supply_chain_history[component.component_id] = []
        
        # Store hash if available
        if component.hash_checksum:
            self.verified_hashes[component.hash_checksum] = component
        
        logger.info(f"Registered component: {component.component_id}")
        return True
    
    def verify_component(self, component: Component) -> List[SupplyChainViolation]:
        """
        Verify component authenticity and compliance
        
        Args:
            component: Component to verify
            
        Returns:
            List of supply chain violations
        """
        violations = []
        
        # Verify manufacturer
        if component.manufacturer not in self.approved_manufacturers:
            violations.append(SupplyChainViolation(
                violation_id=f"SC-MFG-{component.component_id}-{int(datetime.utcnow().timestamp())}",
                timestamp=datetime.utcnow(),
                component_id=component.component_id,
                violation_type="UNAUTHORIZED_MANUFACTURER",
                severity="CRITICAL",
                description=f"Component from unauthorized manufacturer: {component.manufacturer}",
                evidence={'manufacturer': component.manufacturer, 'approved_list': list(self.approved_manufacturers)},
                recommended_action="REJECT component and investigate supplier chain"
            ))
        
        # Verify component grade
        if component.component_type in [ComponentType.PROCESSOR, ComponentType.COMMUNICATION]:
            if component.grade == ComponentGrade.COMMERCIAL_OFF_THE_SHELF:
                violations.append(SupplyChainViolation(
                    violation_id=f"SC-GRADE-{component.component_id}-{int(datetime.utcnow().timestamp())}",
                    timestamp=datetime.utcnow(),
                    component_id=component.component_id,
                    violation_type="INADEQUATE_COMPONENT_GRADE",
                    severity="HIGH",
                    description=f"COTS component used for critical system: {component.component_type.value}",
                    evidence={'component_type': component.component_type.value, 'grade': component.grade.value},
                    recommended_action="Use Space-Grade or Military-Grade component"
                ))
        
        # Verify required certifications
        missing_certs = set(self.required_certifications) - set(component.certifications)
        if missing_certs:
            violations.append(SupplyChainViolation(
                violation_id=f"SC-CERT-{component.component_id}-{int(datetime.utcnow().timestamp())}",
                timestamp=datetime.utcnow(),
                component_id=component.component_id,
                violation_type="MISSING_CERTIFICATIONS",
                severity="MEDIUM",
                description=f"Component missing required certifications",
                evidence={'missing': list(missing_certs), 'required': self.required_certifications},
                recommended_action="Obtain missing certifications or reject component"
            ))
        
        # Verify hash checksum for software/firmware
        if component.component_type in [ComponentType.SOFTWARE, ComponentType.FIRMWARE]:
            if not component.hash_checksum:
                violations.append(SupplyChainViolation(
                    violation_id=f"SC-HASH-{component.component_id}-{int(datetime.utcnow().timestamp())}",
                    timestamp=datetime.utcnow(),
                    component_id=component.component_id,
                    violation_type="MISSING_HASH_VERIFICATION",
                    severity="HIGH",
                    description="Software/firmware lacks cryptographic hash verification",
                    evidence={'component_type': component.component_type.value},
                    recommended_action="Implement SHA-256/SHA-3 hash verification"
                ))
        
        # Check for known counterfeits
        if component.part_number in self.known_counterfeits:
            violations.append(SupplyChainViolation(
                violation_id=f"SC-COUNTERFEIT-{component.component_id}-{int(datetime.utcnow().timestamp())}",
                timestamp=datetime.utcnow(),
                component_id=component.component_id,
                violation_type="KNOWN_COUNTERFEIT",
                severity="CRITICAL",
                description="Component matches known counterfeit pattern",
                evidence={'part_number': component.part_number},
                recommended_action="IMMEDIATE QUARANTINE and report to authorities"
            ))
        
        # Verify digital signature
        if component.digital_signature:
            if not self._verify_digital_signature(component):
                violations.append(SupplyChainViolation(
                    violation_id=f"SC-SIG-{component.component_id}-{int(datetime.utcnow().timestamp())}",
                    timestamp=datetime.utcnow(),
                    component_id=component.component_id,
                    violation_type="INVALID_DIGITAL_SIGNATURE",
                    severity="CRITICAL",
                    description="Component digital signature verification failed",
                    evidence={'signature': component.digital_signature[:32]},
                    recommended_action="REJECT component - possible tampering"
                ))
        
        return violations
    
    def _verify_digital_signature(self, component: Component) -> bool:
        """Verify component digital signature (simplified)"""
        # In production, use proper cryptographic verification
        # This is a placeholder for demonstration
        if not component.digital_signature:
            return False
        
        # Simulate signature verification
        expected_signature = hashlib.sha256(
            f"{component.part_number}{component.serial_number}".encode()
        ).hexdigest()
        
        return component.digital_signature == expected_signature
    
    def track_supply_chain_event(
        self,
        component_id: str,
        event_type: str,
        location: str,
        handler: str,
        notes: str = ""
    ) -> SupplyChainEvent:
        """
        Track component movement through supply chain
        
        Args:
            component_id: Component identifier
            event_type: Type of event (received, inspected, installed, etc.)
            location: Current location
            handler: Person/entity handling component
            notes: Additional notes
            
        Returns:
            SupplyChainEvent object
        """
        event = SupplyChainEvent(
            event_id=f"SCE-{component_id}-{int(datetime.utcnow().timestamp())}",
            timestamp=datetime.utcnow(),
            component_id=component_id,
            event_type=event_type,
            location=location,
            handler=handler,
            verification_performed=False,
            verification_result=None,
            notes=notes
        )
        
        if component_id not in self.supply_chain_history:
            self.supply_chain_history[component_id] = []
        
        self.supply_chain_history[component_id].append(event)
        
        logger.info(f"Tracked supply chain event: {event_type} for {component_id}")
        return event
    
    def perform_component_inspection(
        self,
        component_id: str,
        inspection_data: Dict
    ) -> Tuple[VerificationStatus, List[SupplyChainViolation]]:
        """
        Perform physical/electrical inspection of component
        
        Args:
            component_id: Component to inspect
            inspection_data: Inspection results (visual, electrical, etc.)
            
        Returns:
            Tuple of (VerificationStatus, violations)
        """
        if component_id not in self.component_registry:
            logger.error(f"Unknown component: {component_id}")
            return VerificationStatus.FAILED, []
        
        component = self.component_registry[component_id]
        violations = []
        suspicious_indicators = []
        
        # Visual inspection checks
        if inspection_data.get('surface_marks'):
            suspicious_indicators.append('surface_marks')
        
        if inspection_data.get('packaging_damage'):
            suspicious_indicators.append('packaging_damage')
        
        # Electrical testing
        expected_performance = inspection_data.get('expected_performance', {})
        actual_performance = inspection_data.get('actual_performance', {})
        
        for param, expected_val in expected_performance.items():
            actual_val = actual_performance.get(param)
            if actual_val:
                deviation = abs(actual_val - expected_val) / expected_val
                if deviation > 0.1:  # 10% deviation threshold
                    suspicious_indicators.append('performance_deviation')
                    break
        
        # Hash verification for software/firmware
        if component.component_type in [ComponentType.SOFTWARE, ComponentType.FIRMWARE]:
            provided_hash = inspection_data.get('hash_checksum')
            if provided_hash != component.hash_checksum:
                suspicious_indicators.append('hash_mismatch')
        
        # Check against suspicious patterns
        for pattern in self.suspicious_patterns:
            pattern_indicators = set(pattern['indicators'])
            if pattern_indicators.intersection(suspicious_indicators):
                violations.append(SupplyChainViolation(
                    violation_id=f"SC-INSPECT-{component_id}-{int(datetime.utcnow().timestamp())}",
                    timestamp=datetime.utcnow(),
                    component_id=component_id,
                    violation_type=pattern['pattern_id'],
                    severity="HIGH",
                    description=pattern['description'],
                    evidence={
                        'indicators_detected': list(pattern_indicators.intersection(suspicious_indicators)),
                        'inspection_data': inspection_data
                    },
                    recommended_action="Quarantine component and perform detailed forensic analysis"
                ))
        
        # Determine verification status
        if suspicious_indicators:
            if any(v.severity == 'CRITICAL' for v in violations):
                status = VerificationStatus.COUNTERFEIT
            else:
                status = VerificationStatus.SUSPICIOUS
        else:
            status = VerificationStatus.VERIFIED
        
        # Record inspection event
        event = self.track_supply_chain_event(
            component_id=component_id,
            event_type="INSPECTION",
            location=inspection_data.get('location', 'ISRO Facility'),
            handler=inspection_data.get('inspector', 'Unknown'),
            notes=f"Inspection result: {status.value}"
        )
        event.verification_performed = True
        event.verification_result = status
        
        return status, violations
    
    def generate_component_provenance_report(self, component_id: str) -> Dict:
        """
        Generate complete provenance report for component
        
        Args:
            component_id: Component identifier
            
        Returns:
            Provenance report dictionary
        """
        if component_id not in self.component_registry:
            return {'error': f'Component {component_id} not found'}
        
        component = self.component_registry[component_id]
        history = self.supply_chain_history.get(component_id, [])
        
        return {
            'component_id': component_id,
            'part_number': component.part_number,
            'component_type': component.component_type.value,
            'grade': component.grade.value,
            'manufacturer': component.manufacturer,
            'manufacture_date': component.manufacture_date.isoformat(),
            'certifications': component.certifications,
            'supply_chain_events': [
                {
                    'timestamp': event.timestamp.isoformat(),
                    'event_type': event.event_type,
                    'location': event.location,
                    'handler': event.handler,
                    'verification_status': event.verification_result.value if event.verification_result else None
                }
                for event in history
            ],
            'current_status': history[-1].verification_result.value if history and history[-1].verification_result else 'UNKNOWN',
            'chain_of_custody_complete': len(history) > 0
        }
    
    def export_violations(self, violations: List[SupplyChainViolation], format: str = 'json') -> str:
        """Export supply chain violations for SIEM integration"""
        if format == 'json':
            return json.dumps([
                {
                    'violation_id': v.violation_id,
                    'timestamp': v.timestamp.isoformat(),
                    'component_id': v.component_id,
                    'type': v.violation_type,
                    'severity': v.severity,
                    'description': v.description,
                    'evidence': v.evidence,
                    'recommended_action': v.recommended_action
                }
                for v in violations
            ], indent=2)
        return str(violations)


# Example usage for ISRO component verification
if __name__ == "__main__":
    config = {
        'approved_manufacturers': [
            'ISRO-LEOS', 'ISRO-SAC', 'ISRO-VSSC',
            'BEL', 'HAL', 'DRDO'
        ],
        'approved_suppliers': [
            'ISRO Central Stores', 'Authorized Distributor A'
        ],
        'required_certifications': [
            'ISRO-QR-001', 'MIL-STD-883', 'ECSS-Q-ST-60'
        ]
    }
    
    monitor = SupplyChainMonitor(config)
    
    # Register space-grade component
    component = Component(
        component_id="COMP-RAD-001",
        part_number="RAD750-001",
        component_type=ComponentType.PROCESSOR,
        grade=ComponentGrade.SPACE_GRADE,
        manufacturer="ISRO-LEOS",
        authorized_suppliers=["ISRO Central Stores"],
        lot_number="LOT-2025-001",
        serial_number="SN-123456",
        manufacture_date=datetime(2025, 1, 15),
        certifications=["ISRO-QR-001", "MIL-STD-883"],
        hash_checksum=None,
        digital_signature=hashlib.sha256(b"RAD750-001SN-123456").hexdigest()
    )
    
    # Verify and register
    violations = monitor.verify_component(component)
    if not violations or all(v.severity != 'CRITICAL' for v in violations):
        monitor.register_component(component)
    
    # Track supply chain
    monitor.track_supply_chain_event(
        component_id="COMP-RAD-001",
        event_type="RECEIVED",
        location="ISRO Central Stores",
        handler="Officer-001",
        notes="Initial receipt from manufacturer"
    )
    
    # Perform inspection
    inspection_data = {
        'location': 'ISRO Quality Assurance Lab',
        'inspector': 'QA-Engineer-005',
        'surface_marks': False,
        'packaging_damage': False,
        'expected_performance': {'clock_speed_mhz': 200},
        'actual_performance': {'clock_speed_mhz': 198}
    }
    
    status, inspection_violations = monitor.perform_component_inspection(
        "COMP-RAD-001",
        inspection_data
    )
    
    print(f"Verification Status: {status.value}")
    if inspection_violations:
        print(monitor.export_violations(inspection_violations))
    
    # Generate provenance report
    print(json.dumps(monitor.generate_component_provenance_report("COMP-RAD-001"), indent=2))
