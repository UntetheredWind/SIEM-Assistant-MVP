"""
Threat Analysis Engine
Provides intelligent threat assessment and classification for security alerts.
Implements risk scoring, MITRE ATT&CK mapping, and threat intelligence enrichment.
"""

import logging
import asyncio
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from enum import Enum
import re
import ipaddress

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = 1
    MEDIUM = 2  
    HIGH = 3
    CRITICAL = 4


class AttackPhase(Enum):
    """MITRE ATT&CK tactics/phases."""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class IOCType(Enum):
    """Indicator of Compromise types."""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    FILE_HASH = "file_hash"
    FILE_PATH = "file_path"
    EMAIL = "email"
    URL = "url"
    REGISTRY_KEY = "registry_key"
    PROCESS_NAME = "process_name"


class ThreatAnalyzer:
    """
    Advanced threat analysis engine for security alert enrichment.
    Provides threat scoring, IOC extraction, and MITRE ATT&CK mapping.
    """

    def __init__(self):
        self.threat_intelligence_db = self._initialize_threat_intel()
        self.mitre_mappings = self._initialize_mitre_mappings()
        self.known_bad_ips = self._load_known_bad_ips()
        self.analysis_cache = {}

    def _initialize_threat_intel(self) -> Dict:
        """Initialize threat intelligence database (simplified for MVP)."""
        return {
            'malicious_ips': [
                '192.168.1.100',  # Example malicious IP
                '10.0.0.50',      # Another example
                '172.16.0.25',    # Test IP
                '203.0.113.42'    # Demo IP
            ],
            'suspicious_domains': [
                'malicious-site.com',
                'phishing-domain.net',
                'c2-server.org'
            ],
            'known_malware_hashes': [
                'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                'd4f3b2e1a7c9b8d6f5e4a3c2b1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2'
            ]
        }

    def _initialize_mitre_mappings(self) -> Dict:
        """Initialize MITRE ATT&CK technique mappings."""
        return {
            # SSH-related attacks
            '5763': {  # SSH authentication failed
                'techniques': ['T1110.001'],  # Password Guessing
                'tactics': ['credential_access'],
                'description': 'Brute force attack against SSH service'
            },
            '5715': {  # SSH successful login
                'techniques': ['T1021.004'],  # SSH
                'tactics': ['lateral_movement', 'persistence'],
                'description': 'SSH access (potentially suspicious)'
            },

            # Web attacks
            '31168': {  # Web attack detected
                'techniques': ['T1190'],  # Exploit Public-Facing Application
                'tactics': ['initial_access'],
                'description': 'Web application attack attempt'
            },

            # File integrity monitoring
            '550': {   # File integrity monitoring
                'techniques': ['T1070.004'],  # File Deletion
                'tactics': ['defense_evasion'],
                'description': 'File system modification detected'
            },

            # Process monitoring
            '592': {   # Process monitoring
                'techniques': ['T1059'],  # Command and Scripting Interpreter
                'tactics': ['execution'],
                'description': 'Suspicious process execution'
            }
        }

    def _load_known_bad_ips(self) -> set:
        """Load known malicious IP addresses."""
        # In production, this would load from threat intelligence feeds
        return {
            '192.168.1.100',
            '10.0.0.50', 
            '172.16.0.25',
            '203.0.113.42',  # Example bad IP
            '198.51.100.1'   # Another example
        }

    async def analyze_alert(self, alert: Dict) -> Dict:
        """
        Perform comprehensive threat analysis on security alert.

        Args:
            alert: Wazuh alert data

        Returns:
            Threat analysis results
        """
        # Generate cache key for alert
        cache_key = self._generate_cache_key(alert)

        # Check cache first
        if cache_key in self.analysis_cache:
            cached_result = self.analysis_cache[cache_key]
            if self._is_cache_valid(cached_result):
                return cached_result['analysis']

        # Perform full analysis
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'alert_id': alert.get('id', 'unknown'),
            'threat_level': ThreatLevel.LOW,
            'confidence_score': 0.0,
            'risk_score': 0,
            'indicators': [],
            'mitre_attack': {},
            'recommendations': [],
            'context': {}
        }

        # Extract and analyze IOCs
        iocs = self._extract_iocs(alert)
        analysis['indicators'] = iocs

        # Perform threat scoring
        threat_score = await self._calculate_threat_score(alert, iocs)
        analysis['threat_level'] = self._score_to_threat_level(threat_score)
        analysis['risk_score'] = threat_score
        analysis['confidence_score'] = self._calculate_confidence(alert, iocs)

        # Map to MITRE ATT&CK framework
        mitre_info = self._map_to_mitre(alert)
        analysis['mitre_attack'] = mitre_info

        # Generate contextual information
        context = await self._build_context(alert, iocs)
        analysis['context'] = context

        # Generate recommendations
        recommendations = self._generate_recommendations(alert, analysis)
        analysis['recommendations'] = recommendations

        # Cache the result
        self.analysis_cache[cache_key] = {
            'timestamp': datetime.now(),
            'analysis': analysis
        }

        return analysis

    def _extract_iocs(self, alert: Dict) -> List[Dict]:
        """Extract Indicators of Compromise from alert data."""
        iocs = []

        # Extract IP addresses
        for field in ['srcip', 'dstip']:
            if field in alert.get('data', {}):
                ip = alert['data'][field]
                if self._is_valid_ip(ip):
                    iocs.append({
                        'type': IOCType.IP_ADDRESS.value,
                        'value': ip,
                        'field': field,
                        'reputation': self._check_ip_reputation(ip)
                    })

        # Extract file paths
        full_log = alert.get('full_log', '')
        file_paths = self._extract_file_paths(full_log)
        for path in file_paths:
            iocs.append({
                'type': IOCType.FILE_PATH.value,
                'value': path,
                'field': 'full_log'
            })

        # Extract process names
        processes = self._extract_process_names(full_log)
        for process in processes:
            iocs.append({
                'type': IOCType.PROCESS_NAME.value,
                'value': process,
                'field': 'full_log'
            })

        # Extract domains from URLs
        domains = self._extract_domains(full_log)
        for domain in domains:
            iocs.append({
                'type': IOCType.DOMAIN.value,
                'value': domain,
                'field': 'full_log',
                'reputation': self._check_domain_reputation(domain)
            })

        return iocs

    async def _calculate_threat_score(self, alert: Dict, iocs: List[Dict]) -> int:
        """Calculate overall threat score (0-100)."""
        base_score = 0

        # Base score from rule level
        rule_level = alert.get('rule', {}).get('level', 0)
        base_score += min(rule_level * 5, 50)  # Max 50 points from rule level

        # IOC reputation scoring
        ioc_score = 0
        for ioc in iocs:
            if ioc.get('reputation') == 'malicious':
                ioc_score += 25
            elif ioc.get('reputation') == 'suspicious':
                ioc_score += 10

        base_score += min(ioc_score, 30)  # Max 30 points from IOCs

        # Rule group based scoring
        rule_groups = alert.get('rule', {}).get('groups', [])
        group_score = 0
        high_risk_groups = ['malware', 'exploit', 'attack', 'intrusion']
        medium_risk_groups = ['authentication_failed', 'access_denied']

        for group in rule_groups:
            if any(hrg in group.lower() for hrg in high_risk_groups):
                group_score += 15
            elif any(mrg in group.lower() for mrg in medium_risk_groups):
                group_score += 5

        base_score += min(group_score, 20)  # Max 20 points from groups

        return min(base_score, 100)

    def _score_to_threat_level(self, score: int) -> ThreatLevel:
        """Convert numeric score to threat level."""
        if score >= 80:
            return ThreatLevel.CRITICAL
        elif score >= 60:
            return ThreatLevel.HIGH
        elif score >= 30:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

    def _calculate_confidence(self, alert: Dict, iocs: List[Dict]) -> float:
        """Calculate confidence score (0.0-1.0)."""
        confidence = 0.5  # Base confidence

        # Higher confidence for known IOCs
        malicious_iocs = sum(1 for ioc in iocs if ioc.get('reputation') == 'malicious')
        if malicious_iocs > 0:
            confidence += 0.3

        # Higher confidence for well-documented rule types
        rule_id = alert.get('rule', {}).get('id', '')
        if rule_id in self.mitre_mappings:
            confidence += 0.2

        return min(confidence, 1.0)

    def _map_to_mitre(self, alert: Dict) -> Dict:
        """Map alert to MITRE ATT&CK framework."""
        rule_id = alert.get('rule', {}).get('id', '')

        if rule_id in self.mitre_mappings:
            mapping = self.mitre_mappings[rule_id]
            return {
                'techniques': mapping['techniques'],
                'tactics': mapping['tactics'],
                'description': mapping['description']
            }

        # Fallback mapping based on rule groups
        rule_groups = alert.get('rule', {}).get('groups', [])
        tactics = []

        for group in rule_groups:
            if 'authentication' in group.lower():
                tactics.append(AttackPhase.CREDENTIAL_ACCESS.value)
            elif 'web' in group.lower() or 'exploit' in group.lower():
                tactics.append(AttackPhase.INITIAL_ACCESS.value)
            elif 'malware' in group.lower():
                tactics.append(AttackPhase.EXECUTION.value)

        return {
            'techniques': [],
            'tactics': list(set(tactics)),
            'description': 'Generic mapping based on rule groups'
        }

    async def _build_context(self, alert: Dict, iocs: List[Dict]) -> Dict:
        """Build contextual information about the threat."""
        context = {
            'agent_info': {},
            'attack_pattern': 'unknown',
            'geographic_info': {},
            'temporal_analysis': {}
        }

        # Agent context
        if 'agent' in alert:
            context['agent_info'] = {
                'id': alert['agent'].get('id'),
                'name': alert['agent'].get('name'),
                'ip': alert['agent'].get('ip'),
                'last_seen': alert.get('timestamp')
            }

        # Determine attack pattern
        context['attack_pattern'] = self._identify_attack_pattern(alert, iocs)

        # Geographic information (simplified)
        for ioc in iocs:
            if ioc['type'] == IOCType.IP_ADDRESS.value:
                context['geographic_info'][ioc['value']] = self._get_ip_geolocation(ioc['value'])

        return context

    def _generate_recommendations(self, alert: Dict, analysis: Dict) -> List[str]:
        """Generate actionable recommendations based on analysis."""
        recommendations = []

        threat_level = analysis['threat_level']
        risk_score = analysis['risk_score']

        # High-level recommendations based on threat level
        if threat_level == ThreatLevel.CRITICAL:
            recommendations.extend([
                "Immediately isolate affected systems",
                "Initiate incident response procedures",
                "Block malicious IPs at network perimeter",
                "Perform forensic analysis of affected systems"
            ])
        elif threat_level == ThreatLevel.HIGH:
            recommendations.extend([
                "Implement additional monitoring on affected systems",
                "Consider blocking suspicious IPs",
                "Review and strengthen access controls",
                "Schedule security assessment"
            ])
        elif threat_level == ThreatLevel.MEDIUM:
            recommendations.extend([
                "Monitor for similar activity patterns",
                "Update security policies if necessary",
                "Consider user awareness training"
            ])

        # IOC-specific recommendations
        malicious_ips = [ioc for ioc in analysis['indicators'] 
                        if ioc['type'] == IOCType.IP_ADDRESS.value and 
                        ioc.get('reputation') == 'malicious']

        if malicious_ips:
            recommendations.append(f"Block {len(malicious_ips)} identified malicious IP addresses")

        # MITRE-specific recommendations
        mitre_tactics = analysis['mitre_attack'].get('tactics', [])
        if 'credential_access' in mitre_tactics:
            recommendations.append("Enforce strong password policies and MFA")
        if 'initial_access' in mitre_tactics:
            recommendations.append("Review and patch public-facing applications")

        return recommendations

    # Helper methods

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _check_ip_reputation(self, ip: str) -> str:
        """Check IP reputation against threat intelligence."""
        if ip in self.known_bad_ips:
            return 'malicious'
        elif self._is_private_ip(ip):
            return 'internal'
        else:
            return 'unknown'

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private address space."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False

    def _check_domain_reputation(self, domain: str) -> str:
        """Check domain reputation."""
        if domain in self.threat_intelligence_db.get('suspicious_domains', []):
            return 'malicious'
        return 'unknown'

    def _extract_file_paths(self, text: str) -> List[str]:
        """Extract file paths from log text."""
        # Windows and Unix path patterns
        patterns = [
            r'[a-zA-Z]:\\(?:[^\\/:*?"<>|\s]+\\)*[^\\/:*?"<>|\s]*',  # Windows paths
            r'/(?:[^/\s]+/)*[^/\s]+',  # Unix paths
        ]

        paths = []
        for pattern in patterns:
            matches = re.findall(pattern, text)
            paths.extend(matches)

        return list(set(paths))  # Remove duplicates

    def _extract_process_names(self, text: str) -> List[str]:
        """Extract process names from log text."""
        # Common process name patterns
        patterns = [
            r'(\w+\.exe)',  # Windows executables
            r'/usr/bin/(\w+)',  # Unix binaries
            r'/bin/(\w+)',  # Unix binaries
        ]

        processes = []
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            processes.extend(matches)

        return list(set(processes))

    def _extract_domains(self, text: str) -> List[str]:
        """Extract domain names from log text."""
        # Domain pattern
        domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        matches = re.findall(domain_pattern, text)
        return list(set(matches))

    def _identify_attack_pattern(self, alert: Dict, iocs: List[Dict]) -> str:
        """Identify the type of attack pattern."""
        rule_groups = alert.get('rule', {}).get('groups', [])

        if any('brute' in group.lower() for group in rule_groups):
            return 'brute_force'
        elif any('web' in group.lower() for group in rule_groups):
            return 'web_attack'
        elif any('malware' in group.lower() for group in rule_groups):
            return 'malware'
        elif any('authentication' in group.lower() for group in rule_groups):
            return 'credential_attack'
        else:
            return 'unknown'

    def _get_ip_geolocation(self, ip: str) -> Dict:
        """Get IP geolocation information (simplified)."""
        # In production, this would use a real geolocation service
        if self._is_private_ip(ip):
            return {'country': 'Internal', 'region': 'Private Network'}
        else:
            return {'country': 'Unknown', 'region': 'Unknown'}

    def _generate_cache_key(self, alert: Dict) -> str:
        """Generate cache key for alert."""
        key_data = f"{alert.get('rule', {}).get('id', '')}-{alert.get('data', {}).get('srcip', '')}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def _is_cache_valid(self, cached_result: Dict, max_age_minutes: int = 5) -> bool:
        """Check if cached result is still valid."""
        cache_time = cached_result['timestamp']
        age = datetime.now() - cache_time
        return age.total_seconds() < (max_age_minutes * 60)


# Example usage and testing
async def demo_threat_analyzer():
    """Demo function for testing threat analyzer."""

    sample_alert = {
        'id': 'demo_alert_001',
        'rule': {
            'level': 10,
            'id': '5763',
            'description': 'SSH authentication failed',
            'groups': ['authentication_failed', 'sshd']
        },
        'data': {
            'srcip': '192.168.1.100',
            'srcuser': 'attacker'
        },
        'agent': {
            'id': '001',
            'name': 'web-server-01',
            'ip': '10.0.1.50'
        },
        'full_log': 'Oct 15 21:07:00 web-server sshd[29205]: Authentication failure for attacker from 192.168.1.100',
        'timestamp': datetime.now().isoformat()
    }

    analyzer = ThreatAnalyzer()
    analysis = await analyzer.analyze_alert(sample_alert)

    print("Threat Analysis Results:")
    print(f"Threat Level: {analysis['threat_level'].name}")
    print(f"Risk Score: {analysis['risk_score']}/100")
    print(f"Confidence: {analysis['confidence_score']:.2f}")
    print(f"IOCs Found: {len(analysis['indicators'])}")
    print(f"MITRE Tactics: {analysis['mitre_attack'].get('tactics', [])}")
    print(f"Recommendations: {len(analysis['recommendations'])}")

    return analysis


if __name__ == "__main__":
    asyncio.run(demo_threat_analyzer())
