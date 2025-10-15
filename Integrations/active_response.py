"""
Active Response Automation
Handles automated threat mitigation responses based on alert severity and type.
Implements response playbooks and orchestration logic.
"""

import logging
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from enum import Enum

try:
    from Integrations.wazuh_client import WazuhClient, WazuhAPIError
    from config.wazuh_config import AlertSeverity, ResponseAction, ActiveResponseConfig, wazuh_config
except ImportError:
    # Fallback enums if config is missing
    class AlertSeverity(Enum):
        LOW = 1
        MEDIUM = 5
        HIGH = 10
        CRITICAL = 15

    class ResponseAction(Enum):
        FIREWALL_DROP = "firewall-drop"
        HOST_DENY = "host-deny"
        ROUTE_NULL = "route-null"
        WIN_ROUTE_NULL = "win_route-null"
        WIN_FIREWALL_DROP = "win_firewall-drop"
        CUSTOM_BLOCK = "custom-block"
        FILE_QUARANTINE = "quarantine-file"

    WazuhClient = None
    WazuhAPIError = Exception

logger = logging.getLogger(__name__)


class ResponseStatus(Enum):
    """Status of response execution."""
    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class ThreatLevel(Enum):
    """Threat level classification."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ResponsePlaybook:
    """Defines an automated response playbook."""

    def __init__(self, name: str, severity_threshold: AlertSeverity, 
                 actions: List[ResponseAction], conditions: Dict = None):
        self.name = name
        self.severity_threshold = severity_threshold
        self.actions = actions
        self.conditions = conditions or {}
        self.execution_count = 0
        self.last_executed = None

    def should_execute(self, alert: Dict, threat_analysis: Dict) -> bool:
        """Determine if playbook should execute based on alert and analysis."""
        # Check severity threshold
        alert_level = alert.get('rule', {}).get('level', 0)
        if alert_level < self.severity_threshold.value:
            return False

        # Check custom conditions
        for condition, value in self.conditions.items():
            if condition == 'rule_groups':
                alert_groups = alert.get('rule', {}).get('groups', [])
                if not any(group in alert_groups for group in value):
                    return False
            elif condition == 'max_executions_per_hour':
                if self._exceeds_execution_limit(value):
                    return False
            elif condition == 'source_ip_reputation':
                if threat_analysis.get('ip_reputation', 'unknown') not in value:
                    return False

        return True

    def _exceeds_execution_limit(self, max_executions: int) -> bool:
        """Check if execution limit is exceeded."""
        if not self.last_executed:
            return False

        one_hour_ago = datetime.now() - timedelta(hours=1)
        if self.last_executed > one_hour_ago and self.execution_count >= max_executions:
            return True

        # Reset counter if more than an hour has passed
        if self.last_executed <= one_hour_ago:
            self.execution_count = 0

        return False


class ActiveResponseEngine:
    """
    Core engine for automated active response execution.
    Handles playbook selection, response execution, and result tracking.
    """

    def __init__(self, wazuh_client=None):
        self.wazuh_client = wazuh_client
        self.playbooks = self._initialize_playbooks()
        self.response_history = []
        self.active_responses = {}

    def _initialize_playbooks(self) -> List[ResponsePlaybook]:
        """Initialize predefined response playbooks."""
        return [
            # SSH Brute Force Playbook
            ResponsePlaybook(
                name="SSH Brute Force Protection",
                severity_threshold=AlertSeverity.MEDIUM,
                actions=[ResponseAction.FIREWALL_DROP],
                conditions={
                    'rule_groups': ['authentication_failed', 'sshd'],
                    'max_executions_per_hour': 10
                }
            ),

            # Web Attack Playbook
            ResponsePlaybook(
                name="Web Attack Mitigation",
                severity_threshold=AlertSeverity.HIGH,
                actions=[ResponseAction.FIREWALL_DROP, ResponseAction.CUSTOM_BLOCK],
                conditions={
                    'rule_groups': ['web', 'attack', 'exploit'],
                    'max_executions_per_hour': 5
                }
            ),

            # Malware Detection Playbook
            ResponsePlaybook(
                name="Malware Response",
                severity_threshold=AlertSeverity.CRITICAL,
                actions=[ResponseAction.FILE_QUARANTINE, ResponseAction.HOST_DENY],
                conditions={
                    'rule_groups': ['malware', 'rootcheck', 'virus'],
                    'max_executions_per_hour': 3
                }
            ),

            # High Severity Generic Playbook
            ResponsePlaybook(
                name="Critical Alert Response",
                severity_threshold=AlertSeverity.CRITICAL,
                actions=[ResponseAction.FIREWALL_DROP],
                conditions={
                    'max_executions_per_hour': 20
                }
            )
        ]

    async def process_alert(self, alert: Dict) -> Dict:
        """
        Process incoming alert and execute appropriate responses.

        Args:
            alert: Wazuh alert data

        Returns:
            Response execution results
        """
        try:
            # Analyze threat (simplified for MVP)
            threat_analysis = await self._analyze_threat(alert)

            # Find applicable playbooks
            applicable_playbooks = []
            for playbook in self.playbooks:
                if playbook.should_execute(alert, threat_analysis):
                    applicable_playbooks.append(playbook)

            if not applicable_playbooks:
                logger.info(f"No applicable playbooks for alert {alert.get('id', 'unknown')}")
                return {'status': 'no_action', 'reason': 'No applicable playbooks'}

            # Execute highest priority playbook
            selected_playbook = max(applicable_playbooks, 
                                  key=lambda p: p.severity_threshold.value)

            result = await self._execute_playbook(selected_playbook, alert, threat_analysis)

            # Update playbook execution tracking
            selected_playbook.execution_count += 1
            selected_playbook.last_executed = datetime.now()

            return result

        except Exception as e:
            logger.error(f"Error processing alert: {str(e)}")
            return {'status': 'error', 'error': str(e)}

    async def _analyze_threat(self, alert: Dict) -> Dict:
        """Simplified threat analysis for MVP."""
        analysis = {
            'threat_level': ThreatLevel.MEDIUM,
            'confidence': 0.7,
            'indicators': [],
            'recommendations': []
        }

        # Basic threat scoring based on rule level
        rule_level = alert.get('rule', {}).get('level', 0)
        if rule_level >= 15:
            analysis['threat_level'] = ThreatLevel.CRITICAL
            analysis['confidence'] = 0.95
        elif rule_level >= 10:
            analysis['threat_level'] = ThreatLevel.HIGH
            analysis['confidence'] = 0.85
        elif rule_level >= 5:
            analysis['threat_level'] = ThreatLevel.MEDIUM
            analysis['confidence'] = 0.7
        else:
            analysis['threat_level'] = ThreatLevel.LOW
            analysis['confidence'] = 0.5

        return analysis

    async def _execute_playbook(self, playbook: ResponsePlaybook, alert: Dict, 
                               threat_analysis: Dict) -> Dict:
        """Execute response playbook actions."""
        response_id = f"resp_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{len(self.response_history)}"

        execution_result = {
            'response_id': response_id,
            'playbook': playbook.name,
            'alert_id': alert.get('id'),
            'timestamp': datetime.now().isoformat(),
            'status': ResponseStatus.EXECUTING.value,
            'actions': [],
            'threat_analysis': threat_analysis
        }

        self.active_responses[response_id] = execution_result

        try:
            # Extract response targets
            targets = self._extract_response_targets(alert, threat_analysis)

            # Execute each action in the playbook
            for action in playbook.actions:
                action_result = await self._execute_action(action, targets, alert)
                execution_result['actions'].append(action_result)

            execution_result['status'] = ResponseStatus.COMPLETED.value
            logger.info(f"Successfully executed playbook {playbook.name} for alert {alert.get('id')}")

        except Exception as e:
            execution_result['status'] = ResponseStatus.FAILED.value
            execution_result['error'] = str(e)
            logger.error(f"Failed to execute playbook {playbook.name}: {str(e)}")

        # Store in history
        self.response_history.append(execution_result)
        if response_id in self.active_responses:
            del self.active_responses[response_id]

        return execution_result

    def _extract_response_targets(self, alert: Dict, threat_analysis: Dict) -> Dict:
        """Extract target information for response actions."""
        targets = {}

        # Extract IP addresses
        if 'srcip' in alert.get('data', {}):
            targets['source_ip'] = alert['data']['srcip']

        # Extract agent information
        if 'agent' in alert:
            targets['agent_id'] = alert['agent'].get('id')
            targets['agent_name'] = alert['agent'].get('name')

        # Extract file paths for quarantine
        if 'full_log' in alert and 'file' in alert['full_log'].lower():
            # Simple regex to extract file paths - enhance based on needs
            import re
            file_pattern = r'([a-zA-Z]:\[^\s]+|/[^\s]+)'
            matches = re.findall(file_pattern, alert['full_log'])
            if matches:
                targets['file_path'] = matches[0]

        return targets

    async def _execute_action(self, action: ResponseAction, targets: Dict, alert: Dict) -> Dict:
        """Execute individual response action."""
        action_result = {
            'action': action.value,
            'timestamp': datetime.now().isoformat(),
            'status': ResponseStatus.EXECUTING.value,
            'targets': targets
        }

        try:
            if action == ResponseAction.FIREWALL_DROP:
                await self._execute_firewall_drop(targets, action_result)
            elif action == ResponseAction.HOST_DENY:
                await self._execute_host_deny(targets, action_result)
            elif action == ResponseAction.FILE_QUARANTINE:
                await self._execute_file_quarantine(targets, action_result)
            elif action == ResponseAction.CUSTOM_BLOCK:
                await self._execute_custom_block(targets, action_result)
            else:
                action_result['status'] = ResponseStatus.FAILED.value
                action_result['error'] = f"Unsupported action: {action.value}"

        except Exception as e:
            action_result['status'] = ResponseStatus.FAILED.value
            action_result['error'] = str(e)
            logger.error(f"Action {action.value} failed: {str(e)}")

        return action_result

    async def _execute_firewall_drop(self, targets: Dict, action_result: Dict):
        """Execute firewall drop action."""
        if 'source_ip' not in targets:
            raise ValueError("No source IP found for firewall drop")

        if 'agent_id' not in targets:
            raise ValueError("No agent ID found for firewall drop")

        # For MVP: simulate response execution
        # In production: self.wazuh_client.run_active_response(...)
        action_result['status'] = ResponseStatus.COMPLETED.value
        action_result['message'] = f"[SIMULATED] Blocked IP {targets['source_ip']} on agent {targets['agent_id']}"
        action_result['simulation'] = True

    async def _execute_host_deny(self, targets: Dict, action_result: Dict):
        """Execute host deny action."""
        if 'source_ip' not in targets:
            raise ValueError("No source IP found for host deny")

        if 'agent_id' not in targets:
            raise ValueError("No agent ID found for host deny")

        action_result['status'] = ResponseStatus.COMPLETED.value
        action_result['message'] = f"[SIMULATED] Added {targets['source_ip']} to hosts.deny on agent {targets['agent_id']}"
        action_result['simulation'] = True

    async def _execute_file_quarantine(self, targets: Dict, action_result: Dict):
        """Execute file quarantine action."""
        if 'file_path' not in targets:
            raise ValueError("No file path found for quarantine")

        if 'agent_id' not in targets:
            raise ValueError("No agent ID found for file quarantine")

        action_result['status'] = ResponseStatus.COMPLETED.value
        action_result['message'] = f"[SIMULATED] Quarantined file {targets['file_path']} on agent {targets['agent_id']}"
        action_result['simulation'] = True

    async def _execute_custom_block(self, targets: Dict, action_result: Dict):
        """Execute custom blocking action."""
        action_result['status'] = ResponseStatus.COMPLETED.value
        action_result['message'] = "[SIMULATED] Custom block action executed"
        action_result['simulation'] = True

        if 'source_ip' in targets:
            logger.info(f"[SIMULATED] Would block {targets['source_ip']} at network perimeter")

    def get_response_history(self, limit: int = 100) -> List[Dict]:
        """Get recent response execution history."""
        return self.response_history[-limit:]

    def get_active_responses(self) -> Dict:
        """Get currently executing responses."""
        return self.active_responses.copy()

    def get_playbook_stats(self) -> List[Dict]:
        """Get playbook execution statistics."""
        stats = []
        for playbook in self.playbooks:
            stats.append({
                'name': playbook.name,
                'execution_count': playbook.execution_count,
                'last_executed': playbook.last_executed.isoformat() if playbook.last_executed else None,
                'severity_threshold': playbook.severity_threshold.name
            })
        return stats


# Example usage and testing functions for development
async def demo_response_engine():
    """Demo function for testing response engine with sample data."""

    # Sample alert data
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
            'name': 'web-server-01'
        },
        'full_log': 'Oct 15 21:07:00 web-server sshd[29205]: Authentication failure for attacker from 192.168.1.100'
    }

    # Create mock response engine for testing
    engine = ActiveResponseEngine()

    # Process the alert
    result = await engine.process_alert(sample_alert)

    print("Response Engine Demo Results:")
    print(f"Status: {result['status']}")
    print(f"Response ID: {result.get('response_id', 'N/A')}")
    print(f"Actions executed: {len(result.get('actions', []))}")

    return result


if __name__ == "__main__":
    # Run demo for testing
    asyncio.run(demo_response_engine())
