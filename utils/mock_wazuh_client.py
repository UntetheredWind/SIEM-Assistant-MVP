"""
Mock Wazuh Client for Development
Provides simulated Wazuh functionality when no real server is available.
"""

import logging
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import time

logger = logging.getLogger(__name__)


class MockWazuhClient:
    """Mock Wazuh client for development without real server."""
    
    def __init__(self, config=None):
        self.token = "mock-jwt-token-12345"
        self.connected = True
        logger.info("Initialized Mock Wazuh Client")
    
    def authenticate(self) -> str:
        """Mock authentication."""
        time.sleep(0.1)  # Simulate network delay
        return self.token
    
    def health_check(self) -> Tuple[bool, str]:
        """Mock health check."""
        return True, "Mock Wazuh client is healthy and responsive"
    
    def get_agents(self, params: Dict = None) -> Dict:
        """Mock get agents."""
        return {
            'data': {
                'affected_items': [
                    {
                        'id': '001',
                        'name': 'web-server-01',
                        'ip': '10.0.1.50',
                        'status': 'active',
                        'version': '4.13.1',
                        'os': {'platform': 'windows', 'name': 'Windows Server 2019'}
                    },
                    {
                        'id': '002', 
                        'name': 'db-server-02',
                        'ip': '10.0.1.51',
                        'status': 'active',
                        'version': '4.13.1',
                        'os': {'platform': 'linux', 'name': 'Ubuntu 20.04'}
                    },
                    {
                        'id': '003',
                        'name': 'workstation-03', 
                        'ip': '10.0.1.52',
                        'status': 'disconnected',
                        'version': '4.13.1',
                        'os': {'platform': 'windows', 'name': 'Windows 10'}
                    }
                ],
                'total_affected_items': 3
            }
        }
    
    def get_agent(self, agent_id: str) -> Dict:
        """Mock get specific agent."""
        agents = self.get_agents()['data']['affected_items']
        for agent in agents:
            if agent['id'] == agent_id:
                return {'data': {'affected_items': [agent]}}
        return {'data': {'affected_items': []}}
    
    def get_alerts(self, params: Dict = None) -> Dict:
        """Generate mock alerts."""
        limit = params.get('limit', 10) if params else 10
        alerts = []
        
        alert_templates = [
            {
                'rule': {
                    'level': 10,
                    'id': '5763',
                    'description': 'SSH authentication failed',
                    'groups': ['authentication_failed', 'sshd']
                },
                'data': {'srcip': f'192.168.1.{random.randint(100, 200)}'},
                'agent': {'id': '001', 'name': 'web-server-01'}
            },
            {
                'rule': {
                    'level': 12,
                    'id': '31168', 
                    'description': 'Web attack detected',
                    'groups': ['web', 'attack']
                },
                'data': {'srcip': f'203.0.113.{random.randint(1, 100)}'},
                'agent': {'id': '001', 'name': 'web-server-01'}
            },
            {
                'rule': {
                    'level': 15,
                    'id': '592',
                    'description': 'Malware detected',
                    'groups': ['malware', 'rootcheck']
                },
                'data': {'srcip': '10.0.1.75'},
                'agent': {'id': '002', 'name': 'db-server-02'}
            },
            {
                'rule': {
                    'level': 7,
                    'id': '550',
                    'description': 'File integrity monitoring alert',
                    'groups': ['syscheck', 'file_changed']
                },
                'data': {'file': '/etc/passwd'},
                'agent': {'id': '002', 'name': 'db-server-02'}
            }
        ]
        
        for i in range(min(limit, 20)):  # Max 20 mock alerts
            template = random.choice(alert_templates)
            alert = template.copy()
            alert['id'] = f'mock_alert_{i:04d}'
            alert['timestamp'] = (datetime.now() - timedelta(minutes=random.randint(1, 1440))).isoformat()
            alert['full_log'] = self._generate_mock_log(alert)
            alerts.append(alert)
        
        return {
            'data': {
                'affected_items': alerts,
                'total_affected_items': len(alerts)
            }
        }
    
    def get_rules(self, params: Dict = None) -> Dict:
        """Mock get rules."""
        return {
            'data': {
                'affected_items': [
                    {
                        'id': '5763',
                        'level': 10,
                        'description': 'SSH authentication failed',
                        'groups': ['authentication_failed', 'sshd']
                    },
                    {
                        'id': '31168',
                        'level': 12,
                        'description': 'Web attack detected', 
                        'groups': ['web', 'attack']
                    },
                    {
                        'id': '592',
                        'level': 15,
                        'description': 'Malware detected',
                        'groups': ['malware', 'rootcheck']
                    }
                ]
            }
        }
    
    def run_active_response(self, agent_id: str, command: str, arguments: List[str] = None) -> Dict:
        """Mock active response execution."""
        time.sleep(0.5)  # Simulate execution time
        
        return {
            'data': {
                'message': f'[SIMULATED] Active response executed successfully',
                'command': command,
                'agent_id': agent_id,
                'arguments': arguments or [],
                'status': 'completed',
                'simulation': True
            }
        }
    
    def get_manager_info(self) -> Dict:
        """Mock manager information."""
        return {
            'data': {
                'affected_items': [{
                    'version': 'v4.13.1',
                    'compilation_date': '2024-09-30',
                    'installation_date': '2025-09-30T12:00:00Z',
                    'hostname': 'mock-wazuh-manager',
                    'type': 'mock',
                    'max_agents': 'unlimited'
                }]
            }
        }
    
    def get_syscollector_info(self, agent_id: str, component: str = None) -> Dict:
        """Mock syscollector information."""
        mock_data = {
            'os': {
                'hostname': f'host-{agent_id}',
                'architecture': 'x86_64',
                'os_name': 'Windows Server 2019' if agent_id == '001' else 'Ubuntu 20.04'
            },
            'hardware': {
                'cpu_cores': 4,
                'cpu_name': 'Intel Core i7',
                'ram_total': '16384MB'
            },
            'packages': [
                {'name': 'openssh-server', 'version': '8.2p1'},
                {'name': 'nginx', 'version': '1.18.0'}
            ]
        }
        
        if component:
            return {'data': {'affected_items': [mock_data.get(component, {})]}}
        return {'data': {'affected_items': [mock_data]}}
    
    def _generate_mock_log(self, alert: Dict) -> str:
        """Generate realistic log entries for alerts."""
        rule_id = alert['rule']['id']
        timestamp = datetime.now().strftime('%b %d %H:%M:%S')
        
        log_templates = {
            '5763': f'{timestamp} web-server sshd[29205]: Authentication failure for admin from {alert.get("data", {}).get("srcip", "192.168.1.100")}',
            '31168': f'{timestamp} web-server nginx: 192.168.1.10 - - "GET /admin/login.php?user=admin&pass=123456" 200 1234',
            '592': f'{timestamp} db-server ossec: File \'/etc/passwd\' modified',
            '550': f'{timestamp} db-server kernel: Possible rootkit detected in /usr/bin/ls'
        }
        
        return log_templates.get(rule_id, f'{timestamp} mock-server: Sample log entry for rule {rule_id}')
    
    def close(self):
        """Clean up mock client."""
        logger.info("Mock Wazuh client closed")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def create_mock_client():
    """Factory function for creating mock client."""
    return MockWazuhClient()