"""
Wazuh Configuration Management
Handles all Wazuh-related configuration settings and validation.
"""

import os
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class AlertSeverity(Enum):
    """Alert severity levels for threat classification."""
    LOW = 1
    MEDIUM = 5
    HIGH = 10
    CRITICAL = 15


class ResponseAction(Enum):
    """Available active response actions."""
    FIREWALL_DROP = "firewall-drop"
    HOST_DENY = "host-deny"  
    ROUTE_NULL = "route-null"
    WIN_ROUTE_NULL = "win_route-null"
    WIN_FIREWALL_DROP = "win_firewall-drop"
    CUSTOM_BLOCK = "custom-block"
    FILE_QUARANTINE = "quarantine-file"


@dataclass
class WazuhManagerConfig:
    """Wazuh Manager configuration settings."""
    host: str
    port: int = 55000
    protocol: str = "https"
    username: str = "wazuh"
    password: str = ""
    verify_ssl: bool = False
    timeout: int = 30

    @property
    def base_url(self) -> str:
        """Get the base URL for Wazuh API."""
        return f"{self.protocol}://{self.host}:{self.port}"

    @property
    def auth_url(self) -> str:
        """Get the authentication URL."""
        return f"{self.base_url}/security/user/authenticate"


@dataclass  
class ActiveResponseConfig:
    """Configuration for active response actions."""
    command: ResponseAction
    location: str = "local"
    timeout: int = 600
    level: Optional[int] = None
    rules_id: Optional[List[str]] = None
    rules_group: Optional[List[str]] = None
    agent_id: Optional[List[str]] = None

    def to_ossec_config(self) -> str:
        """Convert to OSSEC configuration format."""
        config_lines = ["<active-response>"]
        config_lines.append(f"  <command>{self.command.value}</command>")
        config_lines.append(f"  <location>{self.location}</location>")

        if self.timeout:
            config_lines.append(f"  <timeout>{self.timeout}</timeout>")

        if self.level:
            config_lines.append(f"  <level>{self.level}</level>")

        if self.rules_id:
            config_lines.append(f"  <rules_id>{','.join(self.rules_id)}</rules_id>")

        if self.rules_group:
            config_lines.append(f"  <rules_group>{','.join(self.rules_group)}</rules_group>")

        if self.agent_id:
            config_lines.append(f"  <agent_id>{','.join(self.agent_id)}</agent_id>")

        config_lines.append("</active-response>")
        return "\n".join(config_lines)


class WazuhConfig:
    """Main Wazuh configuration class."""

    def __init__(self):
        self.manager = self._load_manager_config()
        self.active_responses = self._load_active_response_configs()

    def _load_manager_config(self) -> WazuhManagerConfig:
        """Load Wazuh manager configuration from environment."""
        return WazuhManagerConfig(
            host=os.getenv('WAZUH_MANAGER_HOST', 'localhost'),
            port=int(os.getenv('WAZUH_MANAGER_PORT', '55000')),
            protocol=os.getenv('WAZUH_PROTOCOL', 'https'),
            username=os.getenv('WAZUH_API_USER', 'wazuh'),
            password=os.getenv('WAZUH_API_PASSWORD', 'wazuh'),
            verify_ssl=os.getenv('WAZUH_VERIFY_SSL', 'False').lower() == 'true',
            timeout=int(os.getenv('WAZUH_TIMEOUT', '30'))
        )

    def _load_active_response_configs(self) -> List[ActiveResponseConfig]:
        """Load predefined active response configurations."""
        return [
            # SSH Brute Force Protection
            ActiveResponseConfig(
                command=ResponseAction.FIREWALL_DROP,
                location="local",
                timeout=600,
                rules_id=["5763", "5764"]  # SSH authentication failed rules
            ),

            # Web Attack Protection  
            ActiveResponseConfig(
                command=ResponseAction.FIREWALL_DROP,
                location="local", 
                timeout=1800,
                rules_id=["31168", "31169", "31170"]  # Web attack rules
            ),

            # High Severity Alerts
            ActiveResponseConfig(
                command=ResponseAction.FIREWALL_DROP,
                location="local",
                timeout=3600,
                level=15  # Critical level alerts
            ),

            # Malware Detection
            ActiveResponseConfig(
                command=ResponseAction.FILE_QUARANTINE,
                location="local", 
                timeout=0,  # Permanent quarantine
                rules_group=["rootcheck", "malware"]
            )
        ]

    def get_response_config(self, rule_id: str = None, level: int = None) -> Optional[ActiveResponseConfig]:
        """Get appropriate response configuration based on alert criteria."""
        for response in self.active_responses:
            if rule_id and response.rules_id and rule_id in response.rules_id:
                return response
            if level and response.level and level >= response.level:
                return response
        return None

    def validate_config(self) -> List[str]:
        """Validate configuration and return any errors."""
        errors = []

        if not self.manager.host:
            errors.append("Wazuh manager host not configured")

        if not self.manager.password:
            errors.append("Wazuh API password not configured")

        if self.manager.port < 1 or self.manager.port > 65535:
            errors.append("Invalid Wazuh manager port")

        return errors


# Global configuration instance
wazuh_config = WazuhConfig()
