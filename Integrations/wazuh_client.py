"""
Wazuh API Client
Production-ready wrapper for Wazuh Manager API interactions.
Handles authentication, request management, and error handling.
"""

import json
import requests
import logging
from base64 import b64encode
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
import urllib3
from requests.exceptions import RequestException, Timeout, ConnectionError

try:
    from config.wazuh_config import WazuhConfig, wazuh_config
except ImportError:
    # Fallback configuration if config file is missing
    class FallbackWazuhConfig:
        def __init__(self):
            self.manager = type('obj', (object,), {
                'host': 'localhost',
                'port': 55000,
                'protocol': 'https',
                'username': 'wazuh',
                'password': 'wazuh',
                'verify_ssl': False,
                'timeout': 30,
                'base_url': 'https://localhost:55000',
                'auth_url': 'https://localhost:55000/security/user/authenticate'
            })()

    wazuh_config = FallbackWazuhConfig()

# Suppress SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class WazuhAPIError(Exception):
    """Custom exception for Wazuh API errors."""
    def __init__(self, message: str, status_code: int = None, response: str = None):
        self.message = message
        self.status_code = status_code
        self.response = response
        super().__init__(self.message)


class WazuhClient:
    """
    Production-ready Wazuh API client with authentication, error handling,
    and comprehensive API coverage for security operations.
    """

    def __init__(self, config=None):
        self.config = config or wazuh_config
        self.token = None
        self.token_expires = None
        self.session = requests.Session()

        # Configure session
        self.session.verify = self.config.manager.verify_ssl
        self.session.timeout = self.config.manager.timeout

    def authenticate(self) -> str:
        """
        Authenticate with Wazuh API and obtain JWT token.

        Returns:
            JWT token string

        Raises:
            WazuhAPIError: Authentication failed
        """
        try:
            # Prepare basic authentication
            credentials = f"{self.config.manager.username}:{self.config.manager.password}"
            encoded_credentials = b64encode(credentials.encode()).decode()

            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Basic {encoded_credentials}'
            }

            # Make authentication request
            response = self.session.post(
                self.config.manager.auth_url,
                headers=headers,
                params={'raw': 'true'}  # Get plain token
            )

            if response.status_code == 200:
                self.token = response.text.strip()
                # Token expires in 15 minutes by default
                self.token_expires = datetime.now() + timedelta(minutes=15)
                logger.info("Successfully authenticated with Wazuh API")
                return self.token
            else:
                error_msg = f"Authentication failed: {response.status_code} - {response.text}"
                logger.error(error_msg)
                raise WazuhAPIError(error_msg, response.status_code, response.text)

        except RequestException as e:
            error_msg = f"Connection error during authentication: {str(e)}"
            logger.error(error_msg)
            raise WazuhAPIError(error_msg)

    def _ensure_authenticated(self):
        """Ensure we have a valid authentication token."""
        if not self.token or (self.token_expires and datetime.now() >= self.token_expires):
            self.authenticate()

    def _make_request(self, method: str, endpoint: str, params: Dict = None, 
                     data: Dict = None, json_data: Dict = None) -> Dict:
        """
        Make authenticated request to Wazuh API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path
            params: URL parameters
            data: Form data
            json_data: JSON data for request body

        Returns:
            API response as dictionary

        Raises:
            WazuhAPIError: API request failed
        """
        self._ensure_authenticated()

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.token}'
        }

        url = f"{self.config.manager.base_url}/{endpoint.lstrip('/')}"

        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                json=json_data
            )

            if response.status_code in [200, 201]:
                return response.json() if response.text else {}
            else:
                error_msg = f"API request failed: {response.status_code} - {response.text}"
                logger.error(f"{method} {url} failed: {error_msg}")
                raise WazuhAPIError(error_msg, response.status_code, response.text)

        except RequestException as e:
            error_msg = f"Request error: {str(e)}"
            logger.error(error_msg)
            raise WazuhAPIError(error_msg)

    # Agent Management Methods

    def get_agents(self, params: Dict = None) -> Dict:
        """Get list of Wazuh agents."""
        return self._make_request('GET', '/agents', params=params)

    def get_agent(self, agent_id: str) -> Dict:
        """Get specific agent information."""
        return self._make_request('GET', f'/agents/{agent_id}')

    def restart_agent(self, agent_id: str) -> Dict:
        """Restart specific Wazuh agent."""
        return self._make_request('PUT', f'/agents/{agent_id}/restart')

    def delete_agent(self, agent_id: str) -> Dict:
        """Delete Wazuh agent."""
        return self._make_request('DELETE', f'/agents/{agent_id}')

    # Active Response Methods

    def run_active_response(self, agent_id: str, command: str, arguments: List[str] = None) -> Dict:
        """
        Execute active response command on agent.

        Args:
            agent_id: Target agent ID
            command: Active response command name
            arguments: Command arguments

        Returns:
            API response
        """
        data = {
            'command': command,
            'arguments': arguments or []
        }
        return self._make_request('PUT', f'/active-response/{agent_id}', json_data=data)

    def get_active_responses(self) -> Dict:
        """Get available active response commands."""
        return self._make_request('GET', '/active-response')

    # Alert and Events Methods

    def get_alerts(self, params: Dict = None) -> Dict:
        """
        Get security alerts from Wazuh.

        Args:
            params: Query parameters (limit, offset, sort, search, etc.)

        Returns:
            Alerts data
        """
        default_params = {
            'limit': 500,
            'sort': '-timestamp',
            'pretty': 'true'
        }
        if params:
            default_params.update(params)

        return self._make_request('GET', '/alerts', params=default_params)

    def get_alert_summary(self) -> Dict:
        """Get alert summary statistics."""
        return self._make_request('GET', '/alerts/summary')

    # Rules and Decoders

    def get_rules(self, params: Dict = None) -> Dict:
        """Get Wazuh rules."""
        return self._make_request('GET', '/rules', params=params)

    def get_rule(self, rule_id: str) -> Dict:
        """Get specific rule information."""
        return self._make_request('GET', f'/rules/{rule_id}')

    def test_rule(self, rule_data: Dict) -> Dict:
        """Test rule configuration."""
        return self._make_request('POST', '/rules/test', json_data=rule_data)

    # Manager and Cluster Methods

    def get_manager_info(self) -> Dict:
        """Get Wazuh manager information."""
        return self._make_request('GET', '/')

    def restart_manager(self) -> Dict:
        """Restart Wazuh manager."""
        return self._make_request('PUT', '/manager/restart')

    def get_cluster_status(self) -> Dict:
        """Get cluster status information."""
        return self._make_request('GET', '/cluster/status')

    def get_cluster_nodes(self) -> Dict:
        """Get cluster nodes information."""
        return self._make_request('GET', '/cluster/nodes')

    # Security Events Analysis

    def get_mitre_attacks(self, params: Dict = None) -> Dict:
        """Get MITRE ATT&CK framework information."""
        return self._make_request('GET', '/mitre', params=params)

    def get_syscollector_info(self, agent_id: str, component: str = None) -> Dict:
        """
        Get system collector information from agent.

        Args:
            agent_id: Agent ID
            component: Specific component (os, hardware, packages, etc.)
        """
        endpoint = f'/syscollector/{agent_id}'
        if component:
            endpoint += f'/{component}'
        return self._make_request('GET', endpoint)

    # File Integrity Monitoring

    def get_syscheck_events(self, agent_id: str, params: Dict = None) -> Dict:
        """Get File Integrity Monitoring events for agent."""
        return self._make_request('GET', f'/syscheck/{agent_id}', params=params)

    def clear_syscheck_database(self, agent_id: str) -> Dict:
        """Clear syscheck database for agent."""
        return self._make_request('DELETE', f'/syscheck/{agent_id}')

    # Configuration Management

    def get_agent_config(self, agent_id: str, component: str = None) -> Dict:
        """Get agent configuration."""
        endpoint = f'/agents/{agent_id}/config'
        if component:
            endpoint += f'/{component}'
        return self._make_request('GET', endpoint)

    def update_agent_config(self, agent_id: str, config_data: Dict) -> Dict:
        """Update agent configuration."""
        return self._make_request('PUT', f'/agents/{agent_id}/config', json_data=config_data)

    # Utility Methods

    def health_check(self) -> Tuple[bool, str]:
        """
        Check Wazuh API connectivity and health.

        Returns:
            Tuple of (is_healthy, status_message)
        """
        try:
            response = self.get_manager_info()
            if response.get('data'):
                return True, "Wazuh API is healthy and responsive"
            else:
                return False, "Wazuh API responded but returned no data"
        except WazuhAPIError as e:
            return False, f"Wazuh API health check failed: {e.message}"
        except Exception as e:
            return False, f"Unexpected error during health check: {str(e)}"

    def get_api_info(self) -> Dict:
        """Get API version and configuration information."""
        return self._make_request('GET', '/?pretty=true')

    def close(self):
        """Clean up resources."""
        if self.session:
            self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# Factory function for easy client creation
def create_wazuh_client(config=None) -> WazuhClient:
    """Create and authenticate Wazuh client."""
    client = WazuhClient(config)
    client.authenticate()
    return client
