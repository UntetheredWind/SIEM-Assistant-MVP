import streamlit as st
from components.chat_interface import SIEMChatInterface
from utils.chat_manager import ChatManager
from datetime import datetime
import os
from dotenv import load_dotenv
import logging

# Add after imports
st.sidebar.success("🆕 Check out our **Space Security Module** →")
st.sidebar.info("💡 **USP Highlight:** Specialized for ISRO satellite operations with CCSDS protocol support")

# Add mission context selector
st.sidebar.divider()
st.sidebar.subheader("🛰️ Mission Context")
mission = st.sidebar.selectbox(
    "Active Mission",
    ["None", "Chandrayaan-4 🌙", "Gaganyaan-1 👨‍🚀", "GSAT-31 📡", "PSLV-C58 🚀"]
)

if mission != "None":
    st.sidebar.success(f"**Monitoring:** {mission}")
    phase = st.sidebar.select_slider(
        "Mission Phase",
        options=["Pre-Launch", "Launch", "LEOP", "Nominal Ops", "Maneuver"],
        value="Nominal Ops"
    )

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Import Wazuh integration components with better error handling
WAZUH_INTEGRATION_AVAILABLE = False
wazuh_import_error = None

try:
    # Check if required files exist
    import sys
    from pathlib import Path

    # Add current directory to path
    current_dir = Path(__file__).parent
    sys.path.insert(0, str(current_dir))

    # Try importing with correct capitalization - "Integrations" not "integrations"
    try:
        from Integrations.wazuh_client import WazuhClient
        logger.info("Successfully imported WazuhClient")
    except ImportError as e:
        logger.error(f"Failed to import WazuhClient: {e}")
        raise

    try:
        from utils.mock_wazuh_client import MockWazuhClient
        logger.info("Successfully imported MockWazuhClient")
    except ImportError as e:
        logger.error(f"Failed to import MockWazuhClient: {e}")
        raise

    try:
        from Integrations.active_response import ActiveResponseEngine
        logger.info("Successfully imported ActiveResponseEngine")
    except ImportError as e:
        logger.error(f"Failed to import ActiveResponseEngine: {e}")
        raise

    try:
        from utils.threat_analyzer import ThreatAnalyzer
        logger.info("Successfully imported ThreatAnalyzer")
    except ImportError as e:
        logger.error(f"Failed to import ThreatAnalyzer: {e}")
        raise

    WAZUH_INTEGRATION_AVAILABLE = True
    logger.info("All Wazuh integration components loaded successfully")

except ImportError as e:
    wazuh_import_error = str(e)
    logger.error(f"Wazuh integration not available: {e}")
    WAZUH_INTEGRATION_AVAILABLE = False

# Enhanced Fallback MockWazuhClient with more features
class FallbackMockWazuhClient:
    """Enhanced fallback mock client when imports fail"""

    def __init__(self):
        self.connected = True
        logger.info("Using enhanced fallback mock Wazuh client")

    def authenticate(self):
        return "fallback-mock-token"

    def health_check(self):
        return True, "Enhanced fallback mock client active"

    def get_agents(self, params=None):
        return {
            'data': {
                'affected_items': [
                    {
                        'id': '001', 
                        'name': 'web-server-01', 
                        'status': 'active',
                        'ip': '10.0.1.10',
                        'version': '4.13.1',
                        'os': {'platform': 'windows', 'name': 'Windows Server 2019'}
                    },
                    {
                        'id': '002', 
                        'name': 'db-server-02', 
                        'status': 'active',
                        'ip': '10.0.1.11',
                        'version': '4.13.1',
                        'os': {'platform': 'linux', 'name': 'Ubuntu 20.04'}
                    },
                    {
                        'id': '003', 
                        'name': 'workstation-03', 
                        'status': 'disconnected',
                        'ip': '10.0.1.12',
                        'version': '4.13.1',
                        'os': {'platform': 'windows', 'name': 'Windows 10'}
                    }
                ],
                'total_affected_items': 3
            }
        }

    def get_alerts(self, params=None):
        import random
        from datetime import timedelta

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
            }
        ]

        for i in range(min(limit, 8)):
            template = random.choice(alert_templates)
            alert = template.copy()
            alert['id'] = f'fallback_alert_{i:03d}'
            alert['timestamp'] = (datetime.now() - timedelta(minutes=random.randint(1, 60))).isoformat()
            alert['full_log'] = f'{datetime.now().strftime("%b %d %H:%M:%S")} {alert["agent"]["name"]} ossec: {alert["rule"]["description"]} from {alert["data"]["srcip"]}'
            alerts.append(alert)

        return {
            'data': {
                'affected_items': alerts,
                'total_affected_items': len(alerts)
            }
        }

    def run_active_response(self, agent_id, command, arguments=None):
        return {
            'data': {
                'message': f'[SIMULATED] Command {command} executed on agent {agent_id}',
                'command': command,
                'agent_id': agent_id,
                'arguments': arguments or [],
                'status': 'completed',
                'simulation': True
            }
        }

    def get_manager_info(self):
        return {
            'data': {
                'affected_items': [{
                    'version': 'v4.13.1-fallback',
                    'compilation_date': '2024-09-30',
                    'installation_date': '2025-09-30T12:00:00Z',
                    'hostname': 'fallback-mock-manager',
                    'type': 'fallback_mock'
                }]
            }
        }

    def get_rules(self, params=None):
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
                    }
                ]
            }
        }

# Page configuration
st.set_page_config(
    page_title="SIEM Assistant MVP",
    page_icon="shield",  
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://github.com/your-repo/siem-assistant',
        'Report a bug': 'https://github.com/your-repo/siem-assistant/issues',
        'About': "# SIEM Assistant MVP\nAI-powered security analysis with proactive triage and educational features."
    }
)

# Initialize session state variables FIRST
def initialize_session_state():
    """Initialize all session state variables"""
    # Initialize chat system variables
    if "chat_sessions" not in st.session_state:
        st.session_state.chat_sessions = {}

    if "current_session_id" not in st.session_state:
        st.session_state.current_session_id = None

    # Initialize modal states
    if "show_proactive_modal" not in st.session_state:
        st.session_state.show_proactive_modal = False

    if "show_query_modal" not in st.session_state:
        st.session_state.show_query_modal = False

    if "show_log_modal" not in st.session_state:
        st.session_state.show_log_modal = False

    # Initialize page load time
    if 'page_load_time' not in st.session_state:
        st.session_state.page_load_time = datetime.now()

    # Initialize Wazuh integration state
    if 'wazuh_client' not in st.session_state:
        st.session_state.wazuh_client = None

    if 'wazuh_status' not in st.session_state:
        st.session_state.wazuh_status = {'connected': False, 'message': 'Not initialized'}

# Call initialization function FIRST
initialize_session_state()

# Wazuh Integration Functions
def get_wazuh_client():
    """Get appropriate Wazuh client based on environment configuration."""
    if st.session_state.wazuh_client is None:
        try:
            # Check if running in development/mock mode
            development_mode = os.getenv('WAZUH_DEVELOPMENT_MODE', 'true').lower() == 'true'

            if WAZUH_INTEGRATION_AVAILABLE:
                if development_mode:
                    st.session_state.wazuh_client = MockWazuhClient()
                    st.session_state.wazuh_status = {
                        'connected': True, 
                        'message': 'Mock Wazuh client active (Development Mode)',
                        'mode': 'mock'
                    }
                    logger.info("Using MockWazuhClient in development mode")
                else:
                    try:
                        st.session_state.wazuh_client = WazuhClient()
                        health, message = st.session_state.wazuh_client.health_check()
                        st.session_state.wazuh_status = {
                            'connected': health,
                            'message': message,
                            'mode': 'real'
                        }
                        logger.info("Using real WazuhClient")
                    except Exception as e:
                        # Fallback to mock client if real connection fails
                        st.session_state.wazuh_client = MockWazuhClient()
                        st.session_state.wazuh_status = {
                            'connected': True,
                            'message': f'Fallback to mock mode: {str(e)}',
                            'mode': 'fallback_mock'
                        }
                        logger.warning(f"Fallback to mock client: {e}")
            else:
                # Use enhanced fallback client when imports fail
                st.session_state.wazuh_client = FallbackMockWazuhClient()
                st.session_state.wazuh_status = {
                    'connected': True,
                    'message': f'Using enhanced fallback client. Files missing from Integrations folder.',
                    'mode': 'fallback'
                }
                logger.info("Using Enhanced FallbackMockWazuhClient")

        except Exception as e:
            # Final fallback
            st.session_state.wazuh_client = FallbackMockWazuhClient()
            st.session_state.wazuh_status = {
                'connected': True,
                'message': f'Emergency fallback: {str(e)}',
                'mode': 'emergency_fallback'
            }
            logger.error(f"Emergency fallback: {e}")

    return st.session_state.wazuh_client

def get_wazuh_stats():
    """Get Wazuh statistics for dashboard - COMPLETELY ISOLATED from chat functionality."""
    try:
        client = get_wazuh_client()
        if client is None:
            logger.warning("Wazuh client is None")
            return {
                'agents_count': 0,
                'alerts_today': 0,
                'active_responses': 0,
                'threat_level': 'Unknown'
            }

        # Get agents count - with complete error handling
        try:
            agents_response = client.get_agents(params={'limit': 1})
            if not agents_response or 'data' not in agents_response:
                logger.warning("Invalid agents response structure")
                agents_count = 0
            else:
                agents_count = agents_response.get('data', {}).get('total_affected_items', 0)
        except Exception as agents_error:
            logger.error(f"Error getting agents: {agents_error}")
            agents_count = 0

        # Get recent alerts count - with complete error handling
        try:
            alerts_response = client.get_alerts(params={'limit': 100})
            if not alerts_response or 'data' not in alerts_response:
                logger.warning("Invalid alerts response structure")
                alerts_today = 0
                alerts = []
            else:
                affected_items = alerts_response.get('data', {}).get('affected_items', [])
                alerts_today = len(affected_items) if affected_items else 0
                alerts = affected_items
        except Exception as alerts_error:
            logger.error(f"Error getting alerts: {alerts_error}")
            alerts_today = 0
            alerts = []

        # Calculate threat level based on recent alerts - with complete error handling
        try:
            high_severity_alerts = 0
            if alerts:
                for alert in alerts:
                    try:
                        rule_level = alert.get('rule', {}).get('level', 0) if alert else 0
                        if rule_level >= 10:
                            high_severity_alerts += 1
                    except Exception as alert_parse_error:
                        logger.warning(f"Error parsing individual alert: {alert_parse_error}")
                        continue

            if high_severity_alerts > 3:
                threat_level = 'HIGH'
            elif high_severity_alerts > 1:
                threat_level = 'MEDIUM'
            else:
                threat_level = 'LOW'
        except Exception as threat_error:
            logger.error(f"Error calculating threat level: {threat_error}")
            threat_level = 'LOW'

        final_stats = {
            'agents_count': agents_count,
            'alerts_today': alerts_today,
            'active_responses': 0,
            'threat_level': threat_level
        }

        logger.info(f"Successfully calculated Wazuh stats: {final_stats}")
        return final_stats

    except Exception as e:
        logger.error(f"Complete error in get_wazuh_stats: {e}")
        logger.error(f"Exception type: {type(e).__name__}")
        logger.error(f"Exception args: {e.args}")
        return {
            'agents_count': 0,
            'alerts_today': 0,
            'active_responses': 0,
            'threat_level': 'Error',
            'error': str(e)
        }

def simulate_high_severity_alert():
    """Simulate a high-severity security alert for demonstration."""
    try:
        client = get_wazuh_client()
        if client is None:
            logger.warning("Cannot simulate alert - no Wazuh client")
            return None

        # Generate a mock high-severity alert
        mock_alert = {
            'id': f'demo_alert_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
            'timestamp': datetime.now().isoformat(),
            'rule': {
                'level': 15,
                'id': '31168',
                'description': 'Multiple web attack attempts detected',
                'groups': ['web', 'attack', 'exploit']
            },
            'data': {
                'srcip': '203.0.113.42',
                'srcuser': 'attacker',
                'url': '/admin/login.php'
            },
            'agent': {
                'id': '001',
                'name': 'web-server-01',
                'ip': '10.0.1.50'
            },
            'full_log': f'{datetime.now().strftime("%b %d %H:%M:%S")} web-server nginx: 203.0.113.42 - - "POST /admin/login.php" 200 1234 "Mozilla/5.0 (Attack Tool)"'
        }

        return mock_alert
    except Exception as e:
        logger.error(f"Error simulating alert: {e}")
        return None

# Custom CSS (same as before, keeping all styling)
st.markdown("""
<style>
/* Global Styles */
.main {
    padding-top: 1rem;
}

/* Sidebar Enhancements */
.css-1d391kg {
    padding-top: 1rem;
    background: linear-gradient(180deg, #f8f9fa 0%, #e9ecef 100%);
}

.sidebar .sidebar-content {
    background: transparent;
}

/* Chat History Styling */
.chat-session-current {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
    color: white !important;
    border: none !important;
    font-weight: 600 !important;
}

.chat-session-normal {
    background: rgba(255, 255, 255, 0.9) !important;
    border: 1px solid #e1e5e9 !important;
    color: #495057 !important;
    transition: all 0.3s ease !important;
}

.chat-session-normal:hover {
    background: rgba(102, 126, 234, 0.1) !important;
    border-color: #667eea !important;
    transform: translateX(4px) !important;
}

/* Main Title Styling */
.main-title {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    font-size: 2.5rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
}

.main-subtitle {
    color: #6c757d;
    font-size: 1.1rem;
    font-weight: 400;
    margin-bottom: 2rem;
}

/* Sidebar Section Headers */
.sidebar-header {
    color: #495057;
    font-size: 1.1rem;
    font-weight: 600;
    margin: 1rem 0 0.5rem 0;
    padding-bottom: 0.5rem;
    border-bottom: 2px solid #e9ecef;
}

/* USP Cards */
.usp-card {
    background: rgba(255, 255, 255, 0.9);
    padding: 1rem;
    border-radius: 10px;
    border-left: 4px solid #667eea;
    margin: 0.5rem 0;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.usp-title {
    font-weight: 600;
    color: #495057;
    margin-bottom: 0.5rem;
}

.usp-description {
    font-size: 0.9rem;
    color: #6c757d;
    line-height: 1.4;
}

/* Status Indicators */
.status-online {
    color: #28a745;
    font-weight: 600;
}

.status-mock {
    color: #ffc107;
    font-weight: 600;
}

.status-offline {
    color: #dc3545;
    font-weight: 600;
}

.status-indicator {
    display: inline-block;
    width: 8px;
    height: 8px;
    background: #28a745;
    border-radius: 50%;
    margin-right: 8px;
    animation: pulse 2s infinite;
}

.status-indicator.mock {
    background: #ffc107;
}

.status-indicator.offline {
    background: #dc3545;
    animation: none;
}

.status-indicator.fallback {
    background: #17a2b8;
}

@keyframes pulse {
    0% { opacity: 1; }
    50% { opacity: 0.5; }
    100% { opacity: 1; }
}

/* Wazuh Status Cards */
.wazuh-status-card {
    background: rgba(255, 255, 255, 0.95);
    padding: 0.75rem;
    border-radius: 8px;
    border: 1px solid #e9ecef;
    margin: 0.25rem 0;
    box-shadow: 0 1px 4px rgba(0, 0, 0, 0.1);
}

.wazuh-metric {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.25rem 0;
}

.wazuh-metric-value {
    font-weight: 600;
    color: #495057;
}

.threat-level-high { color: #dc3545; }
.threat-level-medium { color: #ffc107; }
.threat-level-low { color: #28a745; }

/* Session Meta Info */
.session-meta {
    font-size: 0.75rem;
    color: #6c757d;
    margin-top: 0.25rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.session-stats {
    display: flex;
    gap: 0.5rem;
    align-items: center;
}

/* Session Count Badge */
.session-count {
    background: #667eea;
    color: white;
    font-size: 0.75rem;
    padding: 2px 6px;
    border-radius: 12px;
    font-weight: 600;
}

/* Error/Warning Messages */
.wazuh-error {
    background: #f8d7da;
    color: #721c24;
    padding: 0.75rem;
    border-radius: 0.25rem;
    border: 1px solid #f5c6cb;
    margin: 0.5rem 0;
}

.wazuh-warning {
    background: #fff3cd;
    color: #856404;
    padding: 0.75rem;
    border-radius: 0.25rem;
    border: 1px solid #ffeaa7;
    margin: 0.5rem 0;
}

.wazuh-info {
    background: #d1ecf1;
    color: #0c5460;
    padding: 0.75rem;
    border-radius: 0.25rem;
    border: 1px solid #bee5eb;
    margin: 0.5rem 0;
}

.wazuh-success {
    background: #d4edda;
    color: #155724;
    padding: 0.75rem;
    border-radius: 0.25rem;
    border: 1px solid #c3e6cb;
    margin: 0.5rem 0;
}
</style>
""", unsafe_allow_html=True)

# Initialize chat manager
def get_chat_manager():
    """Get or create chat manager instance"""
    if 'chat_manager' not in st.session_state:
        st.session_state.chat_manager = ChatManager()
    return st.session_state.chat_manager

chat_manager = get_chat_manager()

# Initialize Wazuh client
wazuh_client = get_wazuh_client()

# Application header
st.markdown('<h1 class="main-title">SIEM Assistant MVP</h1>', unsafe_allow_html=True)
st.markdown('<p class="main-subtitle">Intelligent Security Analysis with Proactive Triage & Educational Features</p>', unsafe_allow_html=True)

# Sidebar Configuration
with st.sidebar:
    # Wazuh Status indicator
    wazuh_status = st.session_state.wazuh_status

    # Determine status display
    if wazuh_status['connected']:
        mode = wazuh_status.get('mode', 'unknown')
        if mode == 'mock':
            status_class = "status-indicator mock"
            status_text = "status-mock"
            status_message = "Wazuh Mock Mode"
        elif mode in ['fallback', 'fallback_mock', 'emergency_fallback']:
            status_class = "status-indicator fallback"
            status_text = "status-mock"
            status_message = "Wazuh Fallback Mode"
        else:
            status_class = "status-indicator"
            status_text = "status-online"
            status_message = "Wazuh Connected"
    else:
        status_class = "status-indicator offline"
        status_text = "status-offline"
        status_message = "Wazuh Offline"

    st.markdown(f"""
    <div style="text-align: center; margin-bottom: 1rem;">
        <span class="{status_class}"></span>
        <span class="{status_text}">{status_message}</span>
    </div>
    """, unsafe_allow_html=True)

    # Show integration status details
    if not WAZUH_INTEGRATION_AVAILABLE:
        if wazuh_import_error:
            st.markdown(f"""
            <div class="wazuh-warning">
                <strong>Integration Note:</strong><br>
                Wazuh files not found in Integrations folder.<br>
                <small>Using enhanced fallback client with full functionality.</small>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="wazuh-success">
                <strong>Fallback Mode Active:</strong><br>
                Enhanced mock client providing full SIEM capabilities for demonstration.
            </div>
            """, unsafe_allow_html=True)

    # Wazuh Statistics (completely isolated and error-proof)
    st.markdown('<div class="sidebar-header">Security Overview</div>', unsafe_allow_html=True)

    # COMPLETELY WRAPPED in try-except with no possibility of error propagation
    wazuh_stats_success = False
    try:
        wazuh_stats = get_wazuh_stats()
        wazuh_stats_success = True
    except Exception as wazuh_stats_error:
        logger.error(f"Critical error in Wazuh stats section: {wazuh_stats_error}")
        logger.error(f"Error type: {type(wazuh_stats_error).__name__}")
        wazuh_stats = {
            'agents_count': 0,
            'alerts_today': 0,
            'active_responses': 0,
            'threat_level': 'Error'
        }

    if wazuh_stats_success:
        try:
            # Create metrics display
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Agents", wazuh_stats.get('agents_count', 0), delta=None)
                st.metric("Alerts Today", wazuh_stats.get('alerts_today', 0), delta=None)

            with col2:
                threat_level = wazuh_stats.get('threat_level', 'Unknown')
                threat_color = {
                    'HIGH': 'threat-level-high',
                    'MEDIUM': 'threat-level-medium', 
                    'LOW': 'threat-level-low'
                }.get(threat_level, '')

                st.markdown(f"""
                <div class="wazuh-status-card">
                    <div class="wazuh-metric">
                        <span>Threat Level:</span>
                        <span class="wazuh-metric-value {threat_color}">{threat_level}</span>
                    </div>
                    <div class="wazuh-metric">
                        <span>Mode:</span>
                        <span class="wazuh-metric-value">{wazuh_status.get('mode', 'unknown').replace('_', ' ').title()}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
        except Exception as display_error:
            logger.error(f"Error displaying Wazuh stats: {display_error}")
            st.error("Error displaying security overview")
    else:
        st.error("Unable to load security statistics")

    # Alert Simulation Button (completely isolated)
    try:
        if st.button("Simulate High-Severity Alert", key="simulate_alert", use_container_width=True, help="Trigger a mock high-severity security alert for demonstration"):
            mock_alert = simulate_high_severity_alert()
            if mock_alert:
                st.session_state.demo_alert = mock_alert
                st.success("High-severity alert simulated! Check the chat interface for proactive analysis.")

                # Auto-trigger chat response
                try:
                    if hasattr(st.session_state, 'chat_manager'):
                        alert_message = f"""HIGH-SEVERITY ALERT DETECTED

**Alert ID**: {mock_alert['id']}
**Rule**: {mock_alert['rule']['description']} (Level {mock_alert['rule']['level']})
**Source IP**: {mock_alert['data']['srcip']}
**Agent**: {mock_alert['agent']['name']}
**Time**: {mock_alert['timestamp']}

**Proactive Analysis**:
This appears to be a coordinated web application attack targeting administrative interfaces. The attack is originating from IP {mock_alert['data']['srcip']} and targeting the login portal at {mock_alert['data']['url']}.

**Recommended Actions**:
1. Block source IP {mock_alert['data']['srcip']} immediately
2. Investigate other attempts from this IP
3. Review web application firewall rules
4. Check for similar patterns in recent logs

**MITRE ATT&CK Mapping**: T1190 (Exploit Public-Facing Application)

Would you like me to execute any active response actions or provide additional analysis?"""

                        # Add this to current chat session
                        if st.session_state.current_session_id:
                            current_session = st.session_state.chat_sessions.get(st.session_state.current_session_id)
                            if current_session and isinstance(current_session, dict):
                                if 'messages' not in current_session:
                                    current_session['messages'] = []
                                current_session['messages'].append({
                                    'role': 'assistant',
                                    'content': alert_message,
                                    'timestamp': datetime.now(),
                                    'alert_data': mock_alert
                                })
                                current_session['message_count'] = current_session.get('message_count', 0) + 1
                                current_session['last_updated'] = datetime.now()
                except Exception as chat_error:
                    logger.error(f"Error adding alert to chat: {chat_error}")

                st.rerun()
            else:
                st.error("Failed to simulate alert")
    except Exception as button_error:
        logger.error(f"Error with alert simulation button: {button_error}")
        st.error("Alert simulation unavailable")

    st.markdown("---")

    # Chat History Section (completely isolated from Wazuh)
    st.markdown('<div class="sidebar-header">Chat History</div>', unsafe_allow_html=True)

    # New Chat button with enhanced styling
    col1, col2 = st.columns([3, 1])
    with col1:
        if st.button("+ New Chat Session", type="primary", use_container_width=True, key="new_chat_main"):
            try:
                new_session_id = chat_manager.create_new_session()
                st.success(f"Created new chat session")
                st.rerun()
            except Exception as e:
                st.error(f"Error creating session: {str(e)}")

    with col2:
        # Session count badge
        session_count = len(st.session_state.chat_sessions) if st.session_state.chat_sessions else 0
        st.markdown(f'<div style="text-align: center; margin-top: 8px;"><span class="session-count">{session_count}</span></div>', unsafe_allow_html=True)

    st.markdown("---")

    # Display chat sessions (completely isolated from Wazuh)
    try:
        chat_sessions_list = chat_manager.get_sorted_sessions()

        if not chat_sessions_list:
            st.info("No chat sessions yet. Create your first chat!")
        else:
            for i, chat_session in enumerate(chat_sessions_list):
                session_container = st.container()

                with session_container:
                    col1, col2 = st.columns([4, 1])

                    with col1:
                        is_current = chat_session["id"] == st.session_state.current_session_id
                        button_key = f"session_{chat_session['id']}"
                        active_indicator = "* " if is_current else "- "
                        button_label = f"{active_indicator}{chat_session['name']}"

                        if st.button(
                            button_label,
                            key=button_key,
                            disabled=is_current,
                            use_container_width=True,
                            help=f"Switch to this chat session (Created: {chat_session.get('last_updated', datetime.now()).strftime('%H:%M')})"
                        ):
                            chat_manager.switch_session(chat_session["id"])
                            st.success(f"Switched to: {chat_session['name']}")
                            st.rerun()

                    with col2:
                        if len(chat_sessions_list) > 1:
                            confirm_key = f"confirm_delete_{chat_session['id']}"
                            if st.button("X", key=f"delete_{chat_session['id']}", help="Delete this chat session"):
                                if confirm_key not in st.session_state:
                                    st.session_state[confirm_key] = True
                                    st.warning("Click delete again to confirm")
                                    st.rerun()
                                else:
                                    chat_manager.delete_session(chat_session["id"])
                                    if confirm_key in st.session_state:
                                        del st.session_state[confirm_key]
                                    st.success("Session deleted")
                                    st.rerun()
                        else:
                            st.button("-", disabled=True, help="Cannot delete the only session", key=f"locked_{chat_session['id']}")

                    with st.container():
                        # Safe access to session attributes
                        message_count = chat_session.get('message_count', 0)
                        last_updated = chat_session.get('last_updated', datetime.now())

                        st.markdown(f"""
                        <div class="session-meta">
                            <div class="session-stats">
                                <span>{message_count} msgs</span>
                                <span>{last_updated.strftime('%H:%M')}</span>
                            </div>
                            {'<span style="color: #28a745; font-weight: 600;">Active</span>' if is_current else ''}
                        </div>
                        """, unsafe_allow_html=True)

                    st.markdown("---")

    except Exception as e:
        st.error(f"Error displaying sessions: {str(e)}")
        st.info("Please refresh the page to reset the session state.")

    # USP Information Section
    st.markdown('<div class="sidebar-header">Features Overview</div>', unsafe_allow_html=True)

    st.markdown("""
    <div class="usp-card">
        <div class="usp-title">USP 1: Proactive Triage</div>
        <div class="usp-description">
            Automated alert analysis that triggers immediately when high-severity security events occur, providing instant context and response recommendations.
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="usp-card">
        <div class="usp-title">USP 2: Glass Box Training</div>
        <div class="usp-description">
            Educational query generation with step-by-step explanations, helping analysts learn KQL, DSL, and security analysis techniques.
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="usp-card">
        <div class="usp-title">USP 3: Closed-Loop Wazuh Active Response</div>
        <div class="usp-description">
            Direct integration with Wazuh for real-time threat mitigation, allowing analysts to take immediate actions like blocking IPs or isolating hosts directly from the chat interface.
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Session Stats Section - COMPLETELY ISOLATED from everything else
    st.markdown('<div class="sidebar-header">Session Stats</div>', unsafe_allow_html=True)

    try:
        # Get chat sessions separately for stats calculation
        stats_sessions = chat_manager.get_sorted_sessions()

        if stats_sessions and len(stats_sessions) > 0:
            # Safe access to message_count with default value
            total_messages = 0
            for session in stats_sessions:
                if isinstance(session, dict):
                    total_messages += session.get('message_count', 0)

            avg_messages = total_messages / len(stats_sessions) if len(stats_sessions) > 0 else 0

            col1, col2 = st.columns(2)
            with col1:
                st.metric("Total Messages", total_messages, delta=None)
            with col2:
                st.metric("Avg per Session", f"{avg_messages:.1f}", delta=None)
        else:
            st.info("No statistics available yet.")
    except Exception as stats_error:
        logger.error(f"Error calculating session stats: {stats_error}")
        st.info("Statistics temporarily unavailable.")

    # System Information
    st.markdown("---")
    st.markdown('<div class="sidebar-header">System Info</div>', unsafe_allow_html=True)

    current_time = datetime.now().strftime("%H:%M:%S")
    development_mode = os.getenv('WAZUH_DEVELOPMENT_MODE', 'true').lower() == 'true'

    st.markdown(f"""
    <div style="font-size: 0.8rem; color: #6c757d;">
        <div>Current Time: {current_time}</div>
        <div>AI Model: Gemini Pro</div>
        <div>Wazuh: {'Mock Mode' if development_mode else 'Production'}</div>
        <div>Integration: {'Available' if WAZUH_INTEGRATION_AVAILABLE else 'Enhanced Fallback'}</div>
        <div>Sessions: Auto-saved</div>
        <div>Status: Ready</div>
    </div>
    """, unsafe_allow_html=True)

    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; font-size: 0.75rem; color: #6c757d; margin-top: 1rem;">
        <div><strong>SIEM Assistant MVP v2.0</strong></div>
        <div>Built with Streamlit & Gemini AI</div>
        <div>Integrated with Wazuh SIEM</div>
        <div style="margin-top: 0.5rem;">
            <span>Secure</span> • 
            <span>Fast</span> • 
            <span>Educational</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

# Main Content Area
try:
    chat_interface = SIEMChatInterface()

    if hasattr(chat_interface, 'set_wazuh_client'):
        chat_interface.set_wazuh_client(wazuh_client)

    chat_interface.render_chat()

    # Quick action shortcuts
    with st.expander("Quick Actions & Shortcuts", expanded=False):
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.markdown("""
            **Alert Response**
            - High-severity simulation
            - Auto-triage analysis
            - Response recommendations
            - Active response execution
            """)

        with col2:
            st.markdown("""
            **Query Building**
            - KQL & DSL generation
            - Step-by-step learning
            - Performance optimization
            - Wazuh rule creation
            """)

        with col3:
            st.markdown("""
            **Log Analysis**
            - Event correlation
            - Pattern detection
            - Anomaly identification
            - Threat intelligence
            """)

        with col4:
            st.markdown("""
            **Learning Mode**
            - Beginner to expert levels
            - Interactive explanations
            - Best practice guidance
            - MITRE ATT&CK mapping
            """)

    # Wazuh Integration Status Panel
    with st.expander("Wazuh Integration Status", expanded=False):
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**Connection Status**")
            status = st.session_state.wazuh_status
            st.write(f"Status: {status['message']}")
            st.write(f"Mode: {status.get('mode', 'unknown').replace('_', ' ').title()}")
            st.write(f"Integration Available: {'Yes' if WAZUH_INTEGRATION_AVAILABLE else 'No (Using Enhanced Fallback)'}")

            if wazuh_import_error:
                st.write(f"Import Error: {wazuh_import_error}")

            if st.button("Refresh Connection", key="refresh_wazuh"):
                st.session_state.wazuh_client = None
                st.session_state.wazuh_status = {'connected': False, 'message': 'Not initialized'}
                st.rerun()

        with col2:
            st.markdown("**Available Features**")
            features = [
                "Enhanced Mock Alert Generation",
                "Threat Analysis Simulation", 
                "Active Response Simulation",
                "Agent Management Mock",
                "Rule-based Analysis",
                "Security Statistics",
                "Proactive Alert Processing"
            ]
            for feature in features:
                st.write(f"✓ {feature}")

except Exception as e:
    st.error(f"Application Error: {str(e)}")
    st.info("Please refresh the page or contact support if the issue persists.")

    if os.getenv("DEBUG_MODE", "false").lower() == "true":
        st.exception(e)

# Keyboard shortcuts hint
st.markdown("""
<div style="position: fixed; bottom: 10px; right: 10px; background: rgba(0,0,0,0.8); color: white; padding: 5px 10px; border-radius: 15px; font-size: 0.7rem; z-index: 1000;">
    Press Ctrl+Enter to send message | Try "Simulate Alert" in sidebar
</div>
""", unsafe_allow_html=True)