import streamlit as st
import pandas as pd
import numpy as np
import altair as alt
import logging
import os
import re
from datetime import datetime, timedelta
import random
from utils.gemini_client import GeminiClient
from utils.chat_manager import ChatManager
from utils.nlp_processor import SecurityNLPProcessor, QueryIntent
from utils.report_generator import ReportGenerator
from typing import Dict

# Elasticsearch integration with error handling
ELASTICSEARCH_AVAILABLE = False
try:
    try:
        from integrations.elasticsearch_client import SimpleElasticsearchClient
    except ImportError:
        from Integrations.elasticsearch_client import SimpleElasticsearchClient

    ELASTICSEARCH_AVAILABLE = True
except ImportError as e:
    ELASTICSEARCH_AVAILABLE = False
except Exception as e:
    ELASTICSEARCH_AVAILABLE = False

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SIEMChatInterface:
    def __init__(self):
        self.gemini_client = GeminiClient()
        self.chat_manager = ChatManager()
        
        # NEW: Add NLP and Report components
        self.nlp_processor = SecurityNLPProcessor()
        self.report_generator = ReportGenerator(self.gemini_client)
        
        # Initialize Elasticsearch client if available
        self.es_client = None
        if ELASTICSEARCH_AVAILABLE:
            try:
                self.es_client = SimpleElasticsearchClient()
                if self.es_client and self.es_client.test_connection():
                    logger.info("[SUCCESS] Elasticsearch client initialized.")
                else:
                    logger.warning("[WARNING] Elasticsearch client created but connection failed.")
            except Exception as e:
                logger.error(f"[ERROR] Failed to initialize Elasticsearch client: {str(e)}")
                self.es_client = None

        st.session_state.setdefault("insight_cards", None)
        st.session_state.setdefault("time_window_days", 7)
        st.session_state.setdefault("pending_response", False)
        st.session_state.setdefault("current_table", None)
        st.session_state.setdefault("current_chart", None)

    def render_floating_buttons(self):
        """Render floating feature buttons above chat input."""
        st.markdown("""
        <style>
        .floating-container {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 15px;
            padding: 15px;
            margin: 10px 0;
        }
        </style>
        """, unsafe_allow_html=True)

        st.markdown('<div class="floating-container">', unsafe_allow_html=True)
        st.markdown('<h4>Quick Actions</h4>', unsafe_allow_html=True)

        col1, col2, col3, col4 = st.columns([1, 1, 1, 1])
        with col1:
            if st.button("Alert Triage", key="alert_triage_btn", use_container_width=True):
                self.chat_manager.add_message("user", "Show me recent high-severity security alerts from Elasticsearch")
                st.session_state.pending_response = True
                st.rerun()
        with col2:
            if st.button("Query Builder", key="query_builder_btn", use_container_width=True):
                self.chat_manager.add_message("user", "Teach me how to build a KQL query for detecting failed login attempts. Include syntax, best practices, and example query.")
                st.session_state.pending_response = True
                st.rerun()
        with col3:
            if st.button("Threat Intel", key="threat_intel_btn", use_container_width=True):
                self.chat_manager.add_message("user", "Show me threat intelligence summary from Elasticsearch with charts")
                st.session_state.pending_response = True
                st.rerun()
        with col4:
            if st.button("MITRE Analysis", key="mitre_analysis_btn", use_container_width=True):
                self.chat_manager.add_message("user", "Find MITRE T1110 related events in Elasticsearch")
                st.session_state.pending_response = True
                st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)

    def _is_educational_query(self, query: str) -> bool:
        """Determine if query is asking for help/learning vs actual data retrieval"""
        query_lower = query.lower()
        
        # Strong educational indicators - must be present for educational routing
        strong_educational_keywords = [
            "how to", "teach me", "explain how", "what is", "help me build",
            "help me write", "help me create", "show me how", "guide me",
            "tutorial", "learn", "understand", "best practice", "example of",
            "how can i", "how do i", "walk me through", "step by step",
            "difference between", "compare", "what are the types"
        ]
        
        # If it's clearly a data request, don't route to educational
        data_request_indicators = [
            "show me", "find", "search", "list", "get", "display",
            "generate.*report", "create.*report", "give me.*data",
            "events", "alerts", "logs", "incidents", "activity"
        ]
        
        # Check for strong educational indicators first
        has_educational = any(keyword in query_lower for keyword in strong_educational_keywords)
        
        # Check for data request indicators
        has_data_request = any(re.search(pattern, query_lower) for pattern in data_request_indicators)
        
        # If it has data request indicators, prioritize those over educational
        if has_data_request:
            return False
        
        # Only route to educational if strong educational indicators are present
        return has_educational

    def _generate_response(self, prompt: str, es_connected: bool) -> str:
        """Generate response from either Elasticsearch or Gemini"""
        response = None
        
        try:
            # First check: Is this clearly an educational query?
            if self._is_educational_query(prompt):
                logger.info("Detected educational query - using Gemini")
                
                siem_context = """
You are an expert SIEM security instructor helping analysts learn security analysis skills.
Focus on teaching concepts, query syntax, best practices, and providing clear examples.
When asked about building queries, provide:
1. Complete, working query examples
2. Explanation of each component
3. Best practices and common pitfalls
4. Variations for different scenarios

Be thorough but clear. Use code blocks for queries.
"""
                response = self.gemini_client.generate_response(prompt, siem_context)
                return response if response and response.strip() else "Unable to generate educational content. Please try again."
            
            # Second check: Try NLP processor for data queries
            logger.info("Processing query with NLP processor...")
            
            # Process with NLP first to understand intent
            intent = self.nlp_processor.process_query(prompt)
            logger.info(f"NLP Result - Intent: {intent.intent_type}, Confidence: {intent.confidence:.2f}, Use Gemini: {self.nlp_processor.should_use_gemini(prompt)}")
            
            # If NLP says use Gemini AND we have low confidence, use Gemini
            if self.nlp_processor.should_use_gemini(prompt) and intent.confidence < 0.6:
                logger.info("NLP recommends Gemini due to low confidence or conversational nature")
            else:
                # Try Elasticsearch/Mock data first
                if es_connected and self.es_client:
                    logger.info("Trying Elasticsearch with NLP-generated query...")
                    es_response = self.handle_elasticsearch_query(prompt)
                    if es_response and es_response.strip():
                        logger.info(f"ES response successful: {len(es_response)} chars")
                        return es_response
                else:
                    # No ES connection - create mock data response
                    logger.info("No ES connection - generating mock data response")
                    mock_response = self._generate_mock_data_response(prompt, intent)
                    if mock_response and mock_response.strip():
                        return mock_response
            
            # Fallback to Gemini for general queries
            logger.info("Using Gemini AI for general query...")
            
            siem_context = """
You are an expert SIEM security assistant helping analysts with:
- Security event analysis and threat detection
- MITRE ATT&CK framework and tactics
- Query building (KQL, Elasticsearch DSL, SPL)
- Incident response and log analysis
- Security best practices and SOC workflows

Provide clear, actionable, technical guidance.
Keep responses focused and practical.
"""
            
            response = self.gemini_client.generate_response(prompt, siem_context)
            logger.info(f"Gemini response: {len(response) if response else 0} chars")
            
            # Validate response
            if not response or not response.strip():
                logger.error("Empty response from all methods")
                response = (
                    "Unable to generate response\n\n"
                    "Troubleshooting steps:\n"
                    "1. Check your GOOGLE_API_KEY in .env file\n"
                    "2. Verify Gemini API quota and billing\n"
                    "3. Try a different question\n"
                    "4. Check terminal logs for detailed errors\n\n"
                    "Example queries:\n"
                    "- What is a brute force attack?\n"
                    "- Help me write a KQL query\n"
                    "- Explain MITRE ATT&CK framework"
                )
            
            return response
            
        except Exception as e:
            logger.error(f"Error generating response: {str(e)}", exc_info=True)
            return (
                f"Error processing your request\n\n"
                f"Please try:\n"
                f"- Rephrasing your question\n"
                f"- Using simpler terminology\n"
                f"- Checking the terminal logs"
            )

    def _generate_mock_data_response(self, query: str, intent: QueryIntent) -> str:
        """Generate mock data response when Elasticsearch is not available"""
        try:
            # Create mock data based on query intent
            mock_data = self._create_mock_security_data(intent)
            
            # Generate report using the report generator
            report = self.report_generator.generate_report(query, mock_data)
            
            # Format response
            response = self._format_report_response(report, intent)
            
            # Add mock data disclaimer
            response = "**🔧 Mock Data Mode (Elasticsearch Offline)**\n\n" + response
            response += "\n\n*Note: This report uses simulated security data for demonstration purposes.*"
            
            return response
            
        except Exception as e:
            logger.error(f"Error generating mock data response: {e}")
            return None

    def _create_mock_security_data(self, intent: QueryIntent) -> dict:
        """Create realistic mock security data based on query intent"""
        
        # Base mock events
        mock_events = []
        
        # Determine event count based on intent
        event_count = intent.entities.get('limit', 15)
        if intent.intent_type == 'report':
            event_count = 50  # More data for reports
        elif intent.intent_type == 'aggregate':
            event_count = 100  # Even more for aggregations
        
        # Define threat types based on query
        threat_types = ['malware', 'authentication', 'network', 'web_attack']
        if intent.entities.get('threats'):
            threat_types = intent.entities['threats'][:3]  # Use specific threats from query
        
        # Create events based on intent
        for i in range(event_count):
            threat_type = random.choice(threat_types)
            
            base_event = {
                '@timestamp': (datetime.now() - timedelta(hours=random.randint(1, 72))).isoformat(),
                'event': {
                    'type': threat_type,
                    'category': threat_type,
                    'severity': random.randint(3, 10),
                    'outcome': random.choice(['success', 'failure', 'unknown'])
                },
                'source': {'ip': f'192.168.{random.randint(1, 5)}.{random.randint(100, 250)}'},
                'destination': {'ip': f'10.0.{random.randint(1, 10)}.{random.randint(10, 100)}'},
                'user': {'name': f'user{random.randint(1, 50)}'},
                'rule': {
                    'id': f'{random.randint(1000, 9999)}',
                    'description': f'Mock {threat_type} security event',
                    'level': random.randint(3, 15)
                },
                'host': {'name': f'host-{random.randint(1, 20)}'},
                'network': {'protocol': random.choice(['tcp', 'udp', 'http', 'https'])}
            }
            
            # Customize based on threat type
            if threat_type == 'malware':
                base_event['event']['category'] = 'malware'
                base_event['rule']['description'] = random.choice([
                    'Malware detection: Trojan.Generic',
                    'Suspicious file execution detected',
                    'Backdoor communication attempt',
                    'Ransomware behavior detected'
                ])
                base_event['file'] = {
                    'name': random.choice(['suspicious.exe', 'malware.dll', 'backdoor.bat']),
                    'hash': f'abc{random.randint(1000, 9999)}def{random.randint(1000, 9999)}'
                }
                base_event['event']['severity'] = random.randint(7, 10)
            
            elif threat_type == 'authentication':
                base_event['event']['category'] = 'authentication'
                base_event['event']['type'] = 'authentication'
                base_event['event']['outcome'] = random.choice(['failure', 'failure', 'failure', 'success'])  # More failures
                base_event['rule']['description'] = random.choice([
                    'SSH authentication failed',
                    'Multiple login failures detected',
                    'Brute force attack detected',
                    'Successful login after failures'
                ])
                base_event['event']['severity'] = random.randint(5, 9)
            
            elif threat_type == 'network':
                base_event['event']['category'] = 'network'
                base_event['rule']['description'] = random.choice([
                    'Suspicious network connection',
                    'Port scan detected',
                    'Unusual traffic volume',
                    'DNS tunneling attempt'
                ])
                base_event['network']['bytes'] = random.randint(1000, 100000)
                base_event['destination']['port'] = random.randint(80, 65535)
            
            elif threat_type == 'web_attack':
                base_event['event']['category'] = 'web'
                base_event['rule']['description'] = random.choice([
                    'SQL injection attempt detected',
                    'XSS attack blocked',
                    'Web application attack',
                    'Suspicious HTTP request'
                ])
                base_event['http'] = {
                    'response_code': random.choice([200, 403, 404, 500]),
                    'method': random.choice(['GET', 'POST', 'PUT']),
                    'url': random.choice(['/admin', '/login', '/api/users', '/cmd.exe'])
                }
                base_event['event']['severity'] = random.randint(6, 10)
            
            # Add MITRE ATT&CK techniques for some events
            if random.random() > 0.7:  # 30% of events
                mitre_techniques = ['T1110', 'T1078', 'T1190', 'T1046', 'T1059', 'T1055']
                base_event['rule']['mitre'] = {
                    'technique': random.choice(mitre_techniques)
                }
            
            mock_events.append(base_event)
        
        # Sort by timestamp (most recent first)
        mock_events.sort(key=lambda x: x['@timestamp'], reverse=True)
        
        return {
            'success': True,
            'total_hits': len(mock_events),
            'results': mock_events,
            'took': random.randint(10, 150),
            'query_type': intent.intent_type,
            'index_used': intent.entities.get('index', 'security-events-sample')
        }

    def render_chat(self):
        """Main chat interface with enhanced error handling"""
        st.markdown('<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 15px; padding: 20px; margin: 10px 0;"><h2 style="color: white; text-align: center; margin-bottom: 0;">SIEM Security Assistant</h2></div>', unsafe_allow_html=True)

        # Connection status
        es_connected = False
        if ELASTICSEARCH_AVAILABLE and self.es_client:
            try:
                es_connected = self.es_client.test_connection()
                if es_connected:
                    indices = self.es_client.get_available_indices()
                    st.success(f"Elasticsearch: {len(indices)} indices ready")
                else:
                    st.warning("Elasticsearch: Not connected - Using mock data mode")
            except Exception as e:
                st.warning(f"Elasticsearch unavailable - Using mock data mode")
                logger.warning(f"ES check failed: {str(e)}")
        else:
            st.info("Running in AI + Mock Data mode (Elasticsearch disabled)")

        # Test Gemini connection once
        if "gemini_tested" not in st.session_state:
            with st.spinner("Testing AI connection..."):
                try:
                    if self.gemini_client.test_connection():
                        st.session_state.gemini_tested = True
                        st.success("Gemini AI: Connected")
                    else:
                        st.session_state.gemini_tested = False
                        st.error("Gemini AI: Connection failed")
                except Exception as e:
                    st.session_state.gemini_tested = False
                    st.error(f"Gemini error: {str(e)[:80]}")

        try:
            # Get and display messages
            messages = self.chat_manager.get_current_messages()
            logger.info(f"Rendering {len(messages)} messages")
            
            if not messages:
                logger.warning("No messages in current session!")
                st.info("Start a conversation by typing a question below or click a Quick Action button.")
            
            # Display each message
            for i, message in enumerate(messages):
                role = message.get("role", "assistant")
                content = message.get("content", "")
                
                with st.chat_message(role):
                    if i > 0:
                        timestamp = message.get("timestamp", datetime.now())
                        if isinstance(timestamp, datetime):
                            time_str = timestamp.strftime('%H:%M')
                        else:
                            time_str = datetime.now().strftime('%H:%M')
                        
                        role_name = "Assistant" if role == "assistant" else "You"
                        st.markdown(f'<small style="color: #888;">{role_name} • {time_str}</small>', unsafe_allow_html=True)
                    
                    # Display content
                    if content and content.strip():
                        st.markdown(content)
                    else:
                        st.warning("Empty message")
                        logger.warning(f"Empty message at index {i}")

            # NEW: Render report components
            self.render_report_components()

            # Render action buttons
            self.render_floating_buttons()

            # Check if we need to generate a response from button click
            if st.session_state.get("pending_response", False):
                logger.info("Processing pending response from button click")
                st.session_state.pending_response = False
                
                # Get the last user message
                if messages and messages[-1]["role"] == "user":
                    prompt = messages[-1]["content"]
                    logger.info(f"Generating response for: {prompt[:50]}...")
                    
                    with st.spinner("Analyzing your query..."):
                        response = self._generate_response(prompt, es_connected)
                        self.chat_manager.add_message("assistant", response)
                        logger.info("Assistant response added to chat")
                    
                    st.rerun()

            # Handle new input from chat box
            if prompt := st.chat_input("Ask about security events, threats, MITRE techniques, or query building..."):
                logger.info(f"New prompt received: {prompt[:50]}...")
                
                # Add user message immediately
                self.chat_manager.add_message("user", prompt)
                logger.info("User message added to chat")
                
                # Generate response
                with st.spinner("Analyzing your query..."):
                    response = self._generate_response(prompt, es_connected)
                    self.chat_manager.add_message("assistant", response)
                    logger.info("Assistant response added to chat")
                
                # Force refresh to show new messages
                logger.info("Triggering UI refresh...")
                st.rerun()

        except Exception as e:
            st.error(f"Critical error: {str(e)}")
            logger.error(f"render_chat error: {str(e)}", exc_info=True)
            st.info("Please refresh the page (F5) if the issue persists.")
            
            # Show debug info in development mode
            if os.getenv("DEBUG_MODE", "false").lower() == "true":
                st.exception(e)

    def handle_elasticsearch_query(self, user_query: str) -> str:
        """Enhanced query handler with NLP and reporting"""
        if not ELASTICSEARCH_AVAILABLE or not self.es_client:
            logger.info("Elasticsearch not available.")
            return None

        try:
            if not self.es_client.test_connection():
                logger.warning("Elasticsearch connection failed.")
                return None
        except Exception as e:
            logger.error(f"ES test error: {str(e)}")
            return None

        try:
            # NEW: Process query with NLP
            intent = self.nlp_processor.process_query(user_query)
            logger.info(f"NLP Intent: {intent.intent_type}, Confidence: {intent.confidence}")

            # Check if should use Gemini instead
            if self.nlp_processor.should_use_gemini(user_query):
                logger.info("NLP recommends Gemini routing")
                return None  # Fall through to Gemini

            # Execute Elasticsearch query
            if intent.es_query:
                logger.info("Using NLP-generated Elasticsearch query")
                result = self.es_client.execute_dsl_query(
                    index=intent.entities.get('index', 'security-events-sample'),
                    dsl_query=intent.es_query
                )
            else:
                # Fallback to existing method
                logger.info("Falling back to existing ES query method")
                result = self.es_client.execute_security_query(user_query)
            
            if not result.get("success"):
                indices = self.es_client.get_available_indices()
                return f"Elasticsearch Error: {result.get('error', 'Unknown')}\nAvailable indices: {', '.join(indices)}"

            if result.get("total_hits", 0) == 0:
                return ("No matching events found.\nTry queries like:\n"
                        "- Show me failed login attempts\n"
                        "- Find error responses with charts\n"
                        "- List suspicious activity in a table")

            # NEW: Generate comprehensive report
            logger.info("Generating comprehensive report")
            report = self.report_generator.generate_report(user_query, result)
            
            # NEW: Format response based on report type
            response = self._format_report_response(report, intent)
            
            return response

        except Exception as e:
            logger.error(f"Error in handle_elasticsearch_query: {e}")
            return f"Error executing query: {str(e)}"

    def _format_report_response(self, report: Dict, intent: QueryIntent) -> str:
        """Format report for chat display"""
        response = ""
        
        # Add textual component
        if report.get('textual'):
            response += report['textual'] + "\n\n"
        
        # Add table indicator (actual table rendered separately)
        if report.get('tabular'):
            row_count = report['tabular'].get('row_count', 0)
            col_count = report['tabular'].get('column_count', 0)
            response += f"**📊 Data Table ({row_count} rows, {col_count} columns)**\n\n"
            # Store for rendering in chat
            st.session_state['current_table'] = report['tabular']
        
        # Add chart indicator (actual chart rendered separately)  
        if report.get('chart'):
            response += "**📈 Interactive Visualization**\n\n"
            st.session_state['current_chart'] = report['chart']
        
        # Add query metadata
        response += f"**Query Analysis:**\n"
        response += f"- Intent: {intent.intent_type.replace('_', ' ').title()}\n"
        response += f"- Confidence: {intent.confidence:.0%}\n"
        response += f"- Index: {intent.entities.get('index', 'default')}\n"
        
        if intent.entities.get('time_range'):
            response += f"- Time Range: Applied\n"
        
        if intent.entities.get('ips'):
            response += f"- IP Filters: {', '.join(intent.entities['ips'][:3])}\n"
        
        if intent.entities.get('threats'):
            response += f"- Threat Types: {', '.join(intent.entities['threats'][:3])}\n"

        # Add total hits info
        if report.get('metadata', {}).get('total_records'):
            response += f"- Total Records: {report['metadata']['total_records']:,}\n"
        
        return response

    def render_report_components(self):
        """Render table and chart components after chat messages"""
        
        # Render table if available
        if 'current_table' in st.session_state and st.session_state['current_table']:
            table_data = st.session_state['current_table']
            
            if 'dataframe' in table_data and not table_data['dataframe'].empty:
                st.subheader("📊 Data Table")
                
                # Show table info
                row_count = table_data.get('row_count', 0)
                col_count = table_data.get('column_count', 0)
                st.caption(f"Showing {len(table_data['dataframe'])} of {row_count} total records ({col_count} columns)")
                
                # Display table
                st.dataframe(table_data['dataframe'], use_container_width=True)
                
                # Download button
                if 'csv_export' in table_data:
                    col1, col2, col3 = st.columns([1, 1, 2])
                    with col1:
                        st.download_button(
                            "📥 Download CSV",
                            data=table_data['csv_export'],
                            file_name=f"siem_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                            mime='text/csv',
                            use_container_width=True
                        )
                    with col2:
                        if st.button("🗑️ Clear Table", use_container_width=True):
                            st.session_state['current_table'] = None
                            st.rerun()
                
                st.divider()

        # Render chart if available
        if 'current_chart' in st.session_state and st.session_state['current_chart']:
            st.subheader("📈 Interactive Visualization")
            
            try:
                st.plotly_chart(st.session_state['current_chart'], use_container_width=True)
                
                # Chart controls
                col1, col2 = st.columns([1, 3])
                with col1:
                    if st.button("🗑️ Clear Chart", use_container_width=True):
                        st.session_state['current_chart'] = None
                        st.rerun()
                
                st.divider()
                
            except Exception as e:
                st.error(f"Error rendering chart: {str(e)}")
                st.session_state['current_chart'] = None

    # Legacy methods for backward compatibility
    def _format_mitre_response(self, result: dict) -> str:
        response = f"**MITRE ATT&CK: {result['mitre_technique']}**\n\n"
        response += f"**Technique:** {result.get('technique_name', 'Unknown')}\n"
        response += f"**Tactic:** {result.get('tactic', 'Unknown')}\n"
        response += f"**Description:** {result.get('description', 'No description available')}\n"
        response += f"**Index:** {result.get('index_searched', 'N/A')}\n\n"
        response += f"**Found {result.get('total_hits', 0)} related events:**\n\n"
        
        for i, event in enumerate(result.get("results", [])[:5], 1):
            timestamp = event.get('@timestamp', event.get('timestamp', 'N/A'))
            response += f"**Event {i}:**\n"
            response += f"- Time: {timestamp}\n"
            response += f"- Severity: {event.get('severity', 'N/A')}\n"
            response += f"- Source IP: {event.get('source_ip', 'N/A')}\n"
            response += f"- Action: {event.get('action', 'N/A')}\n\n"
        
        return response

    def _format_threat_intel_response(self, result: dict) -> str:
        ti = result.get("threat_intelligence", {})
        response = f"**Threat Intelligence Summary**\n\n"
        response += f"**Index:** {result.get('index_analyzed', 'N/A')}\n"
        response += f"**Total Events:** {result.get('total_events', 0):,}\n\n"
        
        if 'threat_landscape' in ti:
            response += "**Top Threat Types:**\n"
            for threat in ti["threat_landscape"].get("buckets", [])[:5]:
                response += f"- {threat['key']}: {threat['doc_count']:,} incidents\n"
        
        if 'severity_distribution' in ti:
            response += "\n**Severity Distribution:**\n"
            for severity in ti["severity_distribution"].get("buckets", []):
                response += f"- {severity['key']}: {severity['doc_count']:,} events\n"
        
        if 'failed_authentications' in ti:
            failed_count = ti["failed_authentications"].get("doc_count", 0)
            if failed_count > 0:
                response += f"\n**Failed Authentication Analysis:**\n"
                response += f"Total Failed Logins: {failed_count:,}\n"
                if 'by_user' in ti["failed_authentications"]:
                    response += "\n**Top Targeted Users:**\n"
                    for user in ti["failed_authentications"]["by_user"].get("buckets", [])[:5]:
                        response += f"- {user['key']}: {user['doc_count']:,} failed attempts\n"
        
        return response

    def _format_security_summary(self, result: dict) -> str:
        response = "**Security Infrastructure Summary**\n\n"
        response += f"**Total Security Indices:** {result.get('total_indices', 0)}\n\n"
        
        for index, info in result.get("indices_summary", {}).items():
            if info.get("status") != "error":
                response += f"**{index}:**\n"
                response += f"- Total Documents: {info.get('total_documents', 0):,}\n"
                response += f"- Recent Activity (24h): {info.get('recent_24h', 0):,}\n"
                response += f"- Status: {info.get('status', 'unknown').upper()}\n\n"
        
        return response

    def _format_es_results(self, result: dict) -> str:
        query_type = result.get('query_type', 'General Search')
        response = f"**{query_type.replace('_', ' ').title()}**\n\n"
        response += f"**Index:** {result.get('index_used', 'N/A')}\n"
        response += f"**Found {result.get('total_hits', 0):,} events** (showing top 10)\n\n"
        
        for i, event in enumerate(result.get("results", [])[:10], 1):
            response += f"**Event {i}:**\n"
            timestamp = event.get('@timestamp', event.get('timestamp', 'N/A'))
            response += f"- Time: {timestamp}\n"
            
            # Handle different schemas
            if 'event_type' in event:
                response += f"- Type: {event.get('event_type', 'N/A')}\n"
                response += f"- Severity: {event.get('severity', 'N/A')}\n"
                response += f"- Source IP: {event.get('source_ip', 'N/A')}\n"
                response += f"- User: {event.get('username', 'N/A')}\n"
            elif 'clientip' in event:
                response += f"- Client IP: {event.get('clientip', 'N/A')}\n"
                response += f"- Response: {event.get('response', 'N/A')}\n"
                response += f"- Request: {event.get('request', 'N/A')[:80]}...\n"
            else:
                # Generic handling
                for key, value in list(event.items())[:5]:
                    if key not in ['@timestamp', 'timestamp']:
                        response += f"- {key}: {str(value)[:80]}\n"
            
            response += "\n"
        
        response += f"\n**Query Time:** {result.get('took', 0)}ms\n"
        return response
