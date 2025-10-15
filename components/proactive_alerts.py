import streamlit as st
import json
import random
from datetime import datetime
from utils.gemini_client import GeminiClient
from utils.mock_data import MockDataGenerator


class ProactiveTriageAssistant:
    def __init__(self):
        self.gemini_client = GeminiClient()
        
    def simulate_alert_trigger(self):
        """Simulate a high-severity alert being triggered"""
        alerts = MockDataGenerator.generate_sample_alerts()
        high_severity_alerts = [alert for alert in alerts if alert["rule_level"] > 12]
        
        # Add ISRO space security alert to the pool
        space_alert = {
            "id": "SPACE-20001",
            "title": "🛰️ CRITICAL: Unauthorized Satellite Telecommand Detected",
            "rule_level": 15,
            "severity": "CRITICAL",
            "source_ip": "203.45.67.89",
            "destination_ip": "10.1.50.23",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "protocol": "CCSDS-TC",
            "mission": "Chandrayaan-4",
            "details": {
                "spacecraft_id": 401,
                "frequency_mhz": 2050.0,
                "ground_station": "ISTRAC-Bangalore",
                "threat_type": "Unencrypted Telecommand",
                "authentication": "MISSING",
                "mission_phase": "Orbital Maneuver",
                "orbital_altitude_km": 384400,
                "mission_criticality": "MAXIMUM"
            }
        }
        
        # 50% chance to show space alert
        if random.random() > 0.5:
            return space_alert
        
        if high_severity_alerts:
            return high_severity_alerts[0]
        return None
    
    def run_triage_playbook(self, alert):
        """Simulate running automated triage queries"""
        
        # Check if it's a space security alert
        if alert.get('id', '').startswith('SPACE-'):
            triage_context = f"""
            You are a specialized SIEM assistant for ISRO space mission security.
            
            CRITICAL SPACE SECURITY ALERT:
            - Alert ID: {alert['id']}
            - Mission: {alert.get('mission', 'Unknown')}
            - Threat: {alert['title']}
            - Source IP: {alert['source_ip']}
            - Protocol: {alert.get('protocol', 'Unknown')}
            - Spacecraft ID: {alert['details']['spacecraft_id']}
            - Ground Station: {alert['details']['ground_station']}
            - Mission Phase: {alert['details']['mission_phase']}
            - Threat Type: {alert['details']['threat_type']}
            
            Perform specialized space mission triage:
            1. Validate CCSDS protocol authentication requirements
            2. Check if spacecraft ID is authorized for this ground station
            3. Verify orbital position matches expected maneuver window
            4. Cross-reference with mission timeline and planned operations
            5. Assess mission impact (mission phase is CRITICAL: {alert['details']['mission_phase']})
            6. Recommend immediate protective actions
            
            Provide a detailed, mission-aware analysis with specific technical recommendations.
            """
        else:
            triage_context = f"""
            You are a SIEM assistant that has automatically detected a high-severity alert.
            
            Alert Details:
            - ID: {alert['id']}
            - Title: {alert['title']}
            - Source IP: {alert['source_ip']}
            - Severity: {alert['severity']}
            - Time: {alert['timestamp']}
            
            Simulate running these triage steps and provide realistic results:
            1. Check if source IP is a repeat offender
            2. Analyze traffic patterns from this IP
            3. Cross-reference with threat intelligence
            4. Suggest immediate actions
            
            Format as a clear, actionable summary for the analyst.
            """
        
        return self.gemini_client.generate_response("Analyze this alert", triage_context)
    
    def render_proactive_alert(self):
        st.subheader("USP 1: Proactive Triage Assistant")
        
        col1, col2 = st.columns([3, 1])
        with col1:
            st.info(" **Innovation:** Auto-triggers triage playbooks when high-severity alerts detected")
        with col2:
            if st.button("Simulate Alert", type="primary", use_container_width=True):
                alert = self.simulate_alert_trigger()
                if alert:
                    st.session_state['current_alert'] = alert
                    st.session_state['triage_complete'] = False
        
        if 'current_alert' in st.session_state and not st.session_state.get('triage_complete', False):
            alert = st.session_state['current_alert']
            
            # Show alert details with styling
            if alert.get('id', '').startswith('SPACE-'):
                # Space security alert styling
                st.error(f"### 🛰️ {alert['title']}")
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Mission", alert.get('mission', 'N/A'))
                with col2:
                    st.metric("Severity", alert['severity'], delta="LEVEL " + str(alert['rule_level']))
                with col3:
                    st.metric("Protocol", alert.get('protocol', 'Unknown'))
                
                with st.expander(" Detailed Threat Information", expanded=True):
                    st.markdown(f"""
                    **Source IP:** `{alert['source_ip']}` → **Destination:** `{alert['destination_ip']}`  
                    **Spacecraft ID:** {alert['details']['spacecraft_id']}  
                    **Ground Station:** {alert['details']['ground_station']}  
                    **Frequency:** {alert['details']['frequency_mhz']} MHz  
                    **Mission Phase:** {alert['details']['mission_phase']} (Criticality: {alert['details']['mission_criticality']})  
                    **Orbital Altitude:** {alert['details']['orbital_altitude_km']:,} km  
                    **Authentication Status:**  {alert['details']['authentication']}  
                    **Detection Time:** {alert['timestamp']}
                    """)
            else:
                # Regular alert styling
                st.error(f"**Alert {alert['id']}**: {alert['title']}")
                st.write(f"**Source IP**: {alert['source_ip']}")
                st.write(f"**Severity**: {alert['severity']} (Level {alert['rule_level']})")
                st.write(f"**Timestamp**: {alert['timestamp']}")
            
            # Auto-triage button
            st.divider()
            col1, col2 = st.columns([2, 1])
            with col1:
                st.markdown("**Automated Triage Playbook Ready**")
                st.caption("AI will analyze threat context, check indicators, and recommend actions")
            with col2:
                if st.button("Run Auto-Triage", type="primary", use_container_width=True):
                    with st.spinner(" Running automated triage playbook..."):
                        triage_results = self.run_triage_playbook(alert)
                        st.session_state['triage_results'] = triage_results
                        st.session_state['triage_complete'] = True
                        st.rerun()
        
        if st.session_state.get('triage_complete', False):
            st.success("###  Automated Triage Complete!")
            
            # Show triage results
            with st.container():
                st.markdown("** AI-Powered Analysis Results:**")
                st.write(st.session_state.get('triage_results', ''))
            
            st.divider()
            
            # Action buttons
            st.markdown("** Recommended Actions:**")
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                if st.button(" Block Source", use_container_width=True):
                    st.success(" Source blocked via Wazuh Active Response")
                    st.balloons()
                    
            with col2:
                if st.button(" Investigate", use_container_width=True):
                    st.info(" Investigation workflow initiated - Opening threat hunter dashboard")
                    
            with col3:
                if st.button(" Alert Team", use_container_width=True):
                    st.warning(" Security team notified via Slack/Email")
                    
            with col4:
                if st.button(" False Positive", use_container_width=True):
                    st.warning(" Alert marked as false positive and logged")
            
            # Show metrics
            st.divider()
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Time Saved", "7.5 min", delta="-85% vs manual", help="Average manual triage: 8-10 minutes")
            with col2:
                st.metric("Confidence Score", "94%", delta="+15% accuracy", help="AI-powered threat assessment")
            with col3:
                st.metric("MTTR Impact", "2.3 sec", delta="Real-time response", help="Mean Time to Respond")
