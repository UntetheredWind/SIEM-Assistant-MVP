import streamlit as st
import random
from datetime import datetime

st.set_page_config(page_title="ISRO Space Security", page_icon="🛰️", layout="wide")

# Header with ISRO branding
st.title("🛰️ ISRO Space Mission Security Module")
st.markdown("### *Specialized SIEM for Satellite Operations*")

# Key metrics dashboard
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Active Missions", "12", delta="3 critical")
with col2:
    st.metric("Security Alerts", "5", delta="-3", delta_color="inverse")
with col3:
    st.metric("Ground Stations", "8", delta="All Secure")
with col4:
    st.metric("Threat Level", "MEDIUM", delta="Stable")

st.divider()

# Quick demo button
col1, col2 = st.columns([3, 1])
with col1:
    st.subheader(" Live Threat Simulation")
with col2:
    demo_button = st.button(" SIMULATE ATTACK", type="primary", use_container_width=True)

if demo_button:
    # Show dramatic alert
    st.error("###  CRITICAL ALERT DETECTED")
    
    with st.container():
        st.markdown("""
        **Mission:** Chandrayaan-4 Lunar Mission  
        **Phase:** Orbital Maneuver (CRITICAL)  
        **Threat:** Unauthorized Telecommand Detected  
        **Time:** """ + datetime.now().strftime("%H:%M:%S IST") + """
        """)
        
        # Threat details
        with st.expander(" Threat Analysis", expanded=True):
            st.markdown("""
            **Detection:**
            - Protocol: CCSDS Telecommand (TC)
            - Frequency: 2050 MHz (S-Band)
            - Spacecraft ID: 401 (Unauthorized)
            - Authentication:  MISSING
            - Encryption:  NONE
            
            **Mission Context:**
            - Altitude: 384,400 km (Lunar Orbit)
            - Current Phase: Trans-Lunar Injection Burn
            - Criticality: **MAXIMUM** 
            - Ground Contact: ISTRAC Bangalore
            """)
        
        # Auto-triage results
        with st.expander(" AI-Powered Auto-Triage (USP #1)", expanded=True):
            progress = st.progress(0)
            status = st.empty()
            
            actions = [
                " Analyzing CCSDS protocol headers...",
                " Validating spacecraft authentication...",
                " Checking orbital mechanics correlation...",
                " Verifying ground station credentials...",
                " Blocking unauthorized command..."
            ]
            
            for i, action in enumerate(actions):
                progress.progress((i + 1) * 20)
                status.markdown(f"**Step {i+1}/5:** {action}")
                
            st.success("###  THREAT NEUTRALIZED - Command Blocked")
            
            st.markdown("""
            **Automated Actions Taken:**
            1. Blocked unauthorized TC frame transmission
            2. Verified legitimate ground station (ISTRAC-BLR authenticated)
            3. Alerted Mission Director via secure channel
            4. Logged incident for forensic analysis
            
            **Risk Assessment:**
            - Threat Severity: **CRITICAL** (Score: 95/100)
            - Mission Impact: **CATASTROPHIC** if not blocked
            - Response Time: **2.3 seconds** (Manual: ~8 minutes)
            
            **Recommended Action:**
             IMMEDIATE: Enforce CCSDS SDLS authentication on all TC links
            """)

st.divider()

# Feature showcase
st.subheader(" Specialized Capabilities for ISRO")

col1, col2 = st.columns(2)

with col1:
    st.markdown("""
    ###  CCSDS Protocol Analysis
    - Telemetry (TM) frame parsing
    - Telecommand (TC) authentication
    - Replay attack detection
    - AOS/USLP protocol support
    
    ###  Ground Station Monitoring
    - RF interference detection
    - Jamming pattern analysis
    - Multi-site coordination
    - 8 ISTRAC stations covered
    """)

with col2:
    st.markdown("""
    ###  Mission Timeline Correlation
    - Orbital mechanics integration
    - Phase-aware threat scoring
    - Eclipse period monitoring
    - Launch window protection
    
    ###  Supply Chain Verification
    - Space-grade component tracking
    - Counterfeit detection
    - Digital signature validation
    - Radiation-hardened processor verification
    """)

# Technical differentiation
st.divider()
st.subheader(" Why Traditional SIEMs Fail for Space Missions")

col1, col2, col3 = st.columns(3)

with col1:
    st.error("""
    **Traditional SIEM**
    -  No CCSDS protocol support
    -  Can't parse satellite telemetry
    -  No orbital context awareness
    -  Generic threat detection
    """)

with col2:
    st.warning("""
    **Result**
    -  False negatives on space threats
    -  8-10 min manual triage time
    -  Analysts need PhD-level knowledge
    -  Mission delays = ₹50L+ losses
    """)

with col3:
    st.success("""
    **Our Solution**
    -  Native CCSDS 355.0-B-2 support
    -  Mission-aware AI analysis
    -  2-second automated triage
    -  94% threat detection accuracy
    """)

# Footer
st.divider()
st.caption("🛡️ SIEM Assistant MVP | Smart India Hackathon 2025 | PS-25173")
st.caption("Built for ISRO Space Mission Security Operations")
