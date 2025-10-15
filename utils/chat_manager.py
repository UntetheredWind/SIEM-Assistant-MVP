import streamlit as st
from datetime import datetime
import uuid

class ChatManager:
    def __init__(self):
        self.initialize_chat_system()
    
    def initialize_chat_system(self):
        """Initialize the chat system with sessions"""
        if "chat_sessions" not in st.session_state:
            st.session_state.chat_sessions = {}
        
        if "current_session_id" not in st.session_state:
            self.create_new_session()
    
    def create_new_session(self):
        """Create a new chat session"""
        session_id = str(uuid.uuid4())[:8]
        timestamp = datetime.now().strftime("%H:%M")
        session_name = f"Chat {timestamp}"
        
        st.session_state.chat_sessions[session_id] = {
            "name": session_name,
            "messages": [
                {
                    "role": "assistant", 
                    "content": "Hello! I'm your SIEM assistant. I can help with security analysis, query generation, and incident investigation. How can I assist you today?"
                }
            ],
            "created_at": datetime.now(),
            "last_updated": datetime.now()
        }
        
        st.session_state.current_session_id = session_id
        return session_id
    
    def get_current_messages(self):
        """Get messages from current session"""
        if not st.session_state.current_session_id or st.session_state.current_session_id not in st.session_state.chat_sessions:
            self.create_new_session()
        
        current_id = st.session_state.current_session_id
        return st.session_state.chat_sessions[current_id]["messages"]
    
    def add_message(self, role, content):
        """Add message to current session"""
        if not st.session_state.current_session_id or st.session_state.current_session_id not in st.session_state.chat_sessions:
            self.create_new_session()
        
        current_id = st.session_state.current_session_id
        message = {"role": role, "content": content}
        
        st.session_state.chat_sessions[current_id]["messages"].append(message)
        st.session_state.chat_sessions[current_id]["last_updated"] = datetime.now()
        
        # Update session name based on first user message
        if role == "user" and len(st.session_state.chat_sessions[current_id]["messages"]) == 2:
            # Truncate first user message for session name
            short_name = content[:30] + "..." if len(content) > 30 else content
            st.session_state.chat_sessions[current_id]["name"] = short_name
    
    def switch_session(self, session_id):
        """Switch to a different chat session"""
        if session_id in st.session_state.chat_sessions:
            st.session_state.current_session_id = session_id
    
    def delete_session(self, session_id):
        """Delete a chat session"""
        if session_id in st.session_state.chat_sessions:
            del st.session_state.chat_sessions[session_id]
            
            # If we deleted the current session, create a new one
            if st.session_state.current_session_id == session_id:
                self.create_new_session()
    
    def get_sorted_sessions(self):
        """Get sessions sorted by last updated"""
        sessions = []
        for session_id, session_data in st.session_state.chat_sessions.items():
            sessions.append({
                "id": session_id,
                "name": session_data["name"],
                "last_updated": session_data["last_updated"],
                "message_count": len(session_data["messages"])
            })
        
        return sorted(sessions, key=lambda x: x["last_updated"], reverse=True)
