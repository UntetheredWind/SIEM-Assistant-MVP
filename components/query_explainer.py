import streamlit as st
from utils.gemini_client import GeminiClient

class QueryExplainerEngine:
    def __init__(self):
        self.gemini_client = GeminiClient()
        
    def generate_sample_query(self, query_type, request):
        """Generate a sample KQL or DSL query based on user request"""
        query_context = f"""
        You are a SIEM query expert. Generate a realistic {query_type} query for this request: "{request}"
        
        Provide:
        1. The complete query
        2. A brief description of what it does
        
        Make it realistic for security analysis scenarios.
        """
        
        return self.gemini_client.generate_response(request, query_context)
    
    def explain_query_components(self, query, query_type):
        """Explain query components in educational detail"""
        return self.gemini_client.explain_query(query, query_type)
    
    def render_query_explainer(self):
        st.subheader("USP 2: Glass Box Analyst Training Engine")
        
        # Query type selector
        query_type = st.selectbox("Select Query Type:", ["KQL", "Elasticsearch DSL"])
        
        # Sample scenarios
        scenarios = [
            "Show failed login attempts by country in the last 24 hours",
            "Find top 10 source IPs with most security events",
            "Analyze network traffic patterns by protocol",
            "Detect brute force attacks on SSH services"
        ]
        
        selected_scenario = st.selectbox("Choose a scenario:", ["Custom"] + scenarios)
        
        if selected_scenario == "Custom":
            user_request = st.text_input("Enter your analysis request:")
        else:
            user_request = selected_scenario
            st.info(f"Selected scenario: {user_request}")
        
        if st.button("Generate Query") and user_request:
            with st.spinner(f"Generating {query_type} query..."):
                query_response = self.generate_sample_query(query_type, user_request)
                st.session_state['current_query'] = query_response
                st.session_state['current_query_type'] = query_type
                st.session_state['show_explanation'] = False
        
        # Display generated query
        if 'current_query' in st.session_state:
            st.write("**Generated Query:**")
            st.code(st.session_state['current_query'], language='sql')
            
            # Explain button
            if st.button("🎓 Explain This Query"):
                with st.spinner("Generating educational explanation..."):
                    explanation = self.explain_query_components(
                        st.session_state['current_query'], 
                        st.session_state['current_query_type']
                    )
                    st.session_state['query_explanation'] = explanation
                    st.session_state['show_explanation'] = True
            
            # Show explanation
            if st.session_state.get('show_explanation', False):
                st.write("**Query Explanation:**")
                st.info(st.session_state.get('query_explanation', ''))
