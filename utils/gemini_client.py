import os
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold
from dotenv import load_dotenv
import logging

load_dotenv()
logger = logging.getLogger(__name__)

class GeminiClient:
    def __init__(self):
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY not found in environment variables")
        
        genai.configure(api_key=api_key)
        
        # Configure safety settings to allow security-related content
        self.safety_settings = {
            HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
        }
        
        # Try to initialize with best available model
        try:
            self.model = genai.GenerativeModel(
                "gemini-2.0-flash-exp",
                safety_settings=self.safety_settings
            )
            logger.info("Successfully initialized Gemini model: gemini-2.0-flash-exp")
        except Exception:
            try:
                self.model = genai.GenerativeModel(
                    "gemini-1.5-flash",
                    safety_settings=self.safety_settings
                )
                logger.info("Successfully initialized Gemini model: gemini-1.5-flash")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini model: {str(e)}")
                raise ValueError(f"Unable to initialize Gemini model: {str(e)}")
    
    def test_connection(self) -> bool:
        """Test if Gemini API is accessible"""
        try:
            response = self.model.generate_content(
                "Respond with 'OK' if you can read this.",
                safety_settings=self.safety_settings
            )
            if response and hasattr(response, 'text') and response.text:
                logger.info("✅ Gemini client connection verified")
                return True
            else:
                logger.warning("Gemini test returned empty response")
                return False
        except Exception as e:
            logger.error(f"Gemini connection test failed: {str(e)}")
            return False
    
    def generate_response(self, prompt: str, system_context: str = "") -> str:
        """Generate response with retry logic and better error handling"""
        max_retries = 2
        
        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Generating response (attempt {attempt}/{max_retries})")
                
                full_prompt = f"{system_context}\n\nUser Query: {prompt}" if system_context else prompt
                
                response = self.model.generate_content(
                    full_prompt,
                    safety_settings=self.safety_settings,
                    generation_config=genai.types.GenerationConfig(
                        temperature=0.7,
                        top_p=0.8,
                        top_k=40,
                        max_output_tokens=2048,
                    )
                )
                
                if response and hasattr(response, 'text') and response.text:
                    logger.info(f"✅ Generated response: {len(response.text)} characters")
                    return response.text
                elif hasattr(response, 'prompt_feedback'):
                    # Handle safety filter blocks
                    feedback = response.prompt_feedback
                    logger.warning(f"Response blocked by safety filters: {feedback}")
                    return (f"⚠️ I apologize, but I cannot respond to this query due to content safety filters. "
                           f"This often happens with security-related queries containing attack terminology.\n\n"
                           f"**Try rephrasing your question** or ask about:\n"
                           f"- General security concepts\n"
                           f"- SIEM best practices\n"
                           f"- Query building techniques\n"
                           f"- Log analysis methods")
                else:
                    logger.warning(f"Empty response on attempt {attempt}")
                    if attempt == max_retries:
                        return "I generated an empty response. Please try rephrasing your question."
                    
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Error generating response (attempt {attempt}): {error_msg}")
                
                if "dangerous_content" in error_msg.lower() or "safety" in error_msg.lower():
                    return (f"⚠️ Content Safety Notice: Your query was blocked by Gemini's safety filters.\n\n"
                           f"**For security analysis queries**, try:\n"
                           f"- 'Explain how to detect brute force attacks'\n"
                           f"- 'What are common authentication failure patterns?'\n"
                           f"- 'Help me understand KQL query syntax'\n"
                           f"- 'Show me how to analyze security logs'")
                
                if attempt == max_retries:
                    return (f"❌ Error: Unable to generate response after {max_retries} attempts.\n\n"
                           f"**Error details:** {error_msg[:150]}\n\n"
                           f"**Troubleshooting:**\n"
                           f"- Check your GOOGLE_API_KEY in .env\n"
                           f"- Verify API quota/billing status\n"
                           f"- Try a simpler question")
        
        return "Unable to generate response. Please try again."
    
    def explain_query(self, query: str, query_type: str = "KQL") -> str:
        """Explain a security query in educational terms"""
        explanation_prompt = f"""
As a SIEM expert educator, explain this {query_type} query for a junior analyst:

Query: {query}

Provide:
1. What this query does (in simple terms)
2. Each component's purpose
3. Why this approach is effective
4. Expected results format

Use clear, educational language suitable for learning.
"""
        return self.generate_response(explanation_prompt)
    
    @staticmethod
    def list_available_models():
        """Helper to list available Gemini models"""
        try:
            models = genai.list_models()
            available = []
            for m in models:
                if 'generateContent' in m.supported_generation_methods:
                    available.append({
                        'name': m.name,
                        'display_name': m.display_name,
                        'description': getattr(m, 'description', 'No description')
                    })
            return available
        except Exception as e:
            return f"Error listing models: {str(e)}"
