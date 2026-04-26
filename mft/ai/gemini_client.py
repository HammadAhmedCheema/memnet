import os
import re
from google import genai

class GeminiClient:
    def __init__(self, api_key):
        self.api_key = api_key
        self.client = genai.Client(api_key=self.api_key)
        self.model_name = "gemini-flash-latest" # Exactly matching the user's working curl command

    def mask_pii(self, context_text):
        """Privacy Guard: Mask specific PII."""
        masked_text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[REDACTED_IP]', context_text)
        return masked_text

    def get_tool_definitions(self):
        """Defines forensic tools for the AI."""
        return [
            {
                "function_declarations": [
                    {
                        "name": "run_forensic_scan",
                        "description": "Executes a Volatility 3 plugin for deeper context.",
                        "parameters": {
                            "type": "OBJECT",
                            "properties": {
                                "plugin_name": {"type": "STRING", "description": "Plugin to run (e.g., malfind, handles)."},
                                "pid": {"type": "INTEGER", "description": "Target PID."}
                            },
                            "required": ["plugin_name"]
                        }
                    },
                    {
                        "name": "get_session_results",
                        "description": "Retrieves all completed forensic scan results from the current session database for correlation and report generation.",
                        "parameters": {
                            "type": "OBJECT",
                            "properties": {}
                        }
                    }
                ]
            }
        ]

    def start_chat(self):
        """Starts a conversational session with tools."""
        config = {
            "tools": self.get_tool_definitions(),
            "system_instruction": "You are the AuraForensics AI Analyst. Correlate artifacts and use tools to investigate."
        }
        return self.client.chats.create(model=self.model_name, config=config)

    def generate_report(self, consolidated_ctx):
        # ... (Existing report logic for one-shot remains if needed, but we prefer chat now)
        # Keeping for backward compatibility
        safe_ctx = self.mask_pii(consolidated_ctx)
        prompt = "Synthesize a forensic report for this data:\n" + safe_ctx
        response = self.client.models.generate_content(model=self.model_name, contents=prompt)
        return response.text
