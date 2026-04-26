from PyQt6.QtCore import QThread, pyqtSignal
import json

class AIChatWorker(QThread):
    finished = pyqtSignal(str)
    tool_requested = pyqtSignal(str, dict) # function_name, arguments
    error = pyqtSignal(str)

    def __init__(self, chat_session, prompt):
        super().__init__()
        self.chat_session = chat_session
        self.prompt = prompt

    def run(self):
        try:
            response = self.chat_session.send_message(self.prompt)
            
            # Check for tool calls
            # In google-genai SDK, parts containing function_calls are processed
            # We'll simplify the signal for the controller to execute
            for part in response.candidates[0].content.parts:
                if part.function_call:
                    name = part.function_call.name
                    args = part.function_call.args
                    self.tool_requested.emit(name, args)
                    return # Exit to wait for tool result in next step

            self.finished.emit(response.text)
        except Exception as e:
            self.error.emit(str(e))
