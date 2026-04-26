from PyQt6.QtCore import QThread, pyqtSignal
from memnet.ai.gemini_client import GeminiClient

class AIWorker(QThread):
    finished = pyqtSignal(str) # The AI Markdown response
    error = pyqtSignal(str) # The error string

    def __init__(self, api_key, context_data, parent=None):
        super().__init__(parent)
        self.api_key = api_key
        self.context_data = context_data

    def run(self):
        try:
            if not self.api_key:
                self.error.emit("API Key is missing or invalid.")
                return
            
            client = GeminiClient(self.api_key)
            report_md = client.generate_report(self.context_data)
            
            self.finished.emit(report_md)
        except Exception as e:
            self.error.emit(str(e))
