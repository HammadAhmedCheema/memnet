from PyQt6.QtCore import QThread, pyqtSignal

class AIReportWorker(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, client, context):
        super().__init__()
        self.client = client
        self.context = context

    def run(self):
        try:
            report = self.client.generate_report(self.context)
            self.finished.emit(report)
        except Exception as e:
            self.error.emit(str(e))
