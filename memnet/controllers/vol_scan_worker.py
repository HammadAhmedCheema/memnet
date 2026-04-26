from PyQt6.QtCore import QThread, pyqtSignal
from memnet.forensics.vol_engine import VolatilityEngine

class VolScanWorker(QThread):
    finished = pyqtSignal(str, list, str) # module_name, results_list, params
    error = pyqtSignal(str, str) # module_name, error_msg
    progress = pyqtSignal(int, str) # percent, description

    def __init__(self, filepath, plugin_name, params=None, parent=None):
        super().__init__(parent)
        self.filepath = filepath
        self.plugin_name = plugin_name
        self.params = params

    def run(self):
        try:
            # engine initialized with progress callback
            engine = VolatilityEngine(self.filepath, progress_callback=self.handle_progress)
            results = engine.run_plugin(self.plugin_name, self.params)
            self.finished.emit(self.plugin_name, results, self.params or "")
        except Exception as e:
            error_details = f"{type(e).__name__}: {str(e)}" if str(e) else repr(e)
            self.error.emit(self.plugin_name, error_details)

    def handle_progress(self, percent, description):
        self.progress.emit(percent, description)

