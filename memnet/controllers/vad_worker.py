from PyQt6.QtCore import QThread, pyqtSignal
from memnet.forensics.vol_engine import VolatilityEngine

class VadCacheWorker(QThread):
    finished = pyqtSignal(list)
    error = pyqtSignal(str)
    progress = pyqtSignal(int, str)

    def __init__(self, filepath, parent=None):
        super().__init__(parent)
        self.filepath = filepath

    def run(self):
        try:
            engine = VolatilityEngine(self.filepath, progress_callback=self.handle_progress)
            vad_map = engine.get_vad_map()
            self.finished.emit(vad_map)
        except Exception as e:
            self.error.emit(str(e))

    def handle_progress(self, percent, description):
        self.progress.emit(percent, description)
