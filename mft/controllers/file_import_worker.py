from PyQt6.QtCore import QThread, pyqtSignal
import hashlib
import os

class FileImportWorker(QThread):
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(str, str, str)  # md5, sha256, filepath
    error = pyqtSignal(str)

    def __init__(self, filepath, parent=None):
        super().__init__(parent)
        self.filepath = filepath

    def run(self):
        try:
            if not os.path.exists(self.filepath):
                self.error.emit(f"File not found: {self.filepath}")
                return

            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()
            
            file_size = os.path.getsize(self.filepath)
            processed = 0

            with open(self.filepath, "rb") as f:
                # Read in 4MB chunks to handle multi-gigabyte memory dumps efficiently
                for chunk in iter(lambda: f.read(4096 * 1024), b""): 
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
                    processed += len(chunk)
                    if file_size > 0:
                        prog = int((processed / file_size) * 100)
                        self.progress.emit(prog, "Hashing Evidence...")

            self.finished.emit(md5_hash.hexdigest(), sha256_hash.hexdigest(), self.filepath)
        except Exception as e:
            self.error.emit(str(e))
