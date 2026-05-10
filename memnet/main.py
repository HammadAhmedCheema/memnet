import sys
import os

# Silence annoying Qt font warnings on Linux
os.environ["QT_LOGGING_RULES"] = "qt.text.font.db.warning=false"

from PyQt6.QtWidgets import QApplication
from memnet.models.database import init_db
from memnet.controllers.main_controller import MainController

import multiprocessing

def main():
    # Fix for multiprocessing issues in PyQt/GUI apps on Linux
    try:
        multiprocessing.set_start_method('spawn', force=True)
    except RuntimeError:
        pass

    # Initialize SQLite database
    init_db()
    
    app = QApplication(sys.argv)
    
    # Initialize the primary controller which manages the view
    controller = MainController()
    controller.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
