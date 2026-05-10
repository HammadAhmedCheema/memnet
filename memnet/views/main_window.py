from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QTabWidget
from memnet.views.dashboard import DashboardWidget
from memnet.views.ai_analyst_view import AIAnalystViewWidget
from memnet.views.graph_view import GraphViewWidget
from memnet.views.tor_view import TorEvidenceWidget
from memnet.views.styles import get_stylesheet
from memnet.views.base_forensic_view import BaseForensicView
from memnet.views.extraction_view import ExtractionWidget
from memnet.constants.plugin_map import TAB_CONFIG
from PyQt6.QtWidgets import QProgressBar, QLabel

class MainWindow(QMainWindow):
    closing = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("MemNet PRO // Memory Analysis Environment")
        self.setGeometry(100, 100, 1260, 900)
        self.setStyleSheet(get_stylesheet())
        
        central_widget = QWidget()
        central_widget.setObjectName("central")
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Top Tab Navigation (Eric Zimmerman style)
        self.tabs = QTabWidget()
        
        # v2.0 Investigative Hub
        self.dashboard_view = DashboardWidget()
        self.ai_analyst_view = AIAnalystViewWidget()
        self.graph_view = GraphViewWidget()
        self.tor_view = TorEvidenceWidget()
        
        # Categorized Forensic Views
        self.process_view = BaseForensicView("Process Intelligence", TAB_CONFIG["Process Intelligence"])
        self.network_view = BaseForensicView("Network & Comms", TAB_CONFIG["Network & Comms"])
        self.threat_view = BaseForensicView("Threat Hunting", TAB_CONFIG["Threat Hunting"])
        self.system_view = BaseForensicView("System & Extraction", TAB_CONFIG["System & Extraction"])
        self.extraction_view = ExtractionWidget()
        
        self.tabs.addTab(self.dashboard_view, "DASHBOARD")
        self.tabs.addTab(self.process_view, "PROCESS")
        self.tabs.addTab(self.network_view, "NETWORK")
        self.tabs.addTab(self.threat_view, "THREAT HUNT")
        self.tabs.addTab(self.system_view, "SYSTEM")
        self.tabs.addTab(self.extraction_view, "DATA EXTRACTION")
        self.tabs.addTab(self.ai_analyst_view, "AI ANALYST")
        self.tabs.addTab(self.graph_view, "GRAPH")
        self.tabs.addTab(self.tor_view, "DARK WEB EVIDENCE")
        
        layout.addWidget(self.tabs)
        central_widget.setLayout(layout)

        # Status Bar with Progress
        self.status_bar = self.statusBar()
        self.progress_label = QLabel("READY")
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_label)
        self.status_bar.addPermanentWidget(self.progress_bar)

    def closeEvent(self, event):
        self.closing.emit()
        super().closeEvent(event)
