from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QFormLayout, QProgressBar, QFrame, QGridLayout, QTableWidget, QTableWidgetItem, QHeaderView
from PyQt6.QtCore import Qt

class StatCard(QFrame):
    def __init__(self, label, value, parent=None):
        super().__init__(parent)
        self.setObjectName("StatsCard")
        layout = QVBoxLayout()
        layout.setSpacing(4)
        
        self.label_widget = QLabel(label)
        self.label_widget.setObjectName("CardLabel")
        
        self.value_widget = QLabel(value)
        self.value_widget.setObjectName("CardValue")
        
        layout.addWidget(self.label_widget)
        layout.addWidget(self.value_widget)
        self.setLayout(layout)

class DashboardWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.main_layout = QVBoxLayout()
        self.main_layout.setContentsMargins(30, 30, 30, 30)
        self.main_layout.setSpacing(20)

        # Title
        title_container = QHBoxLayout()
        title = QLabel("Forensic Analysis Suite")
        title.setObjectName("TitleLabel")
        
        status_chip = QLabel(" // PHASE 4 MISSION ACTIVE")
        status_chip.setStyleSheet("color: #0056D2; font-family: 'JetBrains Mono'; font-size: 10px; font-weight: bold;")
        
        title_container.addWidget(title)
        title_container.addStretch()
        title_container.addWidget(status_chip)
        
        self.main_layout.addLayout(title_container)

        # Stats Grid - Clean industrial overview
        stats_layout = QGridLayout()
        stats_layout.setSpacing(20)
        self.total_processes = StatCard("Process Count", "0")
        self.network_conns = StatCard("Network Streams", "0")
        self.url_count = StatCard("URLs Found", "0")
        self.browser_count = StatCard("Browser History", "0")
        self.dark_web_indicator = StatCard("Tor Triage", "Negative")
        
        stats_layout.addWidget(self.total_processes, 0, 0)
        stats_layout.addWidget(self.network_conns, 0, 1)
        stats_layout.addWidget(self.url_count, 1, 0)
        stats_layout.addWidget(self.browser_count, 1, 1)
        stats_layout.addWidget(self.dark_web_indicator, 2, 0, 1, 2)
        
        self.main_layout.addLayout(stats_layout)

        # Simple Evidence Entry (Eric Zimmerman Style)
        ingestion_frame = QFrame()
        ingestion_frame.setObjectName("StatsCard")
        ingestion_layout = QVBoxLayout(ingestion_frame)
        ingestion_layout.setSpacing(20)
        ingestion_layout.setContentsMargins(30, 30, 30, 30)
        
        entry_header = QLabel("MEMORY DUMP INGESTION")
        entry_header.setObjectName("CardLabel")
        ingestion_layout.addWidget(entry_header)

        self.file_path_display = QLineEdit()
        self.file_path_display.setReadOnly(True)
        self.file_path_display.setPlaceholderText("No evidence file selected...")
        
        self.import_btn = QPushButton("LOAD EVIDENCE IMAGE")
        self.import_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.import_btn.setFixedHeight(50)
        
        # Integrity Table
        self.hash_table = QTableWidget(2, 2)
        self.hash_table.setHorizontalHeaderLabels(["Algorithm", "Checksum Value"])
        self.hash_table.verticalHeader().setVisible(False)
        self.hash_table.setFixedHeight(100)
        self.hash_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.hash_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.hash_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        
        self.hash_table.setItem(0, 0, QTableWidgetItem("MD5"))
        self.hash_table.setItem(1, 0, QTableWidgetItem("SHA256"))
        self.hash_table.setItem(0, 1, QTableWidgetItem("Calculating..."))
        self.hash_table.setItem(1, 1, QTableWidgetItem("Calculating..."))
        
        ingestion_layout.addWidget(self.file_path_display)
        ingestion_layout.addWidget(self.import_btn)
        ingestion_layout.addWidget(self.hash_table)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.hide()
        ingestion_layout.addWidget(self.progress_bar)
        
        self.main_layout.addWidget(ingestion_frame)

        self.main_layout.addStretch()
        self.setLayout(self.main_layout)

    def update_hashes(self, md5, sha256):
        self.hash_table.setItem(0, 1, QTableWidgetItem(md5))
        self.hash_table.setItem(1, 1, QTableWidgetItem(sha256))
