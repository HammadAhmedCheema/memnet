from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTabWidget, QTableWidget, QTableWidgetItem, QHBoxLayout, QPushButton, QLabel, QHeaderView, QFrame, QLineEdit
from PyQt6.QtCore import Qt, pyqtSignal

class CredentialsViewWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)

        # Title
        title_container = QHBoxLayout()
        title = QLabel("Credential Extraction Hub")
        title.setObjectName("TitleLabel")
        status_label = QLabel("// SECURITY OVERRIDE")
        status_label.setStyleSheet("color: #0056D2; font-family: 'JetBrains Mono'; font-size: 10px; font-weight: bold;")
        title_container.addWidget(title)
        title_container.addStretch()
        title_container.addWidget(status_label)
        layout.addLayout(title_container)
        
        controls = QHBoxLayout()
        self.scan_hashdump_btn = QPushButton("EXTRACT HASHDUMP")
        self.scan_cachedump_btn = QPushButton("EXTRACT CACHEDUMP")
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter credentials...")
        self.search_input.setFixedWidth(250)
        self.search_input.textChanged.connect(self.filter_table)

        self.status_label = QLabel("// STANDBY")
        self.status_label.setStyleSheet("color: #0056D2; font-family: 'JetBrains Mono'; font-size: 11px;")
        
        controls.addWidget(self.scan_hashdump_btn)
        controls.addWidget(self.scan_cachedump_btn)
        controls.addWidget(self.search_input)
        controls.addStretch()
        controls.addWidget(self.status_label)
        
        self.table = QTableWidget()
        self.table.setColumnCount(0)
        self.table.setRowCount(0)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.setSortingEnabled(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addLayout(controls)
        layout.addWidget(self.table)
        self.setLayout(layout)

    def filter_table(self, text):
        for i in range(self.table.rowCount()):
            row_visible = False
            for j in range(self.table.columnCount()):
                item = self.table.item(i, j)
                if item and text.lower() in item.text().lower():
                    row_visible = True
                    break
            self.table.setRowHidden(i, not row_visible)

    def populate_table(self, data):
        self.table.setSortingEnabled(False)
        self.table.clear()
        
        if not data:
            self.table.setColumnCount(0)
            self.table.setRowCount(0)
            self.table.setSortingEnabled(True)
            return

        headers = list(data[0].keys())
        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.setRowCount(len(data))
        
        for row_idx, row_dict in enumerate(data):
            for col_idx, col_name in enumerate(headers):
                val = row_dict.get(col_name, "")
                
                # Format Offsets as Hex (New)
                if "OFFSET" in col_name.upper():
                    try:
                        if isinstance(val, (int, str)) and val:
                            val = hex(int(val))
                    except (ValueError, TypeError):
                        pass

                item = QTableWidgetItem(str(val))
                self.table.setItem(row_idx, col_idx, item)
                
        # Auto-resize columns to fit headers and content
        for i in range(self.table.columnCount()):
            self.table.resizeColumnToContents(i)
            self.table.setColumnWidth(i, self.table.columnWidth(i) + 25) # Buffer for sort arrow
            
        self.table.setSortingEnabled(True)
