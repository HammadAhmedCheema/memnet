from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QTabWidget, QTableWidget, 
                             QTableWidgetItem, QHBoxLayout, QPushButton, QLabel, 
                             QHeaderView, QFrame, QLineEdit, QMenu)
from PyQt6.QtCore import Qt, pyqtSignal, QPoint

class ExtractionWidget(QWidget):
    add_to_bookmark = pyqtSignal(dict)
    add_to_graph = pyqtSignal(dict)
    def __init__(self):
        super().__init__()
        self.main_layout = QVBoxLayout()
        self.main_layout.setContentsMargins(40, 40, 40, 40)
        self.main_layout.setSpacing(25)
        
        # Title
        title = QLabel("Specialist Evidence Extractors")
        title.setObjectName("TitleLabel")
        self.main_layout.addWidget(title)

        # Tab Widget
        self.tabs = QTabWidget()
        
        # Tab 1: URLs
        self.url_tab = QWidget()
        url_layout = QVBoxLayout(self.url_tab)
        url_layout.setContentsMargins(20, 20, 20, 20)
        
        url_controls = QHBoxLayout()
        self.extract_url_btn = QPushButton("EXECUTE URL HARVESTER")
        self.url_search = QLineEdit()
        self.url_search.setPlaceholderText("Filter URLs...")
        self.url_search.setFixedWidth(250)
        self.url_search.textChanged.connect(lambda t: self.filter_table(self.url_table, t))

        self.url_status = QLabel("// READY")
        self.url_status.setStyleSheet("color: #0056D2; font-family: 'JetBrains Mono'; font-size: 11px;")
        
        url_controls.addWidget(self.extract_url_btn)
        url_controls.addWidget(self.url_search)
        url_controls.addStretch()
        url_controls.addWidget(self.url_status)
        
        self.url_table = QTableWidget()
        self.url_table.setColumnCount(4)
        self.url_table.setHorizontalHeaderLabels(["OFFSET", "OWNER PID", "SIGNATURE", "EXTRACTED DATA"])
        self.url_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.url_table.setSortingEnabled(True)
        self.url_table.verticalHeader().setVisible(False)
        self.url_table.setAlternatingRowColors(True)
        self.url_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.url_table.customContextMenuRequested.connect(lambda pos: self.show_context_menu(self.url_table, pos))
        
        header = self.url_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        
        url_layout.addLayout(url_controls)
        url_layout.addWidget(self.url_table)
        
        # Tab 2: Browser Artifacts
        self.browser_tab = QWidget()
        browser_layout = QVBoxLayout(self.browser_tab)
        browser_layout.setContentsMargins(20, 20, 20, 20)
        
        browser_controls = QHBoxLayout()
        self.extract_browser_btn = QPushButton("DECRYPT BROWSER CACHE")
        self.browser_search = QLineEdit()
        self.browser_search.setPlaceholderText("Filter Browser data...")
        self.browser_search.setFixedWidth(250)
        self.browser_search.textChanged.connect(lambda t: self.filter_table(self.browser_table, t))

        self.browser_status = QLabel("// READY")
        self.browser_status.setStyleSheet("color: #0056D2; font-family: 'JetBrains Mono'; font-size: 11px;")
        
        browser_controls.addWidget(self.extract_browser_btn)
        browser_controls.addWidget(self.browser_search)
        browser_controls.addStretch()
        browser_controls.addWidget(self.browser_status)
        
        self.browser_table = QTableWidget()
        self.browser_table.setColumnCount(4)
        self.browser_table.setHorizontalHeaderLabels(["OFFSET", "OWNER PID", "IDENTITY", "ARTIFACT DATA"])
        self.browser_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.browser_table.setSortingEnabled(True)
        self.browser_table.verticalHeader().setVisible(False)
        self.browser_table.setAlternatingRowColors(True)
        self.browser_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.browser_table.customContextMenuRequested.connect(lambda pos: self.show_context_menu(self.browser_table, pos))
        
        b_header = self.browser_table.horizontalHeader()
        b_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        b_header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        b_header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        b_header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        
        browser_layout.addLayout(browser_controls)
        browser_layout.addWidget(self.browser_table)
        
        self.tabs.addTab(self.url_tab, "URL HARVESTER")
        self.tabs.addTab(self.browser_tab, "BROWSER DECRYPTOR")
        
        self.main_layout.addWidget(self.tabs)
        self.setLayout(self.main_layout)

    def filter_table(self, table, text):
        for i in range(table.rowCount()):
            row_visible = False
            for j in range(table.columnCount()):
                item = table.item(i, j)
                if item and text.lower() in item.text().lower():
                    row_visible = True
                    break
            table.setRowHidden(i, not row_visible)

    def populate_table(self, table, data):
        table.setRowCount(0)
        if not data:
            return
        table.setRowCount(len(data))
        for row_idx, row_dict in enumerate(data):
            offset_val = row_dict.get("Offset", "")
            # Format Offsets as Hex (New)
            try:
                if isinstance(offset_val, (int, str)) and offset_val:
                    offset_val = hex(int(offset_val))
            except (ValueError, TypeError):
                pass

            # PID Owner (New)
            pid_owner = row_dict.get("PID", "N/A")

            # Rule (URLs) or Identity (Browser)
            col1 = row_dict.get("Rule", row_dict.get("Identity", ""))
            
            # Match (URLs) or Data (Browser)
            col2 = row_dict.get("Match", row_dict.get("Data", ""))
            
            table.setItem(row_idx, 0, QTableWidgetItem(str(offset_val)))
            table.setItem(row_idx, 1, QTableWidgetItem(str(pid_owner)))
            table.setItem(row_idx, 2, QTableWidgetItem(str(col1)))
            table.setItem(row_idx, 3, QTableWidgetItem(str(col2)))

        # Auto-resize columns to fit headers and content
        for i in range(table.columnCount()):
            table.resizeColumnToContents(i)
            table.setColumnWidth(i, table.columnWidth(i) + 25) # Buffer for sort arrow

    def show_context_menu(self, table, position: QPoint):
        item = table.itemAt(position)
        if not item:
            return

        row = item.row()
        row_data = {
            "Offset": table.item(row, 0).text(),
            "PID": table.item(row, 1).text(),
            "Title": table.item(row, 2).text(),
            "Data": table.item(row, 3).text()
        }
        
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu { background-color: #1a1c1e; color: #d1d5db; border: 1px solid #374151; font-family: 'JetBrains Mono'; }
            QMenu::item:selected { background-color: #0056D2; color: white; }
        """)
        
        bookmark_action = menu.addAction("⭐ Add to Bookmarks")
        graph_action = menu.addAction("🕸️ Add to Relation Graph")
        
        action = menu.exec(table.viewport().mapToGlobal(position))
        
        if action == bookmark_action:
            self.add_to_bookmark.emit(row_data)
        elif action == graph_action:
            self.add_to_graph.emit(row_data)
