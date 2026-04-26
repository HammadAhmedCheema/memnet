from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QComboBox, 
                             QPushButton, QLineEdit, QTableView, QLabel, QFrame, QMenu, QHeaderView)
from PyQt6.QtCore import Qt, pyqtSignal, QPoint
from .models import VolatilityTableModel

class BaseForensicView(QWidget):
    execute_plugin = pyqtSignal(str, str) # plugin_alias, params
    add_to_bookmark = pyqtSignal(dict)
    add_to_graph = pyqtSignal(dict)

    def __init__(self, title, options):
        super().__init__()
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Header / Control Bar
        control_bar = QHBoxLayout()
        
        self.dropdown = QComboBox()
        self.dropdown.addItems(options)
        self.dropdown.setMinimumWidth(250)
        self.dropdown.setFixedHeight(35)
        
        self.param_input = QLineEdit()
        self.param_input.setPlaceholderText("Optional Parameters (PID, Key Path, etc.)...")
        self.param_input.setFixedHeight(35)
        self.param_input.hide() # Hidden by default, shown based on plugin logic
        
        self.run_btn = QPushButton("EXECUTE COMMAND")
        self.run_btn.setFixedHeight(35)
        self.run_btn.setMinimumWidth(150)
        self.run_btn.clicked.connect(self.handle_run)

        self.status_label = QLabel("// STANDBY")
        self.status_label.setStyleSheet("color: #869399; font-family: 'JetBrains Mono'; font-size: 11px;")

        control_bar.addWidget(self.dropdown)
        control_bar.addWidget(self.param_input)
        control_bar.addWidget(self.run_btn)
        control_bar.addStretch()
        control_bar.addWidget(self.status_label)
        
        layout.addLayout(control_bar)

        # Table View
        self.table_view = QTableView()
        self.table_view.setAlternatingRowColors(True)
        self.table_view.setSelectionBehavior(QTableView.SelectionBehavior.SelectItems)
        self.table_view.setSelectionMode(QTableView.SelectionMode.ExtendedSelection)
        self.table_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table_view.customContextMenuRequested.connect(self.show_context_menu)
        self.table_view.setVerticalScrollMode(QTableView.ScrollMode.ScrollPerPixel)
        self.table_view.setHorizontalScrollMode(QTableView.ScrollMode.ScrollPerPixel)
        self.table_view.setShowGrid(False)
        self.table_view.setObjectName("ForensicTable")
        
        self.model = VolatilityTableModel()
        self.table_view.setModel(self.model)
        
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table_view.horizontalHeader().setStretchLastSection(True)
        
        layout.addWidget(self.table_view)
        self.setLayout(layout)

        # Dropdown change logic to show/hide param input
        self.dropdown.currentTextChanged.connect(self.on_dropdown_changed)

    def on_dropdown_changed(self, text):
        # Specific keywords that trigger parameter visibility
        needs_param = ["Query Specific Key", "Dump Executable"]
        if any(keyword in text for keyword in needs_param):
            self.param_input.show()
            
            # Context-sensitive placeholders
            if "Query Specific Key" in text:
                self.param_input.setPlaceholderText("Key Path (e.g. ControlSet001\\Control\\Lsa)")
            elif "Dump Executable" in text:
                self.param_input.setPlaceholderText("Target PID")
        else:
            self.param_input.hide()

    def handle_run(self):
        plugin_alias = self.dropdown.currentText()
        params = self.param_input.text()
        self.execute_plugin.emit(plugin_alias, params)

    def update_results(self, data):
        self.model.update_data(data)
        self.table_view.resizeColumnsToContents()
        count = len(data) if data else 0
        self.status_label.setText(f"// EXECUTION COMPLETE: {count} ROWS RETURNED")

    def show_context_menu(self, position: QPoint):
        index = self.table_view.indexAt(position)
        if not index.isValid():
            return

        row_data = self.model._data[index.row()]
        
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu { background-color: #1a1c1e; color: #d1d5db; border: 1px solid #374151; font-family: 'JetBrains Mono'; }
            QMenu::item:selected { background-color: #374151; color: white; }
        """)
        
        # Color Highlight Sub-menu
        color_menu = menu.addMenu("🎨 Highlight Row")
        color_menu.setStyleSheet(menu.styleSheet())
        
        colors = [
            ("🟢 Malicious", "#065F46"),
            ("🔴 Critical", "#7F1D1D"),
            ("🔵 Info", "#1E3A8A"),
            ("🟠 Suspicious", "#7C2D12"),
            ("⚪ Clear Highlight", None)
        ]
        
        color_actions = {}
        for label, hex_code in colors:
            act = color_menu.addAction(label)
            color_actions[act] = hex_code

        graph_action = menu.addAction("🕸️ Add to Relation Graph")
        
        action = menu.exec(self.table_view.viewport().mapToGlobal(position))
        
        if action in color_actions:
            self.model.toggle_bookmark(index.row(), color_actions[action])
        elif action == graph_action:
            self.add_to_graph.emit(row_data)
