from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTreeView, 
                             QPushButton, QLabel, QHeaderView)
from PyQt6.QtGui import QStandardItemModel, QStandardItem, QIcon
from PyQt6.QtCore import Qt, pyqtSignal

class TorEvidenceWidget(QWidget):
    investigate_clicked = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        # Header section
        header_layout = QHBoxLayout()
        title_label = QLabel("DARK WEB EVIDENCE // SURGICAL ARTIFACTS")
        title_label.setStyleSheet("color: #ecf0f1; font-family: 'JetBrains Mono'; font-size: 16px; font-weight: bold;")
        
        self.scan_btn = QPushButton("🚀 INVESTIGATE DARK WEB ACTIVITY")
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #34495e; color: #ecf0f1; border: 1px solid #7f8c8d;
                padding: 10px 20px; font-family: 'JetBrains Mono'; font-weight: bold;
            }
            QPushButton:hover { background-color: #065F46; border-color: #27ae60; }
        """)
        self.scan_btn.clicked.connect(lambda: self.investigate_clicked.emit())

        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(self.scan_btn)
        layout.addLayout(header_layout)

        # Evidence Tree
        self.tree_view = QTreeView()
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(["Category / Artifact", "Evidence Value", "Evidence Source/Path"])
        
        self.tree_view.setModel(self.model)
        self.tree_view.setSelectionBehavior(QTreeView.SelectionBehavior.SelectItems)
        self.tree_view.setSelectionMode(QTreeView.SelectionMode.ExtendedSelection)
        self.tree_view.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.tree_view.header().setCascadingSectionResizes(True)
        self.tree_view.header().setStretchLastSection(True)
        self.tree_view.setStyleSheet("""
            QTreeView {
                background-color: #1a1c1e; color: #d1d5db; 
                border: 1px solid #374151; font-family: 'JetBrains Mono';
            }
            QTreeView::item { padding: 8px; border-bottom: 1px solid #2d2d2d; }
            QTreeView::item:selected { background-color: #065F46; color: white; }
        """)
        
        layout.addWidget(self.tree_view)
        self.setLayout(layout)

    def clear(self):
        self.model.removeRows(0, self.model.rowCount())

    def add_category(self, name, icon_char="📁"):
        cat_item = QStandardItem(f"{icon_char} {name}")
        cat_item.setEditable(False)
        cat_item.setData("category", Qt.ItemDataRole.UserRole)
        self.model.appendRow(cat_item)
        return cat_item

    def add_artifact(self, parent_item, name, value, source):
        name_item = QStandardItem(name)
        val_item = QStandardItem(str(value))
        src_item = QStandardItem(str(source))
        
        for item in [name_item, val_item, src_item]:
            item.setEditable(False)
            
        parent_item.appendRow([name_item, val_item, src_item])
        self.tree_view.expandAll()
