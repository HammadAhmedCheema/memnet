from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QHBoxLayout, QPushButton, QLabel, QLineEdit, QFormLayout, QFrame

class AIAnalystViewWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)
        
        # Title
        title = QLabel("Forensic AI Intelligence")
        title.setObjectName("TitleLabel")
        layout.addWidget(title)

        self.status_label = QLabel("// MONITORING CASE...")
        self.status_label.setStyleSheet("color: #0056D2; font-family: 'JetBrains Mono'; font-size: 11px; font-weight: bold;")
        
        self.artifact_counter = QLabel("ARTIFACTS AVAILABLE: 0")
        self.artifact_counter.setStyleSheet("color: #6B7280; font-family: 'JetBrains Mono'; font-size: 11px;")

        controls = QHBoxLayout()
        self.generate_btn = QPushButton("GENERATE FINAL REPORT")
        self.export_btn = QPushButton("EXPORT REPORT")
        self.export_btn.setObjectName("Secondary")
        self.export_btn.setEnabled(False)
        
        controls.addWidget(self.generate_btn)
        controls.addWidget(self.export_btn)
        controls.addStretch()
        controls.addWidget(self.artifact_counter)
        controls.addWidget(self.status_label)
        
        # Report Display
        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)
        self.chat_history.setPlaceholderText("The forensic AI report will appear here after analysis...")
        self.chat_history.setStyleSheet("""
            QTextEdit {
                background-color: #F9FAFB;
                border: 1px solid #E5E7EB;
                border-radius: 4px;
                font-family: 'JetBrains Mono', monospace;
                font-size: 13px;
                color: #1F2937;
                padding: 20px;
            }
        """)
        
        layout.addLayout(controls)
        layout.addWidget(self.chat_history)
        
        self.setLayout(layout)
        
    def append_message(self, role, text):
        color = "#0056D2" if role == "USER" else "#374151"
        self.chat_history.append(f"<b style='color: {color};'>[{role}]</b> {text}<br>")
        # Scroll to bottom
        self.chat_history.verticalScrollBar().setValue(self.chat_history.verticalScrollBar().maximum())
