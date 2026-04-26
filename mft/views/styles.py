def get_stylesheet():
    return """
    /* Main Window Background - Zimmerman Retro Clinical */
    QMainWindow, QWidget#central {
        background-color: #F9FAFB;
        color: #1F2937;
        font-family: 'Inter', system-ui, sans-serif;
    }

    /* Titles & Headers */
    QLabel#TitleLabel {
        font-family: 'Space Grotesk', sans-serif;
        font-size: 24px;
        font-weight: 600;
        color: #111827;
        margin-bottom: 10px;
        letter-spacing: -0.01em;
    }

    /* Dashboard Cards - Clinical Data Blocks */
    QFrame#StatsCard {
        background-color: #FFFFFF;
        border: 1px solid #D1D5DB;
        border-radius: 0px; 
        padding: 15px;
    }

    QLabel#CardValue {
        font-family: 'JetBrains Mono', monospace;
        font-size: 20px;
        font-weight: bold;
        color: #0056D2; 
    }

    QLabel#CardLabel {
        font-family: 'Space Grotesk', sans-serif;
        font-size: 10px;
        font-weight: 700;
        color: #4B5563;
        text-transform: uppercase;
        letter-spacing: 0.1em;
    }

    /* Table Widgets - High Visibility Grid */
    QTableWidget {
        background-color: #FFFFFF;
        alternate-background-color: #F9FAFB;
        gridline-color: #E5E7EB;
        color: #1F2937;
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
        border: 1px solid #D1D5DB;
        selection-background-color: #DBEAFE;
        selection-color: #1E40AF;
    }

    QHeaderView::section {
        background-color: #F3F4F6;
        color: #4B5563;
        padding: 10px;
        border: 1px solid #E5E7EB;
        font-family: 'Space Grotesk', sans-serif;
        font-weight: bold;
        text-transform: uppercase;
        font-size: 10px;
    }

    QHeaderView {
        background-color: #F3F4F6;
        border: none;
    }

    QTableCornerButton::section {
        background-color: #F3F4F6;
        border: 1px solid #E5E7EB;
    }

    /* Tabs - Efficient Navigation */
    QTabWidget::pane {
        border-top: 1px solid #D1D5DB;
        background: #FFFFFF;
        top: -1px;
    }

    QTabWidget::tab-bar {
        alignment: left;
    }

    QTabBar::tab {
        background: #F3F4F6;
        border: 1px solid #E5E7EB;
        border-bottom-color: #D1D5DB;
        padding: 12px 30px;
        color: #6B7280;
        font-family: 'Space Grotesk', sans-serif;
        font-weight: bold;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-right: -1px;
    }

    QTabBar::tab:selected {
        background: #FFFFFF;
        color: #0056D2;
        border-bottom-color: #FFFFFF;
        border-top: 2px solid #0056D2;
    }

    QTabBar::tab:hover:!selected {
        background: #EDF0F3;
        color: #111827;
    }

    /* Buttons - Forensic Precision */
    QPushButton {
        background-color: #0056D2;
        color: #FFFFFF;
        border: none;
        padding: 10px 22px;
        border-radius: 0px;
        font-family: 'Space Grotesk', sans-serif;
        font-weight: 700;
        text-transform: uppercase;
        font-size: 11px;
    }

    QPushButton:hover {
        background-color: #003A8C;
    }

    QPushButton:pressed {
        background-color: #002D6B;
    }

    /* Ghost Buttons - Utility Scale */
    QPushButton#Secondary {
        background-color: transparent;
        color: #4B5563;
        border: 1px solid #D1D5DB;
        font-family: 'JetBrains Mono', monospace;
    }

    QPushButton#Secondary:hover {
        background-color: #F3F4F6;
        border: 1px solid #0056D2;
        color: #0056D2;
    }

    /* Inputs - Forensic Entry */
    QLineEdit {
        background-color: #FFFFFF;
        border: 1px solid #D1D5DB;
        border-radius: 0px;
        padding: 8px;
        color: #111827;
        font-family: 'JetBrains Mono', monospace;
    }

    QLineEdit:focus {
        border: 1px solid #0056D2;
    }

    """
