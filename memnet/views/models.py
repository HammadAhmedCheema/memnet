from PyQt6.QtCore import QAbstractTableModel, Qt
from PyQt6.QtGui import QBrush, QColor

class VolatilityTableModel(QAbstractTableModel):
    def __init__(self, data=None):
        super().__init__()
        self._data = data or []
        self._headers = []
        self._bookmarks = {} # Map row index -> color hex string
        if self._data:
            self._headers = list(self._data[0].keys())

    def rowCount(self, parent=None):
        return len(self._data)

    def columnCount(self, parent=None):
        return len(self._headers)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        
        row = index.row()
        if role == Qt.ItemDataRole.DisplayRole:
            row_data = self._data[row]
            col_key = self._headers[index.column()]
            val = row_data.get(col_key, "")
            
            # Format memory addresses and offsets as hexadecimal
            hex_keys = ["OFFSET", "ADDRESS", "BASE", "VIRTUAL", "PHYSICAL", "DTB"]
            if any(k in col_key.upper() for k in hex_keys):
                try:
                    # Handle both int and string representations from Volatility
                    if isinstance(val, (int, float)):
                        return f"0x{int(val):X}"
                    elif isinstance(val, str) and val.isdigit():
                        return f"0x{int(val):X}"
                except (ValueError, TypeError):
                    pass
                    
            return str(val)
        
        if role == Qt.ItemDataRole.BackgroundRole:
            if row in self._bookmarks:
                return QBrush(QColor(self._bookmarks[row]))
        
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self._headers[section]
        return None

    def update_data(self, data):
        self.beginResetModel()
        self._data = data or []
        self._bookmarks = {}
        if self._data:
            self._headers = list(self._data[0].keys())
        else:
            self._headers = []
        self.endResetModel()

    def toggle_bookmark(self, row, color_hex=None):
        if not color_hex:
            # Simple toggle off if no color provided
            if row in self._bookmarks:
                del self._bookmarks[row]
        else:
            # If same color exists, toggle off
            if self._bookmarks.get(row) == color_hex:
                del self._bookmarks[row]
            else:
                self._bookmarks[row] = color_hex
                
        self.dataChanged.emit(self.index(row, 0), self.index(row, self.columnCount()-1))
