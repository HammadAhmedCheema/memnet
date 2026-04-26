from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QGraphicsView, QGraphicsScene, 
                             QGraphicsItem, QGraphicsEllipseItem, QGraphicsLineItem, 
                             QLabel, QHBoxLayout, QPushButton, QFrame, QGridLayout)
from PyQt6.QtCore import Qt, QRectF, QPointF, pyqtSignal
from PyQt6.QtGui import QPen, QBrush, QColor, QFont, QPainter

class GraphNode(QGraphicsEllipseItem):
    def __init__(self, node_id, label, node_type="process", metadata=None, parent=None):
        super().__init__(-30, -30, 60, 60)
        self.node_id = node_id
        self.label_text = label
        self.node_type = node_type
        self.metadata = metadata or {}
        self.on_click_handler = None
        self.edges = []
        
        self.setAcceptHoverEvents(True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)

        # Styling
        if node_type == "process":
            self.color = QColor("#0056D2") # Forensic Blue
        elif node_type == "network":
            self.color = QColor("#991B1B") # Deep Red for Net
        elif node_type == "memory":
            self.color = QColor("#059669") # Emerald Green for Memory
        else:
            self.color = QColor("#4B5563") # Gray default
            
        self.setPen(QPen(self.color, 1))
        self.setBrush(QBrush(self.color)) # Solid fill for retro look

        # Set ToolTip (HTML Box) - Light Mode
        self.prepare_tooltip()

    def update_metadata(self, metadata):
        if metadata:
            self.metadata.update(metadata)
            self.prepare_tooltip()

    def prepare_tooltip(self):
        html = f"<div style='background-color: white; color: #1F2937; padding: 10px; border: 1px solid {self.color.name()};'>"
        html += f"<b style='color: {self.color.name()}; font-size: 14px;'>{self.node_type.upper()} INTELLIGENCE</b><br><br>"
        for k, v in self.metadata.items():
            html += f"<b>{k}:</b> {v}<br>"
        html += "</div>"
        self.setToolTip(html)

    def boundingRect(self):
        # Expand bounding rect to include the text label drawn below
        return QRectF(-100, -30, 200, 110)

    def paint(self, painter, option, widget=None):
        super().paint(painter, option, widget)
        painter.setPen(QPen(QColor("#111827"))) # Dark text
        painter.setFont(QFont("JetBrains Mono", 8, QFont.Weight.Bold))
        
        # Center the label below node
        text_rect = QRectF(-75, 35, 150, 40)
        painter.drawText(text_rect, Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap, self.label_text)

    def mouseDoubleClickEvent(self, event):
        if self.on_click_handler:
            self.on_click_handler(self.node_type, self.node_id)
        super().mouseDoubleClickEvent(event)

    def mousePressEvent(self, event):
        super().mousePressEvent(event)

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionChange:
            for edge in self.edges:
                edge.update_position()
        return super().itemChange(change, value)

class GraphEdge(QGraphicsLineItem):
    def __init__(self, source_node, target_node):
        super().__init__()
        self.source = source_node
        self.target = target_node
        self.source.edges.append(self)
        self.target.edges.append(self)
        self.setZValue(-1)
        self.setPen(QPen(QColor("#9CA3AF"), 1, Qt.PenStyle.SolidLine))
        self.update_position()

    def update_position(self):
        line = QGraphicsLineItem(self.source.scenePos().x(), self.source.scenePos().y(),
                                  self.target.scenePos().x(), self.target.scenePos().y())
        self.setLine(line.line())

class GraphViewWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        # Header Info
        header = QHBoxLayout()
        header.setContentsMargins(20, 10, 20, 10)
        self.info_label = QLabel("// GRAPH ENGINE STANDBY")
        self.info_label.setStyleSheet("color: #0056D2; font-family: 'JetBrains Mono'; font-size: 11px;")
        
        self.zoom_in_btn = QPushButton("+")
        self.zoom_in_btn.setObjectName("Secondary")
        self.zoom_in_btn.setFixedWidth(40)
        self.zoom_in_btn.setStyleSheet("color: #111827; padding: 0px; font-size: 18px; font-weight: bold;")
        self.zoom_in_btn.clicked.connect(self.zoom_in)
        
        self.zoom_out_btn = QPushButton("-")
        self.zoom_out_btn.setObjectName("Secondary")
        self.zoom_out_btn.setFixedWidth(40)
        self.zoom_out_btn.setStyleSheet("color: #111827; padding: 0px; font-size: 18px; font-weight: bold;")
        self.zoom_out_btn.clicked.connect(self.zoom_out)

        self.clear_btn = QPushButton("CLEAR GRAPH")
        self.clear_btn.setObjectName("Secondary")
        self.clear_btn.setMinimumWidth(160)
        self.clear_btn.setStyleSheet("font-weight: bold;")
        self.clear_btn.clicked.connect(self.clear)
        
        header.addWidget(self.info_label)
        header.addStretch()
        header.addWidget(self.zoom_in_btn)
        header.addWidget(self.zoom_out_btn)
        header.addWidget(self.clear_btn)
        layout.addLayout(header)

        self.scene = QGraphicsScene()
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.view.setBackgroundBrush(QBrush(QColor("#F9FAFB")))
        self.view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.view.setFrameShape(QGraphicsView.Shape.NoFrame)
        
        layout.addWidget(self.view)
        self.setLayout(layout)
        
        # Fixed Legend (Top Right for better clinical layout)
        self.legend = QFrame(self)
        self.legend.setStyleSheet("background: transparent; border: none;")
        self.legend.setFixedWidth(280)
        
        legend_layout = QVBoxLayout(self.legend)
        legend_layout.setContentsMargins(15, 15, 15, 15)
        legend_layout.setSpacing(12)
        
        def add_legend_item(color, text):
            item_row = QHBoxLayout()
            item_row.setSpacing(12)
            dot = QFrame()
            dot.setFixedSize(16, 16)
            dot.setStyleSheet(f"background-color: {color}; border-radius: 8px;")
            label = QLabel(text)
            label.setStyleSheet("color: #1F2937; font-family: 'JetBrains Mono'; font-size: 13px; font-weight: bold; border: none;")
            item_row.addWidget(dot)
            item_row.addWidget(label)
            item_row.addStretch()
            legend_layout.addLayout(item_row)

        add_legend_item("#0056D2", "PROCESS NODE")
        add_legend_item("#991B1B", "NETWORK CONNECTION")
        add_legend_item("#059669", "MEMORY OFFSET")
        add_legend_item("#9CA3AF", "RELATIONSHIP LINK")
        
        # Ensure the legend actually takes up space
        self.legend.adjustSize()
        
        # Position legend in resize event
        self.legend.raise_() # Bring to front
        self.nodes = {}
        self.node_click_callback = None

    def resizeEvent(self, event):
        super().resizeEvent(event)
        # Keep legend in top-right
        self.legend.raise_()
        self.legend.move(self.width() - self.legend.width() - 30, 70)
        self.legend.show()

    def zoom_in(self):
        self.view.scale(1.2, 1.2)

    def zoom_out(self):
        self.view.scale(0.8, 0.8)

    def reset_view(self):
        self.view.resetTransform()
        if self.nodes:
            self.view.fitInView(self.scene.itemsBoundingRect(), Qt.AspectRatioMode.KeepAspectRatio)
        else:
            self.view.centerOn(0, 0)

    def clear(self):
        self.scene.clear()
        self.nodes = {}
        self.info_label.setText("// GRAPH ENGINE STANDBY")
        self.view.resetTransform()

    def add_node(self, node_id, label, node_type="process", metadata=None, pos=None):
        if node_id in self.nodes:
            node = self.nodes[node_id]
            if metadata:
                node.update_metadata(metadata)
            return node
            
        node = GraphNode(node_id, label, node_type, metadata)
        node.on_click_handler = self.node_click_callback
        if pos:
            node.setPos(pos[0], pos[1])
        self.scene.addItem(node)
        self.nodes[node_id] = node
        return node

    def add_edge(self, source_id, target_id):
        if source_id in self.nodes and target_id in self.nodes:
            # Check if edge already exists
            src = self.nodes[source_id]
            tar = self.nodes[target_id]
            for edge in src.edges:
                if (edge.source == src and edge.target == tar) or (edge.source == tar and edge.target == src):
                    return edge
            
            edge = GraphEdge(src, tar)
            self.scene.addItem(edge)
            return edge
        return None

    def add_forensic_node(self, node_type, node_id, label, metadata=None):
        import random
        pos = (random.randint(-300, 300), random.randint(-300, 300))
        node = self.add_node(node_id, label, node_type, metadata, pos)
        self.info_label.setText(f"// GRAPH UPDATED: Added {node_id} ({node_type})")
        return node

    def add_forensic_edge(self, source_id, target_id):
        return self.add_edge(source_id, target_id)
