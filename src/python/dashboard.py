import sys
import os
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit
from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QPixmap
import sqlite3
from graphviz import Source
from anomaly_detector import AnomalyDetector
from reports import generate_report
from timeline_widget import TimelineWidget

class Dashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('STAS Dashboard')
        self.setMinimumSize(1200, 820)
        self.setStyleSheet("background-color: #0D1117; color: #fff;")  # Dark mode
        self.db_path = self.resolve_db_path()

        central = QWidget()
        layout = QVBoxLayout()

        self.load_btn = QPushButton('Load Sample')
        self.load_btn.clicked.connect(self.load_sample)
        layout.addWidget(self.load_btn)

        self.event_feed = QTextEdit()
        layout.addWidget(QLabel('Live Event Feed'))
        layout.addWidget(self.event_feed)

        self.timeline = TimelineWidget(self.db_path)
        layout.addWidget(QLabel('Timeline'))
        layout.addWidget(self.timeline, 1)

        self.risk_label = QLabel('Risk Score: 0')
        layout.addWidget(self.risk_label)

        self.graph_preview = QLabel()  # For GraphViz PNG
        layout.addWidget(self.graph_preview)

        self.export_btn = QPushButton('Export Report')
        self.export_btn.clicked.connect(self.export_report)
        layout.addWidget(self.export_btn)

        central.setLayout(layout)
        self.setCentralWidget(central)

        # Live update timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_feed)
        self.timer.start(1000)

        self.ad = AnomalyDetector()

    def load_sample(self):
        # Call C++ engine via subprocess or IPC
        import subprocess
        engine = '../../build/stas_engine.exe' if sys.platform.startswith('win') else '../../build-linux/stas_engine'
        subprocess.call([engine, 'sample.exe'])
        self.update_dashboard()

    def update_feed(self):
        # Read from SQLite
        if not os.path.exists(self.db_path):
            self.event_feed.setText('No events database found yet.')
            self.timeline.set_events([])
            return

        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute('SELECT * FROM events ORDER BY timestamp DESC LIMIT 10')
            events = cur.fetchall()
            self.event_feed.setText('\n'.join(str(e) for e in events))
            conn.close()
            self.timeline.load_from_sqlite(self.db_path)
        except sqlite3.Error as exc:
            self.event_feed.setText(f'SQLite error: {exc}')

    def update_dashboard(self):
        # Risk score from DB or calc
        self.risk_label.setText('Risk Score: 85')

        # Timeline
        self.timeline.load_from_sqlite(self.db_path)

        # GraphViz
        if os.path.exists('output.dot'):
            with open('output.dot', 'r') as f:
                src = Source(f.read())
                src.render('output', format='png')
            pixmap = QPixmap('output.png')
            self.graph_preview.setPixmap(pixmap)

        # ML labels
        events = []  # Fetch from DB
        labels = self.ad.detect_anomalies(events)
        print(labels)

    def export_report(self):
        generate_report(self.db_path, 'report.html')

    def resolve_db_path(self):
        here = os.path.dirname(os.path.abspath(__file__))
        candidates = [
            os.path.abspath(os.path.join(here, '../../events.db')),
            os.path.abspath(os.path.join(here, 'events.db')),
            os.path.abspath('events.db'),
        ]
        for path in candidates:
            if os.path.exists(path):
                return path
        return candidates[0]

if __name__ == '__main__':
    app = QApplication(sys.argv)
    win = Dashboard()
    win.show()
    sys.exit(app.exec())
