import sys
import requests
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QTextEdit, QLabel,
    QListWidget, QTableWidget, QTableWidgetItem
)
from PyQt5.QtCore import Qt
import webbrowser

API_URL = "http://ip-api.com/json/{}?fields=status,message,country,regionName,city,isp,org,as,timezone,lat,lon,proxy,hosting,query"


# ================= BACKEND =================

def fetch_ip(ip):
    try:
        res = requests.get(API_URL.format(ip), timeout=5)
        data = res.json()

        if data["status"] != "success":
            return {"ip": ip, "error": data.get("message")}

        lat, lon = data["lat"], data["lon"]

        return {
            "ip": data["query"],
            "location": f"{data['city']}, {data['regionName']}, {data['country']}",
            "isp": data["isp"],
            "org": data["org"],
            "asn": data["as"],
            "timezone": data["timezone"],
            "status": ("Proxy" if data["proxy"] else "") + (" Hosting/VPN" if data["hosting"] else "") or "Clean",
            "map": f"https://www.google.com/maps/search/?api=1&query={lat},{lon}",
            "time": str(datetime.now())
        }

    except Exception as e:
        return {"ip": ip, "error": str(e)}


# ================= UI =================

class MARINTEL(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MARINTEL")
        self.setGeometry(100, 100, 1100, 600)
        self.setStyleSheet(self.dark_theme())

        self.results = []

        self.init_ui()

    def init_ui(self):
        layout = QHBoxLayout()

        # ===== Sidebar =====
        sidebar = QVBoxLayout()

        title = QLabel("MARINTEL ⚡")
        title.setStyleSheet("font-size:20px; font-weight:bold; color:#22c55e;")
        sidebar.addWidget(title)

        subtitle = QLabel("Cyber Intelligence Tool\nby Martech")
        subtitle.setStyleSheet("color:#94a3b8; font-size:10px;")
        sidebar.addWidget(subtitle)

        sidebar.addSpacing(20)

        self.input = QLineEdit()
        self.input.setPlaceholderText("Enter IP(s)...")
        sidebar.addWidget(self.input)

        scan_btn = QPushButton("Scan")
        scan_btn.clicked.connect(self.start_scan)
        sidebar.addWidget(scan_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear)
        sidebar.addWidget(clear_btn)

        sidebar.addStretch()

        layout.addLayout(sidebar, 1)

        # ===== Main Area =====
        main = QVBoxLayout()

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            ["IP", "Location", "ISP", "ASN", "Status", "Map"]
        )
        self.table.cellClicked.connect(self.open_map)

        main.addWidget(self.table)

        self.status = QLabel("Ready")
        self.status.setStyleSheet("color:#94a3b8;")
        main.addWidget(self.status)

        layout.addLayout(main, 3)

        self.setLayout(layout)

    # ================= ACTIONS =================

    def start_scan(self):
        ips = [ip.strip() for ip in self.input.text().split(",")]
        self.results = []
        self.table.setRowCount(0)

        self.status.setText("Scanning... ⚡")

        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(fetch_ip, ips))

        for r in results:
            if "error" in r:
                continue
            self.add_row(r)

        self.status.setText(f"Done. Scanned {len(results)} IP(s)")

    def add_row(self, r):
        row = self.table.rowCount()
        self.table.insertRow(row)

        self.table.setItem(row, 0, QTableWidgetItem(r["ip"]))
        self.table.setItem(row, 1, QTableWidgetItem(r["location"]))
        self.table.setItem(row, 2, QTableWidgetItem(r["isp"]))
        self.table.setItem(row, 3, QTableWidgetItem(r["asn"]))
        self.table.setItem(row, 4, QTableWidgetItem(r["status"]))
        self.table.setItem(row, 5, QTableWidgetItem("Open"))

        self.results.append(r)

    def open_map(self, row, col):
        if col == 5:
            webbrowser.open(self.results[row]["map"])

    def clear(self):
        self.table.setRowCount(0)
        self.results = []
        self.status.setText("Cleared")

    # ================= STYLE =================

    def dark_theme(self):
        return """
        QWidget {
            background-color: #0b1220;
            color: #e5e7eb;
            font-family: Consolas;
        }
        QLineEdit {
            background-color: #111827;
            border: 1px solid #374151;
            padding: 5px;
        }
        QPushButton {
            background-color: #1f2937;
            border: none;
            padding: 8px;
        }
        QPushButton:hover {
            background-color: #374151;
        }
        QTableWidget {
            background-color: #111827;
            gridline-color: #374151;
        }
        """


# ================= RUN =================

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MARINTEL()
    window.show()
    sys.exit(app.exec_())