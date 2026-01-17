#!/usr/bin/env python3
"""
Linux Autoruns 
"""

import os
import subprocess
from dataclasses import dataclass
import hashlib
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QLineEdit, QCheckBox, QLabel
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor

# ==================================================
# DATA MODEL
# ==================================================

@dataclass
class AutorunRecord:
    autorun_type: str
    category: str
    name: str
    exec_path: str
    trigger: str
    user: str
    source: str
    risk: str
    enabled: bool
    sha256: str
# ==================================================
# SAFE COMMAND EXECUTION
# ==================================================

def run_cmd(cmd):
    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        return res.stdout.strip()
    except Exception:
        return ""

# ==================================================
# RISK ENGINE
# ==================================================

def calculate_risk(r):
    score = 0
    if r.user == "root":
        score += 3
    if r.trigger in ("boot", "scheduled"):
        score += 3
    if r.exec_path.startswith("/tmp"):
        score += 5
    if not r.exec_path or r.exec_path == "MISSING":
        score += 4
    if r.sha256 == "N/A":
        score += 1

    if score >= 8:
        return "CRITICAL"
    if score >= 5:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    return "LOW"

#=================================================
#Add Hashing Function
#=================================================
def compute_sha256(path):
    """
    Compute SHA256 hash of a file safely.
    Returns hash string or 'N/A'
    """
    if not path or path in ("MISSING", ""):
        return "N/A"

    # If it's a command, not a file
    if " " in path or path.startswith(("bash", "sh", "python", "perl")):
        return "N/A"

    # Resolve absolute path if possible
    if not os.path.isabs(path):
        return "N/A"

    if not os.path.isfile(path):
        return "N/A"

    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return "N/A"

# ==================================================
# SYSTEMD SERVICES
# ==================================================



def scan_systemd():
    records = []
    out = run_cmd([
        "systemctl", "list-unit-files",
        "--type=service", "--state=enabled", "--no-legend"
    ])

    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue

        service = parts[0]
        if not service.endswith(".service"):
            continue

        exec_out = run_cmd([
            "systemctl", "show", service,
            "--property=ExecStart", "--no-page"
        ])

        exec_path = exec_out.replace("ExecStart=", "").strip() or "MISSING"

        rec = AutorunRecord(
            autorun_type="Service",
            category="systemd",
            name=service,
            exec_path=exec_path,
            trigger="boot",
            user="root",
            source="/etc/systemd/system",
            risk="TEMP",
            enabled=True,
            sha256=compute_sha256(exec_path)
        )
        rec.risk = calculate_risk(rec)
        records.append(rec)

    return records







# ==================================================
# SYSTEMD TIMERS
# ==================================================

def scan_systemd_timers():
    records = []
    out = run_cmd([
        "systemctl", "list-unit-files",
        "--type=timer", "--state=enabled", "--no-legend"
    ])

    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue

        timer = parts[0]
        if not timer.endswith(".timer"):
            continue

        service = timer.replace(".timer", ".service")
        exec_out = run_cmd([
            "systemctl", "show", service,
            "--property=ExecStart", "--no-page"
        ])

        exec_path = exec_out.replace("ExecStart=", "").strip() or "MISSING"

        rec = AutorunRecord(
            autorun_type="Scheduled Task",
            category="systemd-timer",
            name=timer,
            exec_path=exec_path,
            trigger="scheduled",
            user="root",
            source="/etc/systemd/system",
            risk="TEMP",
            enabled=True,
            sha256=compute_sha256(exec_path)
        )
        rec.risk = calculate_risk(rec)
        records.append(rec)

    return records

# ==================================================
# CRON
# ==================================================

def scan_cron():
    records = []
    paths = [
        "/etc/crontab",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly"
    ]

    for path in paths:
        if not os.path.exists(path):
            continue

        if os.path.isfile(path):
            with open(path, "r", errors="ignore") as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        rec = AutorunRecord(
                            autorun_type="Scheduled Task",
                            category="cron",
                            name=f"{os.path.basename(path)}:{i}",
                            exec_path=line,
                            trigger="scheduled",
                            user="root",
                            source=path,
                            risk="TEMP",
                            enabled=True,
                            sha256=compute_sha256(line)
                        )
                        rec.risk = calculate_risk(rec)
                        records.append(rec)
        else:
            for fname in os.listdir(path):
                rec = AutorunRecord(
                    autorun_type="Scheduled Task",
                    category="cron",
                    name=fname,
                    exec_path=os.path.join(path, fname),
                    trigger="scheduled",
                    user="root",
                    source=path,
                    risk="TEMP",
                    enabled=True,
                    sha256=compute_sha256(os.path.join(path, fname))
                )
                rec.risk = calculate_risk(rec)
                records.append(rec)

    return records

# ==================================================
# LOGIN SCRIPTS
# ==================================================

def scan_login():
    records = []
    home = os.path.expanduser("~")
    user = os.getenv("USER", "user")

    for fname in [".bashrc", ".profile", ".bash_profile"]:
        path = os.path.join(home, fname)
        if not os.path.exists(path):
            continue

        with open(path, "r", errors="ignore") as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith("#"):
                    rec = AutorunRecord(
                        autorun_type="Logon",
                        category="login",
                        name=f"{fname}:{i}",
                        exec_path=line,
                        trigger="login",
                        user=user,
                        source=path,
                        risk="TEMP",
                        enabled=True,
                        sha256=compute_sha256(line)
                    )
                    rec.risk = calculate_risk(rec)
                    records.append(rec)

    return records

# ==================================================
# DESKTOP AUTOSTART (ENABLE / DISABLE SUPPORTED)
# ==================================================

def scan_desktop_autostart():
    records = []
    dirs = [
        os.path.expanduser("~/.config/autostart"),
        "/etc/xdg/autostart"
    ]
    user = os.getenv("USER", "user")

    for base in dirs:
        if not os.path.isdir(base):
            continue

        for fname in os.listdir(base):
            if not fname.endswith(".desktop"):
                continue

            path = os.path.join(base, fname)
            name = fname
            exec_cmd = "MISSING"
            enabled = True

            with open(path, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("Name="):
                        name = line.split("=", 1)[1]
                    elif line.startswith("Exec="):
                        exec_cmd = line.split("=", 1)[1]
                    elif line.startswith("Hidden=true") or \
                         line.startswith("X-GNOME-Autostart-enabled=false"):
                        enabled = False

            rec = AutorunRecord(
                autorun_type="Desktop Autostart",
                category="desktop",
                name=name,
                exec_path=exec_cmd,
                trigger="login",
                user=user,
                source=path,
                risk="TEMP",
                enabled=enabled,
                sha256=compute_sha256(exec_cmd)

                
            )
            rec.risk = calculate_risk(rec)
            records.append(rec)

    return records

def toggle_desktop_autostart(record, enable):
    lines = []
    found = False

    with open(record.source, "r", errors="ignore") as f:
        for line in f:
            if line.startswith("Hidden="):
                lines.append(f"Hidden={'false' if enable else 'true'}\n")
                found = True
            else:
                lines.append(line)

    if not found:
        lines.append(f"\nHidden={'false' if enable else 'true'}\n")

    with open(record.source, "w") as f:
        f.writelines(lines)

# ==================================================
# ENGINE
# ==================================================

def scan_all():
    return (
        scan_systemd()
        + scan_systemd_timers()
        + scan_cron()
        + scan_login()
        + scan_desktop_autostart()
    )

# ==================================================
# GUI
# ==================================================

COLORS = {
    "LOW": QColor(200, 255, 200),
    "MEDIUM": QColor(255, 255, 180),
    "HIGH": QColor(255, 200, 150),
    "CRITICAL": QColor(255, 150, 150),
}




class AutorunWidget(QWidget):
    def __init__(self):
        super().__init__()

        self.records = []
        
        
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search...")
        self.search.textChanged.connect(self.filter)
        self.status = QLabel()
        self.table = QTableWidget()
        self.table.setColumnCount(10)
        self.table.setHorizontalHeaderLabels(
            ["Enabled", "Type", "Category", "Name",
             "Trigger", "User",  "Risk",  "Source", "Exec", "SHA256"]
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        layout = QVBoxLayout()
        layout.addWidget(self.search)
        layout.addWidget(self.table)
        layout.addWidget(self.status)
        self.setLayout(layout)
        
    
    
    def start_monitoring(self):
        QTimer.singleShot(0, self._do_scan)

    def _do_scan(self):
        self.records = scan_all()
        self.populate(self.records)



    
    def populate(self, records):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for r in records:
            row = self.table.rowCount()
            self.table.insertRow(row)
            cb = QCheckBox()
            cb.setChecked(r.enabled)
            if r.autorun_type == "Desktop Autostart":
                cb.stateChanged.connect(
                    lambda state, rec=r:
                    toggle_desktop_autostart(rec, state == Qt.Checked)
                )
            else:
                cb.setEnabled(False)
            self.table.setCellWidget(row, 0, cb)
            values = [
                r.autorun_type, r.category, r.name,
                r.trigger, r.user, r.risk, r.exec_path, r.source, r.sha256
            ]
            for col, val in enumerate(values, start=1):
                item = QTableWidgetItem(val)
                item.setFlags(item.flags() ^ Qt.ItemIsEditable)
                if col == 6:
                    item.setBackground(COLORS.get(val))
                self.table.setItem(row, col, item)
        self.table.setSortingEnabled(True)
        self.status.setText(f"Entries: {len(records)}")
    def filter(self, text):
        t = text.lower()
        self.populate([
            r for r in self.records
            if t in r.name.lower()
            or t in r.exec_path.lower()
            or t in r.category.lower()
        ])
