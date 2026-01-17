#!/usr/bin/env python3
"""
tcpview_fixed.py

More robust TCPView-style network connections viewer (PyQt5 + psutil).
- Safe handling of missing fields
- PID -> process info caching
- Fallback to 'ss' on Linux when psutil returns nothing (optional)
- Status bar, filter, adjustable refresh
"""

import sys
import os
import time
import subprocess
import traceback
from collections import defaultdict
import socket

import psutil
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import (
     QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QLineEdit, QLabel, QSpinBox,
    QPushButton, QMessageBox
)
from PyQt5.QtGui import QColor, QBrush

# color mapping for states
STATE_COLORS = {
    'ESTABLISHED': QColor(200, 255, 200),
    'LISTEN': QColor(200, 200, 255),
    'LISTENING': QColor(200, 200, 255),
    'SYN_SENT': QColor(255, 255, 150),
    'SYN_RECV': QColor(255, 255, 200),
    'FIN_WAIT1': QColor(255, 220, 180),
    'FIN_WAIT2': QColor(255, 200, 150),
    'TIME_WAIT': QColor(255, 180, 180),
    'CLOSE_WAIT': QColor(255, 180, 255),
    'CLOSED': QColor(220, 220, 220),
}

# ---------- helpers ----------
def format_addr(addr):
    """addr may be a psutil sockaddr-like object, tuple, or None."""
    if not addr:
        return "", ""
    # Common psutil behavior: an address object with .ip/.port or a tuple (ip, port)
    ip = ""
    port = ""
    try:
        if hasattr(addr, "ip"):
            ip = str(addr.ip)
        elif isinstance(addr, (tuple, list)) and len(addr) >= 1:
            ip = str(addr[0])
        if hasattr(addr, "port"):
            port = str(addr.port)
        elif isinstance(addr, (tuple, list)) and len(addr) >= 2:
            port = str(addr[1])
    except Exception:
        try:
            ip = str(addr)
        except Exception:
            ip = ""
    return ip, port

def is_root():
    if os.name == "nt":
        # Windows admin detection would be different; return False here
        return False
    try:
        return os.geteuid() == 0
    except Exception:
        return False

# lightweight process info cache to avoid repeated psutil.Process calls
class ProcInfoCache:
    def __init__(self, ttl=5.0):
        self.ttl = ttl
        self._cache = {}  # pid -> (name, user, exe, ts)

    def get(self, pid):
        # pid can be None or 0
        if not pid:
            return ("", "", "")
        rec = self._cache.get(pid)
        now = time.time()
        if rec and (now - rec[3]) < self.ttl:
            return (rec[0], rec[1], rec[2])
        # fetch fresh
        try:
            p = psutil.Process(pid)
            name = safe_str(p.name())
            user = safe_str(p.username())
            exe = safe_str(p.exe())
            self._cache[pid] = (name, user, exe, now)
            return (name, user, exe)
        except Exception:
            # store a short-lived negative to avoid thrashing
            self._cache[pid] = ("", "", "", now)
            return ("", "", "")

def safe_str(x):
    try:
        return str(x)
    except Exception:
        return ""

# Fallback parser: use `ss -tunap` (Linux) if psutil returns empty or fails.
def ss_parse_connections():
    """Return list of dicts similar to psutil.net_connections entries:
    { 'family':'inet', 'type': 'tcp'/'udp', 'laddr':(ip,port), 'raddr':(ip,port) or None, 'status':str, 'pid':int or None }
    Requires `ss` install and usually root for PID info.
    """
    try:
        out = subprocess.check_output(["ss", "-tunap"], stderr=subprocess.STDOUT, text=True)
    except Exception:
        return []
    lines = out.splitlines()
    results = []
    # skip header lines until a line starting with "Netid" or similar
    for line in lines:
        line = line.strip()
        if not line or line.startswith("Netid") or line.startswith("State"):
            continue
        # example ss output lines vary; we'll do a permissive parse
        # Format often: tcp   ESTAB 0      0     10.0.0.1:53776   93.184.216.34:80    users:(("curl",pid,fd))
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        status = ""
        laddr_str = ""
        raddr_str = ""
        pid = None
        # find addr tokens (they often are the last 2 or 3 columns)
        # heuristic: last two tokens with ":" are raddr and laddr
        # search for token containing ':' that looks like ip:port
        addr_tokens = [p for p in parts if ":" in p and not p.startswith("users:")]
        if len(addr_tokens) >= 2:
            laddr_str = addr_tokens[-2]
            raddr_str = addr_tokens[-1]
        # status often in parts[1]
        if len(parts) >= 2:
            status = parts[1]
        # try to extract pid from "users:((" substring
        if "users:(" in line:
            try:
                left = line.split("users:(", 1)[1]
                # look for pid,N
                if "pid=" in left:
                    # newer ss may show pid=
                    pid_token = left.split("pid=", 1)[1].split(",", 1)[0]
                    pid = int(pid_token)
                else:
                    # older shows (\"prog\",pid,fd)
                    # find digits sequences
                    import re
                    m = re.search(r",(\d+),\d+\)\)", left)
                    if m:
                        pid = int(m.group(1))
            except Exception:
                pid = None
        # convert laddr/raddr to tuple
        def split_addr(a):
            if a == "*" or a == "*:*":
                return ("", "")
            if "[" in a and "]" in a:
                # IPv6 with brackets [::1]:port
                try:
                    host, port = a.rsplit(":", 1)
                    host = host.strip("[]")
                    return (host, port)
                except Exception:
                    return (a, "")
            try:
                host, port = a.rsplit(":", 1)
                return (host, port)
            except Exception:
                return (a, "")
        laddr = split_addr(laddr_str) if laddr_str else ("", "")
        raddr = split_addr(raddr_str) if raddr_str else ("", "")
        results.append({
            "family": "inet",
            "type": proto.lower(),
            "laddr": laddr,
            "raddr": raddr if raddr != ("", "") else None,
            "status": status,
            "pid": pid
        })
    return results

def ss_parse_unix():
    results = []
    try:
        out = subprocess.check_output(
            ["ss", "-xap"],
            stderr=subprocess.DEVNULL,
            text=True
        )
    except Exception:
        return results

    for line in out.splitlines():
        if "users:(" not in line:
            continue

        # Example:
        # u_str LISTEN 0 128 /var/run/postgresql/.s.PGSQL.5432 users:(("postgres",pid=6646,fd=5))
        parts = line.split()
        path = next((p for p in parts if p.startswith("/")), "")
        pid = None

        if "pid=" in line:
            try:
                pid = int(line.split("pid=", 1)[1].split(",", 1)[0])
            except Exception:
                pid = None

        results.append({
            "proto": "UNIX",
            "path": path,
            "pid": pid
        })

    return results






class TcpWidget(QWidget):
    def __init__(self):
        super().__init__()
        
        v = QVBoxLayout()
        
        ctr = QHBoxLayout()
        ctr.addWidget(QLabel("Filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("type to filter by IP, PID, process, state...")
        self.filter_edit.textChanged.connect(self.apply_filter)
        ctr.addWidget(self.filter_edit)

        ctr.addWidget(QLabel("Refresh (ms):"))
        self.spin = QSpinBox()
        self.spin.setRange(200, 10000)
        self.spin.setValue(1000)
        self.spin.valueChanged.connect(self.on_interval_change)
        ctr.addWidget(self.spin)

        self.btn_refresh = QPushButton("Refresh Now")
        self.btn_refresh.clicked.connect(self.one_shot_refresh)
        ctr.addWidget(self.btn_refresh)

        self.status_label = QLabel("")
        ctr.addWidget(self.status_label)
        ctr.addStretch()
        v.addLayout(ctr)

        
        self.table = QTableWidget(0, 10)
        self.table.setHorizontalHeaderLabels([
            "Proto", "Local Address", "Local Port",
            "Remote Address", "Remote Port", "State",
            "PID", "Process", "User", "Executable"
        ])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSortingEnabled(True)
        v.addWidget(self.table)

        
        self.proc_cache = ProcInfoCache(ttl=2.0)
        self.last_snapshot_time = 0.0
        self.use_ss_fallback = (os.name != "nt")  
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)

        self.setLayout(v)
          
       

    def on_interval_change(self, val):
        self.timer.setInterval(val)

    def one_shot_refresh(self):
        self.refresh()

    def refresh(self):
        try:
            try:
                conns = psutil.net_connections(kind="inet")
            except Exception:
                conns = []

            unix_socks = ss_parse_unix()

            self.table.setSortingEnabled(False)   
            self.table.setRowCount(0)

            self._populate_table(conns)
            self._populate_unix(unix_socks)

            self.table.setSortingEnabled(True)    
            self.apply_filter()
            self.last_snapshot_time = time.time()

        except Exception:
            traceback.print_exc()
            self.status_label.setText("Refresh error (see console)")



    def _populate_table(self, conns):

        for c in conns:
            row = self.table.rowCount()
            self.table.insertRow(row)

            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            state = getattr(c, "status", "") if proto == "TCP" else ""

            l_ip, l_port = format_addr(c.laddr) if c.laddr else ("", "")
            r_ip, r_port = format_addr(c.raddr) if c.raddr else ("", "")

            pid = getattr(c, "pid", None) or 0
            name, user, exe = self.proc_cache.get(pid)

            cells = [
                proto,
                l_ip,
                l_port,
                r_ip,
                r_port,
                state,
                str(pid) if pid else "",
                name,
                user,
                exe
            ]

            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if col == 5 and state and state.upper() in STATE_COLORS:
                    item.setBackground(QBrush(STATE_COLORS[state.upper()]))
                if col in (2, 4, 6):
                    item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row, col, item)


    def _populate_unix(self, unix_socks):
        for u in unix_socks:
            row = self.table.rowCount()
            self.table.insertRow(row)

            pid = u["pid"] or 0
            name, user, exe = self.proc_cache.get(pid)

            cells = [
                "UNIX",
                u["path"],
                "",
                "",
                "",
                "",
                str(pid),
                name or "",
                user or "",
                exe or ""
            ]

            for col, text in enumerate(cells):
                self.table.setItem(row, col, QTableWidgetItem(text))





    def apply_filter(self):
        txt = self.filter_edit.text().strip().lower()
        # if empty filter, show all
        if not txt:
            for r in range(self.table.rowCount()):
                self.table.setRowHidden(r, False)
            return

        shown = 0
        for r in range(self.table.rowCount()):
            row_text = []
            for c in range(self.table.columnCount()):
                it = self.table.item(r, c)
                if it:
                    row_text.append(it.text().lower())
            joined = " ".join(row_text)
            show = (txt in joined)
            self.table.setRowHidden(r, not show)
            if show:
                shown += 1
        self.status_label.setText(f"Connections: {self.table.rowCount()} (visible {shown})")

        def start_monitoring(self):
            if not self.timer.isActive():
                self.timer.start(self.spin.value())
                self.refresh()


        def stop_monitoring(self):
            if self.timer.isActive():
                self.timer.stop()

   