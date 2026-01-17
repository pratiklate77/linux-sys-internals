#!/usr/bin/env python3
"""
ProcList - Full Upgraded PyQt5 Process Explorer (single-file)

Features:
 - Process tree (parent -> child), threads as children
 - Background collection using QThread (no UI blocking)
 - Diff updates (add/remove/update only changed nodes)
 - Configurable auto-refresh interval (1-10s)
 - Expand All / Collapse All
 - Search filter (PID, name, user, command)
 - Recursive sorting
 - Color coding for states and high CPU
 - Right-click context menu (Kill, Terminate, Suspend, Resume, Change Priority)
 - Double-click opens Process Inspector with details, open files, connections, memory maps, threads, IO, env
 - New/terminated process flashes (visual highlight)
 - Per-process CPU%, Mem%, and IO counters shown in columns
"""

import sys
import time
import psutil
import traceback
from collections import deque, defaultdict
from datetime import datetime

from PyQt5.QtCore import (
    Qt, QTimer, QThread, pyqtSignal, QSize, QEvent, QPoint
)
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QTreeWidget, QTreeWidgetItem, QLineEdit, QSpinBox, QLabel,
    QPushButton, QMenu, QAction, QMessageBox, QDialog, QTabWidget,
    QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView, QInputDialog,
    QProgressBar
)
from PyQt5.QtGui import QColor, QBrush, QFont, QIcon, QPainter, QPixmap

# ---------- Constants ----------
CPU_HISTORY_LEN = 30  # history length for sparklines
NEW_FLASH_MS = 1200
TERMINATED_FLASH_MS = 1200
DEFAULT_INTERVAL = 1  # seconds (min 1)
MAX_INTERVAL = 10

# ---------- Utility helpers ----------

def safe_text(x):
    return str(x) if x is not None else ""

def format_bytes(n):
    if n is None:
        return ""
    try:
        n = float(n)
    except:
        return str(n)
    for unit in ["B","KB","MB","GB","TB"]:
        if n < 1024:
            return f"{n:3.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}PB"

# ---------- Worker thread that collects process info ----------

class ProcCollector(QThread):
    # emit mapping: pid -> info dict, and timestamp
    data_ready = pyqtSignal(object, float)

    def __init__(self, interval=DEFAULT_INTERVAL):
        super().__init__()
        self.interval = max(1, int(interval))
        self._running = True
        self._paused = False

    def run(self):
        # We will call psutil.process_iter repeatedly
        while self._running:
            try:
                proc_map = {}
                for p in psutil.process_iter(['pid', 'ppid', 'username', 'name',
                                              'cpu_percent', 'memory_percent',
                                              'cmdline', 'status', 'create_time',
                                              'num_threads', 'io_counters', 'nice']):
                    try:
                        info = p.info
                        # Normalize fields
                        info.setdefault('ppid', 0)
                        info.setdefault('cmdline', [])
                        info.setdefault('cpu_percent', 0.0)
                        info.setdefault('memory_percent', 0.0)
                        info['io'] = getattr(info.get('io_counters'), '._asdict', lambda: None)()
                        proc_map[info['pid']] = info
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                ts = time.time()
                self.data_ready.emit(proc_map, ts)
            except Exception:
                # emit empty on unexpected error
                traceback.print_exc()
                self.data_ready.emit({}, time.time())

            # sleep for interval seconds (allow thread to be stopped quickly)
            for _ in range(int(self.interval * 10)):
                if not self._running:
                    break
                time.sleep(0.1)

    def set_interval(self, sec):
        self.interval = max(1, min(MAX_INTERVAL, int(sec)))

    def stop(self):
        self._running = False

# ---------- Process Inspector dialog ----------

class ProcessInspector(QDialog):
    def __init__(self, pid, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Process Inspector - PID {pid}")
        self.resize(800, 600)
        self.pid = pid

        layout = QVBoxLayout()
        self.setLayout(layout)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # General tab
        self.general = QTextEdit()
        self.general.setReadOnly(True)
        self.tabs.addTab(self.general, "General")

        # Open files tab
        self.files_table = QTableWidget()
        self.files_table.setColumnCount(2)
        self.files_table.setHorizontalHeaderLabels(["Path", "FD"])
        self.files_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tabs.addTab(self.files_table, "Open Files")

        # Connections tab
        self.conn_table = QTableWidget()
        self.conn_table.setColumnCount(5)
        self.conn_table.setHorizontalHeaderLabels(["FD", "Family", "Type", "Local", "Remote"])
        self.conn_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.tabs.addTab(self.conn_table, "Connections")

        # Memory maps
        self.mmaps_table = QTableWidget()
        self.mmaps_table.setColumnCount(4)
        self.mmaps_table.setHorizontalHeaderLabels(["Path", "RSS", "Size", "Perms"])
        self.mmaps_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tabs.addTab(self.mmaps_table, "Memory Maps")

        # Threads
        self.threads_table = QTableWidget()
        self.threads_table.setColumnCount(3)
        self.threads_table.setHorizontalHeaderLabels(["TID", "User Time", "System Time"])
        self.tabs.addTab(self.threads_table, "Threads")

        # IO
        self.io_text = QTextEdit()
        self.io_text.setReadOnly(True)
        self.tabs.addTab(self.io_text, "I/O")

        # Env
        self.env_text = QTextEdit()
        self.env_text.setReadOnly(True)
        self.tabs.addTab(self.env_text, "Environment")

        self.populate()

    def populate(self):
        try:
            p = psutil.Process(self.pid)
        except Exception as e:
            self.general.setPlainText(f"Could not access process {self.pid}: {e}")
            return

        try:
            info = []
            info.append(f"PID: {p.pid}")
            info.append(f"Name: {safe_text(p.name())}")
            info.append(f"Executable: {safe_text(p.exe())}")
            info.append(f"Cmdline: {' '.join(p.cmdline())}")
            info.append(f"Username: {safe_text(p.username())}")
            info.append(f"Create time: {datetime.fromtimestamp(p.create_time()).isoformat() if p.create_time() else ''}")
            info.append(f"Status: {safe_text(p.status())}")
            info.append(f"Num threads: {p.num_threads()}")
            try:
                nice = p.nice()
                info.append(f"Nice: {nice}")
            except Exception:
                pass
            self.general.setPlainText("\n".join(info))
        except Exception:
            self.general.setPlainText("Error while reading general info:\n" + traceback.format_exc())

        # Open files
        try:
            files = p.open_files()
            self.files_table.setRowCount(len(files))
            for i, f in enumerate(files):
                self.files_table.setItem(i, 0, QTableWidgetItem(f.path))
                self.files_table.setItem(i, 1, QTableWidgetItem(str(f.fd)))
        except Exception:
            self.files_table.setRowCount(0)

        # Connections
        try:
            conns = p.connections(kind='inet')
            self.conn_table.setRowCount(len(conns))
            for i, c in enumerate(conns):
                self.conn_table.setItem(i, 0, QTableWidgetItem(str(c.fd)))
                self.conn_table.setItem(i, 1, QTableWidgetItem(str(c.family)))
                self.conn_table.setItem(i, 2, QTableWidgetItem(str(c.type)))
                self.conn_table.setItem(i, 3, QTableWidgetItem(f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""))
                self.conn_table.setItem(i, 4, QTableWidgetItem(f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""))
        except Exception:
            self.conn_table.setRowCount(0)

        # Memory maps
        try:
            maps = p.memory_maps()
            self.mmaps_table.setRowCount(len(maps))
            for i, m in enumerate(maps):
                self.mmaps_table.setItem(i, 0, QTableWidgetItem(safe_text(m.path)))
                self.mmaps_table.setItem(i, 1, QTableWidgetItem(format_bytes(getattr(m, 'rss', 0))))
                self.mmaps_table.setItem(i, 2, QTableWidgetItem(format_bytes(getattr(m, 'size', 0))))
                self.mmaps_table.setItem(i, 3, QTableWidgetItem(safe_text(getattr(m, 'perms', ''))))
        except Exception:
            self.mmaps_table.setRowCount(0)

        # Threads
        try:
            ths = p.threads()
            self.threads_table.setRowCount(len(ths))
            for i, t in enumerate(ths):
                self.threads_table.setItem(i, 0, QTableWidgetItem(str(t.id)))
                self.threads_table.setItem(i, 1, QTableWidgetItem(str(getattr(t, 'user_time', ''))))
                self.threads_table.setItem(i, 2, QTableWidgetItem(str(getattr(t, 'system_time', ''))))
        except Exception:
            self.threads_table.setRowCount(0)

        # IO
        try:
            io = p.io_counters()
            if io:
                text = "\n".join(f"{k}: {getattr(io, k)}" for k in io._fields)
                self.io_text.setPlainText(text)
            else:
                self.io_text.setPlainText("No IO info")
        except Exception:
            self.io_text.setPlainText("No IO info (permission denied or not available)")

        # Env
        try:
            env = p.environ()
            text = "\n".join(f"{k}={v}" for k, v in env.items())
            self.env_text.setPlainText(text)
        except Exception:
            self.env_text.setPlainText("Could not read environment (permission denied)")

# ---------- Main Application Window ----------

class ProcessWidget(QWidget):
    def __init__(self):
        super().__init__()
        
        
        main_layout = QVBoxLayout(self )

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Search:"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Filter by PID, name, user, command...")    
        self.search_edit.textChanged.connect(self.apply_filter)
        controls.addWidget(self.search_edit)
        
        controls.addWidget(QLabel("Refresh (s):"))
        self.refresh_spin = QSpinBox()
        self.refresh_spin.setRange(1, MAX_INTERVAL)
        self.refresh_spin.setValue(DEFAULT_INTERVAL)
        self.refresh_spin.valueChanged.connect(self.change_interval)
        controls.addWidget(self.refresh_spin)   

        self.expand_btn = QPushButton("Expand All")
        self.expand_btn.clicked.connect(self.expand_all)
        controls.addWidget(self.expand_btn) 

        self.collapse_btn = QPushButton("Collapse All")
        self.collapse_btn.clicked.connect(self.collapse_all)
        controls.addWidget(self.collapse_btn)

        self.sort_btn = QPushButton("Sort by CPU")
        self.sort_btn.setCheckable(True)
        self.sort_btn.toggled.connect(self.toggle_cpu_sort) 
        controls.addWidget(self.sort_btn)

        controls.addStretch()   
        main_layout.addLayout(controls)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(7)
        self.tree.setHeaderLabels(["PID", "User", "CPU %", "Mem %", "Name", "Command", "I/O"])
        self.tree.header().setSectionResizeMode(5, QHeaderView.Stretch)
        self.tree.setSortingEnabled(False)  # we handle sorting

        self.tree.itemDoubleClicked.connect(self.on_item_double_click)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.on_context_menu)
        main_layout.addWidget(self.tree)


        bottom = QHBoxLayout()
        self.status_label = QLabel("Ready")
        bottom.addWidget(self.status_label)
        bottom.addStretch()
        main_layout.addLayout(bottom)

        self.proc_nodes = {}  # pid -> QTreeWidgetItem
        self.pid_cpu_history = defaultdict(lambda: deque(maxlen=CPU_HISTORY_LEN))
        self._last_proc_map = {}
        self._last_timestamp = 0.0

        self.original_top_pids = []  # to restore original order
        self.cpu_sorted_pids = []    # current CPU-sorted order
        self.cpu_sort_active = False

        self._flash_timers = {}  # id(item) -> (item, deadline, color)   
        self._filter_text = ""

        # Start collector thread
        self.collector = ProcCollector(interval=self.refresh_spin.value())
        self.collector.data_ready.connect(self.on_data_ready)
        self.collector.start()

        # UI timer for flashing and sparklines
        self.ui_timer = QTimer(self)
        self.ui_timer.timeout.connect(self.on_ui_timer)
        self.ui_timer.start(500)  # 500 ms



        self.status_label = QLabel("Processes: 0 | Last update: N/A")
        main_layout.addWidget(self.status_label)        
        self.setLayout(main_layout) 
        self.resize(900, 600)
        
    # ---------- UI actions ----------
    def change_interval(self):
        val = self.refresh_spin.value()
        self.collector.set_interval(val)
        self.status_label.setText(f"Refresh interval set to {val}s")

    def expand_all(self):
        self.tree.expandAll()

    def collapse_all(self):
        self.tree.collapseAll()

    def sort_tree(self, col=2, order=Qt.DescendingOrder):
        # perform recursive sort: sort top-level by col, then sort children
        def sort_item(item):
            # sort children first
            child_count = item.childCount()
            for i in range(child_count):
                sort_item(item.child(i))
            # collect children and sort them
            if child_count > 0:
                children = [item.child(i) for i in range(child_count)]
                children.sort(key=lambda ch: self.sort_key(ch, col), reverse=(order==Qt.DescendingOrder))
                for idx, ch in enumerate(children):
                    item.removeChild(ch)
                for ch in children:
                    item.addChild(ch)

        # top-level
        top = [self.tree.topLevelItem(i) for i in range(self.tree.topLevelItemCount())]
        top.sort(key=lambda it: self.sort_key(it, col), reverse=(order==Qt.DescendingOrder))
        for t in top:
            self.tree.takeTopLevelItem(self.tree.indexOfTopLevelItem(t))
        for t in top:
            self.tree.addTopLevelItem(t)
            sort_item(t)
    
    # toggle handling for CPU sort

    def toggle_cpu_sort(self, enabled):
        self.cpu_sort_active = enabled
    
        if enabled:
            self.sort_by_cpu_and_save()
            self.sort_btn.setText("Original View")
        else:
            self.restore_original_order()
            self.sort_btn.setText("Sort by CPU")


    #Sort by CPU and save order
    def sort_by_cpu_and_save(self):
        # Save ORIGINAL order once
        if not self.original_top_pids:
            self.original_top_pids = [
                int(self.tree.topLevelItem(i).text(0))
                for i in range(self.tree.topLevelItemCount())
            ]

        # Now sort by CPU
        self.sort_tree(2, Qt.DescendingOrder)

        # Save CPU-sorted order
        self.cpu_sorted_pids.clear()
        for i in range(self.tree.topLevelItemCount()):
            self.cpu_sorted_pids.append(
                int(self.tree.topLevelItem(i).text(0))
            )




    
    def restore_original_order(self):
        if not self.original_top_pids:
            return

        current_items = [
            self.tree.topLevelItem(i)
            for i in range(self.tree.topLevelItemCount())
        ]

        pid_to_item = {
            int(item.text(0)): item
            for item in current_items
        }

        for target_index, pid in enumerate(self.original_top_pids):
            item = pid_to_item.get(pid)
            if not item:
                continue

            current_index = self.tree.indexOfTopLevelItem(item)
            if current_index != -1 and current_index != target_index:
                self.tree.takeTopLevelItem(current_index)
                self.tree.insertTopLevelItem(target_index, item)





    def sort_key(self, item, col):
        txt = item.text(col)
        # try numeric
        try:
            return float(txt)
        except:
            return txt.lower()

    # ---------- Context menu actions ----------
    def on_context_menu(self, pos: QPoint):
        item = self.tree.itemAt(pos)
        if item is None:
            return
        pid = int(item.text(0))
        menu = QMenu(self)

        kill_act = QAction("Kill (SIGKILL)", self)
        kill_act.triggered.connect(lambda: self.do_kill(pid, force=True))
        menu.addAction(kill_act)

        term_act = QAction("Terminate (SIGTERM)", self)
        term_act.triggered.connect(lambda: self.do_kill(pid, force=False))
        menu.addAction(term_act)

        suspend_act = QAction("Suspend", self)
        suspend_act.triggered.connect(lambda: self.do_suspend(pid))
        menu.addAction(suspend_act)

        resume_act = QAction("Resume", self)
        resume_act.triggered.connect(lambda: self.do_resume(pid))
        menu.addAction(resume_act)

        renice_act = QAction("Change Priority (nice)", self)
        renice_act.triggered.connect(lambda: self.do_renice(pid))
        menu.addAction(renice_act)

        inspect_act = QAction("Inspect (Open Inspector)", self)
        inspect_act.triggered.connect(lambda: self.open_inspector(pid))
        menu.addAction(inspect_act)

        menu.exec_(self.tree.viewport().mapToGlobal(pos))

    def do_kill(self, pid, force=False):
        try:
            p = psutil.Process(pid)
            if force:
                p.kill()
            else:
                p.terminate()
            QMessageBox.information(self, "Success", f"Signal sent to PID {pid}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not send signal to {pid}:\n{e}")

    def do_suspend(self, pid):
        try:
            p = psutil.Process(pid)
            p.suspend()
            QMessageBox.information(self, "Success", f"PID {pid} suspended")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not suspend {pid}:\n{e}")

    def do_resume(self, pid):
        try:
            p = psutil.Process(pid)
            p.resume()
            QMessageBox.information(self, "Success", f"PID {pid} resumed")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not resume {pid}:\n{e}")

    def do_renice(self, pid):
        try:
            p = psutil.Process(pid)
            current = p.nice()
            new, ok = QInputDialog.getInt(self, "Set Nice", f"Current nice={current}. Set new nice value (-20..19):", value=current, min=-20, max=19)
            if ok:
                p.nice(new)
                QMessageBox.information(self, "Success", f"Nice set to {new} for {pid}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not change priority of {pid}:\n{e}")

    def open_inspector(self, pid):
        dlg = ProcessInspector(pid, self)
        dlg.exec_()

    def on_item_double_click(self, item, col):
        try:
            pid = int(item.text(0))
            self.open_inspector(pid)
        except Exception:
            pass

    # ---------- Filtering ----------
    def apply_filter(self):
        txt = self.search_edit.text().strip().lower()
        self._filter_text = txt
        # walk all items and hide those that don't match
        def check_item(item):
            # match any column text
            full = " ".join(item.text(i) for i in range(self.tree.columnCount())).lower()
            visible = txt == "" or txt in full
            # check children
            child_count = item.childCount()
            child_visible = False
            for i in range(child_count):
                ch = item.child(i)
                if check_item(ch):
                    child_visible = True
            # item is visible if it or any child matches
            item.setHidden(not (visible or child_visible))
            return (visible or child_visible)
        for i in range(self.tree.topLevelItemCount()):
            check_item(self.tree.topLevelItem(i))

    # ---------- Collector callback: main diff update logic ----------
    def on_data_ready(self, proc_map, ts):
        try:
            # compute added, removed, updated
            old_pids = set(self._last_proc_map.keys())
            new_pids = set(proc_map.keys())

            added = new_pids - old_pids
            removed = old_pids - new_pids
            stayed = new_pids & old_pids

            # Update CPU history and mark changes
            for pid in new_pids:
                cpu = proc_map[pid].get('cpu_percent', 0.0) or 0.0
                self.pid_cpu_history[pid].append(cpu)

            # Remove nodes
            for pid in removed:
                node = self.proc_nodes.pop(pid, None)
                if node:
                    # flash terminated
                    self.flash_item(node, QColor(255, 160, 160), TERMINATED_FLASH_MS)
                    # remove after short delay to let user see flash:
                    # immediate removal is fine too - remove now
                    parent = node.parent()
                    if parent is None:
                        idx = self.tree.indexOfTopLevelItem(node)
                        if idx != -1:
                            self.tree.takeTopLevelItem(idx)
                    else:
                        parent.removeChild(node)

            # Add new nodes
            for pid in added:
                info = proc_map[pid]
                item = self.create_tree_item(info)
                self.proc_nodes[pid] = item
                self.place_item_in_tree(item, info)

                # flash new
                self.flash_item(item, QColor(200, 255, 200), NEW_FLASH_MS)

            # Update existing nodes
            for pid in stayed:
                info = proc_map[pid]
                node = self.proc_nodes.get(pid)
                if node:
                    self.update_tree_item(node, info)

            self._last_proc_map = proc_map
            self._last_timestamp = ts

            # apply search filter after update
            self.apply_filter()

            self.status_label.setText(f"Processes: {len(proc_map)} | Last update: {datetime.fromtimestamp(ts).strftime('%H:%M:%S')}")
        except Exception:
            traceback.print_exc()

    # ---------- Tree item creation / update ----------
    def create_tree_item(self, info):
        pid = info['pid']
        pid_str = str(pid)
        user = info.get('username') or ""
        cpu = f"{info.get('cpu_percent', 0.0):.1f}"
        mem = f"{info.get('memory_percent', 0.0):.1f}"
        name = info.get('name') or ""
        cmd = " ".join(info.get('cmdline') or [])
        io = info.get('io') or {}
        io_str = f"R:{format_bytes(io.get('read_bytes', 0))} W:{format_bytes(io.get('write_bytes', 0))}" if io else ""

        item = QTreeWidgetItem([pid_str, user, cpu, mem, name, cmd, io_str])
        # attach pid as data
        item.setData(0, Qt.UserRole, pid)
        # initial font
        f = item.font(0)
        f.setPointSize(10)
        for c in range(self.tree.columnCount()):
            item.setFont(c, f)
        return item

    def update_tree_item(self, item, info):
        # update text and colors
        pid = info['pid']
        user = info.get('username') or ""
        cpu = info.get('cpu_percent', 0.0) or 0.0
        mem = info.get('memory_percent', 0.0) or 0.0
        name = info.get('name') or ""
        cmd = " ".join(info.get('cmdline') or [])
        io = info.get('io') or {}
        io_str = f"R:{format_bytes(io.get('read_bytes', 0))} W:{format_bytes(io.get('write_bytes', 0))}" if io else ""

        item.setText(1, user)
        item.setText(2, f"{cpu:.1f}")
        item.setText(3, f"{mem:.1f}")
        item.setText(4, name)
        item.setText(5, cmd)
        item.setText(6, io_str)

        # color coding based on status and cpu
        status = info.get('status', '')
        self.apply_color_coding(item, status, cpu)

        # update sparkline icon in name column (small)
        pix = self.render_sparkline(self.pid_cpu_history[pid])
        if pix:
            item.setIcon(4, QIcon(pix))

    def place_item_in_tree(self, item, info):
        # place based on parent PID; if parent not present, top-level
        ppid = info.get('ppid', 0) or 0
        if ppid in self.proc_nodes:
            parent_item = self.proc_nodes[ppid]
            parent_item.addChild(item)
        else:
            # top-level
            self.tree.addTopLevelItem(item)

        # color coding
        self.apply_color_coding(item, info.get('status', ''), info.get('cpu_percent', 0.0) or 0.0)

    def apply_color_coding(self, item, status, cpu):
        # default background/foreground
        # color choices:
        # high cpu > 30% -> orange
        # zombie -> red
        # sleeping -> light yellow
        # normal -> default
        try:
            if status == psutil.STATUS_ZOMBIE:
                bg = QColor(255, 200, 200)
            elif cpu > 50.0:
                bg = QColor(255, 200, 150)
            elif cpu > 20.0:
                bg = QColor(255, 235, 200)
            elif status in (psutil.STATUS_SLEEPING,):
                bg = QColor(255, 250, 205)
            else:
                bg = None

            for c in range(self.tree.columnCount()):
                if bg:
                    item.setBackground(c, QBrush(bg))
                else:
                    item.setBackground(c, QBrush(Qt.transparent))
        except Exception:
            pass

    # ---------- Sparklines ----------
    def render_sparkline(self, data_deque):
        if not data_deque:
            return None
        h = 16
        w = 64
        pix = QPixmap(w, h)
        pix.fill(Qt.transparent)
        painter = QPainter(pix)
        painter.setRenderHint(QPainter.Antialiasing)
        # bounding
        vals = list(data_deque)
        if not vals:
            painter.end()
            return pix
        mx = max(max(vals), 1.0)
        mn = min(vals)
        scale = (h - 4) / (mx - mn) if mx != mn else 1.0
        # draw baseline
        pen = painter.pen()
        pen.setWidth(1)
        painter.setPen(pen)
        step = max(1, w / max(1, len(vals)-1))
        points = []
        for i, v in enumerate(vals):
            x = int(i * step)
            y = int(h - 2 - (v - mn) * scale)
            points.append((x, y))
        # draw polyline
        for i in range(1, len(points)):
            painter.drawLine(points[i-1][0], points[i-1][1], points[i][0], points[i][1])
        painter.end()
        return pix

    # ---------- Flashing items ----------
    def flash_item(self, item, color: QColor, ms: int):
        # set background for entire row and schedule a removal
        key = id(item)
        deadline = time.time() + ms / 1000.0
        # store (item, deadline, color) under id(item)
        self._flash_timers[key] = (item, deadline, color)

        # apply immediately
        for c in range(self.tree.columnCount()):
            item.setBackground(c, QBrush(color))

    def on_ui_timer(self):
        now = time.time()
        # remove expired flashes
        remove = []
        for key, (item, deadline, color) in list(self._flash_timers.items()):
            if now >= deadline:
                # restore to default (we'll reapply color coding from _last_proc_map if exists)
                pid = item.data(0, Qt.UserRole)
                info = self._last_proc_map.get(pid)
                if info:
                    self.apply_color_coding(item, info.get('status', ''), info.get('cpu_percent', 0.0) or 0.0)
                else:
                    # not found -> set transparent (process terminated)
                    for c in range(self.tree.columnCount()):
                        item.setBackground(c, QBrush(Qt.transparent))
                remove.append(key)
        for r in remove:
            self._flash_timers.pop(r, None)

        # update sparklines for visible items
        # (sparklines updated on data arrival already; here we can refresh timestamped UI if needed)
        pass

    def close(self, event):
        self.collector.stop()
        self.collector.wait(2000)
        event.accept()

    # ---------- Clean shutdown ----------
    def closeEvent(self, event):
        try:
            self.collector.stop()
            self.collector.wait(2000)
        except Exception:
            pass
        event.accept()

