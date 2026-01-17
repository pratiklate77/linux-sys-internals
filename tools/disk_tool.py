import os
import sys
import psutil
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel,
    QTableWidget, QTableWidgetItem,
    QTreeWidget, QTreeWidgetItem,
    QProgressBar, QSplitter, QComboBox, QTabWidget
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure


# ============================================================
# Utility
# ============================================================
def human_size(size):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return "PB"

# ============================================================
#
# ============================================================
def get_disks():
    disks = []
    for p in psutil.disk_partitions(all=False):
        try:
            u = psutil.disk_usage(p.mountpoint)
            disks.append({
                "device": p.device,
                "mount": p.mountpoint,
                "total": u.total,
                "used": u.used,
                "free": u.free
            })
        except PermissionError:
            continue
    return disks


def get_partitions():
    parts = []
    for p in psutil.disk_partitions(all=False):
        try:
            u = psutil.disk_usage(p.mountpoint)
            disk = p.device.rstrip("0123456789")
            parts.append({
                "disk": disk,
                "partition": p.device,
                "mount": p.mountpoint,
                "fs": p.fstype,
                "total": u.total,
                "used": u.used,
                "free": u.free
            })
        except PermissionError:
            continue
    return parts



# ============================================================
# Numeric table item (guaranteed correct sorting)
# ============================================================
class NumericItem(QTableWidgetItem):
    def __init__(self, text, value):
        super().__init__(text)
        self.value = value

    def __lt__(self, other):
        if isinstance(other, NumericItem):
            return self.value < other.value
        return super().__lt__(other)


# ============================================================
# Safe filesystem scanning
# ============================================================
def scan_directory(path):
    total = files = dirs = 0
    SKIP_DIRS = {"/proc", "/sys", "/dev", "/run"}
    if path in SKIP_DIRS:
        return 0, 0, 0
    try:
        if not os.path.isdir(path):
            return 0, 0, 0

        with os.scandir(path) as entries:
            for e in entries:
                try:
                    if e.is_symlink():
                        continue

                    if e.is_file(follow_symlinks=False):
                        total += e.stat().st_size
                        files += 1

                    elif e.is_dir(follow_symlinks=False):
                        s, f, d = scan_directory(e.path)
                        total += s
                        files += f
                        dirs += d + 1

                except (PermissionError, OSError):
                    continue

    except (PermissionError, OSError):
        return 0, 0, 0

    return total, files, dirs


def analyze_path(path):
    data = []
    with os.scandir(path) as entries:
        for e in entries:
            try:
                if e.is_symlink():
                    continue

                if e.is_dir(follow_symlinks=False):
                    s, f, d = scan_directory(e.path)
                    data.append({"name": e.name, "size": s, "path": e.path})

                elif e.is_file(follow_symlinks=False):
                    data.append({"name": e.name, "size": e.stat().st_size, "path": e.path})

            except (PermissionError, OSError):
                continue
    return data




def get_physical_disks():
    disks = []

    for d in os.listdir("/sys/block"):
        if d.startswith(("loop", "ram")):
            continue

        disk_path = f"/sys/block/{d}"

        try:
            with open(os.path.join(disk_path, "size")) as f:
                sectors = int(f.read().strip())
            size = sectors * 512

            model = "Unknown"
            model_path = os.path.join(disk_path, "device/model")
            if os.path.exists(model_path):
                with open(model_path) as f:
                    model = f.read().strip()

            disks.append({
                "name": d,
                "model": model,
                "size": size
            })

        except Exception:
            continue

    return disks


def get_partitions_for_disk(disk):
    parts = []
    base = f"/sys/block/{disk}"
    for p in os.listdir(base):
        if p.startswith(disk):
            dev = f"/dev/{p}"
            mount = ""
            for m in psutil.disk_partitions(all=False):
                if m.device == dev:
                    mount = m.mountpoint
            try:
                size_path = f"{base}/{p}/size"
                with open(size_path) as f:
                    size = int(f.read().strip()) * 512
            except:
                size = 0
            parts.append({
                "name": p,
                "size": size,
                "mount": mount
            })
    return parts





# ============================================================
# Worker Thread
# ============================================================
class ScanWorker(QThread):
    finished = pyqtSignal(list)

    def __init__(self, path):
        super().__init__()
        self.path = path

    def run(self):
        self.finished.emit(analyze_path(self.path))


# ============================================================
# Donut Pie Chart with interactions
# ============================================================
class PieChartCanvas(FigureCanvas):
    slice_clicked = pyqtSignal(str)
    legend_clicked = pyqtSignal(str)

    def __init__(self, parent=None):
        self.figure = Figure(figsize=(4, 4))
        self.ax = self.figure.add_subplot(111)
        super().__init__(self.figure)

        self.data_map = {}
        self.wedges = []
        self.figure.canvas.mpl_connect("pick_event", self.on_pick)

    def update_chart(self, data):
        self.ax.clear()
        self.data_map.clear()

        data = sorted([d for d in data if d["size"] > 0],
                      key=lambda x: x["size"], reverse=True)

        top = data[:5]
        rest = data[5:]

        labels = [d["name"] for d in top]
        sizes = [d["size"] for d in top]

        if rest:
            labels.append("Others")
            sizes.append(sum(d["size"] for d in rest))

        wedges, _, autotexts = self.ax.pie(
            sizes,
            startangle=140,
            autopct="%1.1f%%",
            wedgeprops=dict(width=0.4),
            pctdistance=0.8
        )

        for w, label in zip(wedges, labels):
            w.set_picker(True)
            self.data_map[w] = label

        self.ax.legend(
            wedges,
            labels,
            title="Folders",
            loc="center left",
            bbox_to_anchor=(1.05, 0.5)
        )

        self.ax.set_title("Disk Usage (Top 5)")
        self.wedges = wedges
        self.draw()

    def on_pick(self, event):
        wedge = event.artist
        label = self.data_map.get(wedge)
        if label:
            self.slice_clicked.emit(label)


    
    

   



# ============================================================
# Main App
# ============================================================
class DiskWidget(QWidget):
    def __init__(self):
        super().__init__()
        


        main_layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        self.disk_tab = QWidget()
        self.usage_tab = QWidget()

        self.tabs.addTab(self.disk_tab, "Physical Disks")
        self.tabs.addTab(self.usage_tab, "Disk Usage")
        usage_layout = QVBoxLayout(self.usage_tab)


        self.status = QLabel("Select a disk to analyze")
        usage_layout.addWidget(self.status)
        self.disk = QLabel("")
        usage_layout.addWidget(self.disk)

        disk_tab_layout = QVBoxLayout(self.disk_tab)

        self.disk_tree = QTreeWidget()
        self.disk_tree.setHeaderLabels(["Disk/Partition", "Details"])
        disk_tab_layout.addWidget(self.disk_tree)

    
    
        

      
        self.disk_combo = QComboBox()
        self.scan_btn = QPushButton("Scan Disk")
        self.load_disks()

        disk_select_layout = QHBoxLayout()
        disk_select_layout.addWidget(QLabel("Disk:"))
        disk_select_layout.addWidget(self.disk_combo)
        disk_select_layout.addWidget(self.scan_btn)

        usage_layout.addLayout(disk_select_layout)     

        
        
       
        
        

# ================= Partition Table (Ubuntu Disks style) =================
        self.partition_table = QTableWidget()
        self.partition_table.setColumnCount(7)
        self.partition_table.setHorizontalHeaderLabels([
            "Disk", "Partition", "Mount", "FS",
            "Total", "Used", "Free"
        ])
        self.partition_table.setSortingEnabled(True)
        disk_tab_layout.addWidget(self.partition_table)
        self.load_physical_disks()

      

    
    
        self.scan_btn.clicked.connect(self.scan_disk)


       

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        usage_layout.addWidget(self.progress)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Name", "Size"])
        usage_layout.addWidget(self.tree)

        self.table = QTableWidget()
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["Name", "Size"])
        self.table.setSortingEnabled(True)
        self.load_partitions()
        self.chart = PieChartCanvas()
        self.chart.slice_clicked.connect(self.on_chart_click)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self.table)
        splitter.addWidget(self.chart)
        splitter.setSizes([700, 500])
        usage_layout.addWidget(splitter)

        self.worker = None
        self.data = []


    



    def load_physical_disks(self):
        self.disk_tree.clear()

        for d in get_physical_disks():
            disk_item = QTreeWidgetItem([
                d["name"],
                f"{d['model']} | {human_size(d['size'])}"
            ])
            self.disk_tree.addTopLevelItem(disk_item)

            parts = get_partitions_for_disk(d["name"])
            for p in parts:
                text = f"{human_size(p['size'])}"
                if p["mount"]:
                    text += f" | mounted at {p['mount']}"

                part_item = QTreeWidgetItem([p["name"], text])
                disk_item.addChild(part_item)

            disk_item.setExpanded(True)



    
    def load_disks(self):
        self.disks = get_disks()
        self.disk_combo.clear()

        for d in self.disks:
            text = f"{d['device']} ({d['mount']}) - {human_size(d['total'])}"
            self.disk_combo.addItem(text, d)

    def scan_disk(self):
        index = self.disk_combo.currentIndex()
        if index < 0:
            return

        disk = self.disk_combo.itemData(index)
        mount_path = disk["mount"]

        self.status.setText(f"Scanning disk {disk['device']} ({mount_path})")
        self.disk.setText(
            f"Disk: {disk['device']} | Total: {human_size(disk['total'])} | "
            f"Used: {human_size(disk['used'])} | Free: {human_size(disk['free'])}   "
        )

        self.tree.clear()
        self.table.setRowCount(0)

        self.progress.show()

        self.worker = ScanWorker(mount_path)
        self.worker.finished.connect(self.on_finished)
        self.worker.start()

   
    def on_finished(self, data):
        self.data = data
        self.populate_table()
        self.populate_tree(self.worker.path)
        self.chart.update_chart(data)

        self.progress.hide()
        self.status.setText("Scan completed")

    def populate_table(self):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.data))

        for r, d in enumerate(self.data):
            self.table.setItem(r, 0, QTableWidgetItem(d["name"]))
            self.table.setItem(r, 1, NumericItem(human_size(d["size"]), d["size"]))

        self.table.setSortingEnabled(True)
        self.table.sortItems(1, Qt.DescendingOrder)

    def populate_tree(self, path, parent=None, depth=0):
        if depth > 5:
            return
        try:
            with os.scandir(path) as entries:
                for e in entries:
                    try:
                        if e.is_symlink():
                            continue

                        if e.is_file():
                            item = QTreeWidgetItem([e.name, human_size(e.stat().st_size)])
                        else:
                            s, _, _ = scan_directory(e.path)
                            item = QTreeWidgetItem([e.name, human_size(s)])

                        if parent:
                            parent.addChild(item)
                        else:
                            self.tree.addTopLevelItem(item)

                        if e.is_dir():
                            self.populate_tree(e.path, item, depth + 1)

                    except (PermissionError, OSError):
                        continue
        except (PermissionError, OSError):
            pass

    def on_chart_click(self, name):
        # Highlight table row
        for r in range(self.table.rowCount()):
            if self.table.item(r, 0).text() == name:
                self.table.selectRow(r)
                break

        # Expand tree
        it = self.tree.findItems(name, Qt.MatchRecursive, 0)
        if it:
            self.tree.setCurrentItem(it[0])
            self.tree.scrollToItem(it[0])
    def load_partitions(self):
        parts = get_partitions()
        self.partition_table.setRowCount(len(parts))

        for r, p in enumerate(parts):
            self.partition_table.setItem(r, 0, QTableWidgetItem(p["disk"]))
            self.partition_table.setItem(r, 1, QTableWidgetItem(p["partition"]))
            self.partition_table.setItem(r, 2, QTableWidgetItem(p["mount"]))
            self.partition_table.setItem(r, 3, QTableWidgetItem(p["fs"]))
            self.partition_table.setItem(r, 4, NumericItem(human_size(p["total"]), p["total"]))
            self.partition_table.setItem(r, 5, NumericItem(human_size(p["used"]), p["used"]))
            self.partition_table.setItem(r, 6, NumericItem(human_size(p["free"]), p["free"]))


