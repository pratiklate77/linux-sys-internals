import sys
import time
from collections import deque
from datetime import datetime

import psutil
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QProgressBar, QGroupBox, QGridLayout, QSizePolicy, QSpacerItem
)
import pyqtgraph as pg


UPDATE_MS = 800           # UI update interval  milliseconds
HISTORY_LEN = 120        # points to keep in history (UPDATE_MS * HISTORY_LEN ~ time window)
GRAPH_BG = None          # None => use default pyqtgraph background, or set like "#101010"


class CpuBackend:
    def __init__(self, history_len=HISTORY_LEN):
        self.history_len = history_len
        self.overall_history = deque(maxlen=history_len)   # store floats 0..100
        self.time_history = deque(maxlen=history_len)      # timestamps
        # initialize psutil counters so first cpu_percent() returns instant values
        psutil.cpu_percent(interval=None)
        psutil.cpu_percent(percpu=True)

    def poll(self):
        per_core = psutil.cpu_percent(interval=None, percpu=True)
        overall = psutil.cpu_percent(interval=None)
        freq = psutil.cpu_freq()  # may be None on some systems
        load = None
        try:
            load = psutil.getloadavg()  # (1m,5m,15m)
        except Exception:
            load = (0.0, 0.0, 0.0)

        stats = psutil.cpu_stats()  # interrupts, ctx_switches, etc.

        now = time.time()
        self.time_history.append(now)
        self.overall_history.append(overall)

        return {
            "timestamp": now,
            "overall": overall,
            "per_core": per_core,
            "freq": {
                "current": freq.current if freq else 0.0,
                "min": freq.min if freq else 0.0,
                "max": freq.max if freq else 0.0,
            },
            "load_avg": load,
            "interrupts": getattr(stats, "interrupts", 0),
            "ctx_switches": getattr(stats, "ctx_switches", 0),
            "history": list(self.overall_history),
            "time_history": list(self.time_history),
        }


class CpuWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.backend = CpuBackend(HISTORY_LEN)
        self.init_ui()
        self.init_timer()

    def init_ui(self):
        
        main = QVBoxLayout()
        self.setLayout(main)

        top_h = QHBoxLayout()
        main.addLayout(top_h)

        self.overall_label = QLabel("CPU: 0.0%")
        self.overall_label.setStyleSheet("font-weight: bold; font-size: 18px;")
        top_h.addWidget(self.overall_label)

        top_h.addItem(QSpacerItem(40, 10, QSizePolicy.Expanding, QSizePolicy.Minimum))

        stats_box = QGroupBox("Stats")
        stats_layout = QHBoxLayout()
        stats_box.setLayout(stats_layout)
        self.load_label = QLabel("Load: -")
        self.freq_label = QLabel("Freq: -")
        self.int_label = QLabel("Interrupts: -")
        self.ctx_label = QLabel("Ctx Switches: -")

        for w in (self.load_label, self.freq_label, self.int_label, self.ctx_label):
            w.setStyleSheet("font-size: 13px;")
            stats_layout.addWidget(w)

        top_h.addWidget(stats_box)

        graph_box = QGroupBox("Overall CPU Usage (history)")
        graph_layout = QVBoxLayout()
        graph_box.setLayout(graph_layout)
        main.addWidget(graph_box, stretch=1)

        if GRAPH_BG:
            pg.setConfigOption(background = GRAPH_BG,  foreground = 'w')
        else:
            pg.setConfigOptions()

        self.plot_widget = pg.PlotWidget(title="CPU %")
        self.plot_widget.setYRange(0, 100, padding=0.05)
        self.plot_widget.showGrid(x=True, y=True, alpha=0.7)
        self.plot_widget.setMouseEnabled(x=False, y=False)
        self.plot_curve = self.plot_widget.plot(pen=pg.mkPen(width=2))
        graph_layout.addWidget(self.plot_widget)

        cores_box = QGroupBox("Per-core Usage")
        cores_layout = QGridLayout()
        cores_box.setLayout(cores_layout)
        main.addWidget(cores_box)

        self.n_cores = psutil.cpu_count(logical=True) or 1
        self.core_bars = []
        cols = 2
        for i in range(self.n_cores):
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setFormat(f"Core {i}: %p%")
            bar.setTextVisible(True)
            bar.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            self.core_bars.append(bar)
            r = i // cols
            c = i % cols
            cores_layout.addWidget(bar, r, c)

        self.timestamp_label = QLabel("")
        self.timestamp_label.setStyleSheet("font-size: 12px; color: gray;")
        main.addWidget(self.timestamp_label, alignment=Qt.AlignRight)

    def init_timer(self):
        self.timer = QTimer(self)
        self.timer.setInterval(UPDATE_MS)
        self.timer.timeout.connect(self.on_timer)
        

    def on_timer(self):
        if not self.isVisible():
            return
        data = self.backend.poll()
        self.update_ui(data)

    def update_ui(self, data):
        overall = data["overall"]
        self.overall_label.setText(f"CPU: {overall:.1f}%")

        per_core = data["per_core"]
        if len(per_core) != len(self.core_bars):
            for b in self.core_bars:
                b.setParent(None)
            self.core_bars = []
            n = len(per_core)
            cols = 2
            for i in range(n):
                b = QProgressBar()
                b.setRange(0, 100)
                b.setFormat(f"Core {i}: %p%")
                self.core_bars.append(b)
                self.layout().itemAt(2).widget().layout().addWidget(b)

        for i, val in enumerate(per_core):
            if i < len(self.core_bars):
                self.core_bars[i].setValue(int(val))

        la = data.get("load_avg", (0.0, 0.0, 0.0))
        freq = data.get("freq", {})
        self.load_label.setText(f"Load: {la[0]:.2f}, {la[1]:.2f}, {la[2]:.2f}")
        self.freq_label.setText(f"Freq: {freq.get('current',0):.0f} MHz (min {freq.get('min',0):.0f}, max {freq.get('max',0):.0f})")
        self.int_label.setText(f"Interrupts: {data.get('interrupts',0)}")
        self.ctx_label.setText(f"Ctx Switches: {data.get('ctx_switches',0)}")

        history = data.get("history", [])
        if history:
            self.plot_curve.setData(history)

        ts = datetime.fromtimestamp(data.get("timestamp", time.time()))
        self.timestamp_label.setText(f"Last: {ts.strftime('%Y-%m-%d %H:%M:%S')}")


    def start_monitoring(self):
        if not self.timer.isActive():
            self.timer.start()

    def stop_monitoring(self):
        if self.timer.isActive():
            self.timer.stop()


