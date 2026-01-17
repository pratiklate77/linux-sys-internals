#!/usr/bin/env python3

import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QLabel

# -------------------------------
# Import tools (SAFE IMPORTS)
# -------------------------------

def safe_import(name, cls_name):
    try:
        module = __import__(name, fromlist=[cls_name])
        return getattr(module, cls_name)
    except Exception as e:
        print(f"[ERROR] Failed to load {name}: {e}")
        return None


DiskWidget = safe_import("tools.disk_tool", "DiskWidget")
ProcessWidget = safe_import("tools.process_tool", "ProcessWidget")
CpuWidget = safe_import("tools.cpu_tool", "CpuWidget")
AutorunWidget = safe_import("tools.autorun_tool", "AutorunWidget")
TcpWidget = safe_import("tools.tcp_tool", "TcpWidget")


# -------------------------------
# Main Window
# -------------------------------

class SysInternals(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Linux SysInternals")
        self.resize(1300, 800)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # ---- Add tabs SAFELY ----
        self.add_tab(DiskWidget, "Disk")
        self.add_tab(ProcessWidget, "Processes")
        self.add_tab(CpuWidget, "CPU")
        self.add_tab(AutorunWidget, "Autoruns")
        self.add_tab(TcpWidget, "TCP Connections")

        self.tabs.currentChanged.connect(self.on_tab_changed)

    def add_tab(self, WidgetClass, title):
        if WidgetClass is None:
            self.tabs.addTab(QLabel(f"{title} failed to load"), title)
            return

        try:
            widget = WidgetClass()
            self.tabs.addTab(widget, title)
        except Exception as e:
            print(f"[ERROR] Creating {title} tab failed:", e)
            self.tabs.addTab(QLabel(f"{title} crashed"), title)

    def on_tab_changed(self, index):
        active = self.tabs.widget(index)

        for i in range(self.tabs.count()):
            w = self.tabs.widget(i)
            if hasattr(w, "stop_monitoring"):
                w.stop_monitoring()

        if hasattr(active, "start_monitoring"):
            active.start_monitoring()


# -------------------------------
# Entry Point
# -------------------------------

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = SysInternals()
    win.show()
    sys.exit(app.exec_())

