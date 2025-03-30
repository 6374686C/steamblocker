import sys
import subprocess
import ctypes
import winreg
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton
from PyQt6.QtGui import QFont, QPainter, QRadialGradient, QColor, QBrush
from PyQt6.QtCore import Qt, QPointF, QThread, pyqtSignal

STEAM_IP_RANGES = [
    "162.254.192.0/20",
    "192.69.96.0/22",
    "205.196.6.0/24",
    "208.64.200.0/21",
    "208.78.164.0/22"
]

# We block all the little Steam gremlins, you never know
STEAM_EXECUTABLES_RELATIVE = [
    r"GameOverlayUI.exe",
    r"steam.exe",
    r"steamerrorreporter.exe",
    r"steamerrorreporter64.exe",
    r"steamsysinfo.exe",
    r"streaming_client.exe",
    r"uninstall.exe",
    r"WriteMiniDump.exe",
    r"bin\drivers.exe",
    r"bin\fossilize-replay.exe",
    r"bin\fossilize-replay64.exe",
    r"bin\gldriverquery.exe",
    r"bin\gldriverquery64.exe",
    r"bin\secure_desktop_capture.exe",
    r"bin\steamservice.exe",
    r"bin\steamxboxutil.exe",
    r"bin\steamxboxutil64.exe",
    r"bin\steam_monitor.exe",
    r"bin\vulkandriverquery.exe",
    r"bin\vulkandriverquery64.exe",
    r"bin\x64launcher.exe",
    r"bin\x86launcher.exe",
    r"bin\cef\cef.win7\steamwebhelper.exe",
    r"bin\cef\cef.win7x64\steamwebhelper.exe",
]

# Find where's Steam located
def get_steam_install_path():
    """Query the Windows registry for Steam's installation path."""
    try:
        for reg_path in [
            r"SOFTWARE\Valve\Steam",
            r"SOFTWARE\WOW6432Node\Valve\Steam"
        ]:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                install_path, _ = winreg.QueryValueEx(key, "InstallPath")
                winreg.CloseKey(key)
                return install_path
            except FileNotFoundError:
                continue
        return None
    except Exception as e:
        print(f"Error accessing registry: {e}")
        return None

class CheckFirewallThread(QThread):
    finished_signal = pyqtSignal(bool)

    def __init__(self, steam_executables, steam_ip_ranges):
        super().__init__()
        self.steam_executables = steam_executables
        self.steam_ip_ranges = steam_ip_ranges

    def rule_exists(self, rule_name):
        result = subprocess.run(
            f'netsh advfirewall firewall show rule name="{rule_name}"',
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return result.returncode == 0

    def run(self):
        # Check executable rules
        exe_rules_exist = all(
            self.rule_exists(f"SteamBlock_Exe_Out_{exe}") and 
            self.rule_exists(f"SteamBlock_Exe_In_{exe}")
            for exe in self.steam_executables
        )

        # Check IP rules
        ip_rules_exist = all(
            self.rule_exists(f"SteamBlock_IP_Out_{ip}") and 
            self.rule_exists(f"SteamBlock_IP_In_{ip}")
            for ip in self.steam_ip_ranges
        )

        self.finished_signal.emit(exe_rules_exist and ip_rules_exist)

class WorkerThread(QThread):
    finished_signal = pyqtSignal(str)

    def __init__(self, task, finished_text, parent=None):
        super().__init__(parent)
        self.task = task
        self.finished_text = finished_text

    def run(self):
        self.task()
        self.finished_signal.emit(self.finished_text)

class SteamBlockerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Steam Blocker")
        self.setFixedSize(400, 300)
        self.initUI()
        self.check_firewall_status()

    def initUI(self):
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Big fatass title
        self.title_label = QLabel("STEAM BLOCKER")
        title_font = QFont("Calibri", 28, QFont.Weight.Bold)
        self.title_label.setFont(title_font)
        self.title_label.setStyleSheet("color: white;")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.title_label)
        layout.addSpacing(20)

        # Red "DO NOT PRESS" Button (just kidding, press it)
        self.block_button = QPushButton("Block")
        block_font = QFont("Calibri", 14, QFont.Weight.Bold)
        self.block_button.setFont(block_font)
        self.block_button.setStyleSheet(
            "QPushButton { background-color: #d35a74; color: white; padding: 10px; border-radius: 10px; }"
            "QPushButton:hover { background-color: #e74c3c; }"
        )
        self.block_button.clicked.connect(self.on_block)
        layout.addWidget(self.block_button)

        # Unblocka
        self.unblock_button = QPushButton("Unblock")
        unblock_font = QFont("Calibri", 14, QFont.Weight.Bold)
        self.unblock_button.setFont(unblock_font)
        self.unblock_button.setStyleSheet(
            "QPushButton { background-color: #0093d7; color: white; padding: 10px; border-radius: 10px; }"
            "QPushButton:hover { background-color: #26abe9; }"
        )
        self.unblock_button.clicked.connect(self.on_unblock)
        layout.addWidget(self.unblock_button)

        layout.addSpacing(20)

        # Status label to tell us what's going on
        self.status_label = QLabel("Status: Ready")
        status_font = QFont("Calibri", 12, QFont.Weight.Bold)
        self.status_label.setFont(status_font)
        self.status_label.setStyleSheet("color: #f1f1f1;")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def is_admin(self):
        """Check if we got the power"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def paintEvent(self, event):
        painter = QPainter(self)
        rect = self.rect()
        center = QPointF(rect.center())
        gradient = QRadialGradient(center, rect.width() * 0.75, center)
        gradient.setColorAt(0, QColor("#182d4a"))
        gradient.setColorAt(1, QColor("#1d212a"))
        painter.fillRect(rect, QBrush(gradient))

    def check_firewall_status(self):
        self.status_label.setText("Status: Checking Firewall, wait...")
        self.status_label.setStyleSheet("color: #f1f1f1;")
        self.block_button.setEnabled(False)
        self.unblock_button.setEnabled(False)

        if not self.is_admin():
            self.status_label.setText("Needs Admin Rights!")
            self.status_label.setStyleSheet("color: red;")
            return

        self.steam_install_path = get_steam_install_path()
        if self.steam_install_path is None:
            self.status_label.setText("Steam Not Installed")
            self.status_label.setStyleSheet("color: red;")
            return

        self.STEAM_EXECUTABLES = [f"{self.steam_install_path}\\{rel_path}" for rel_path in STEAM_EXECUTABLES_RELATIVE]
        self.STEAM_IP_RANGES = STEAM_IP_RANGES

        self.check_thread = CheckFirewallThread(self.STEAM_EXECUTABLES, self.STEAM_IP_RANGES)
        self.check_thread.finished_signal.connect(self.handle_firewall_check_result)
        self.check_thread.start()

    def handle_firewall_check_result(self, is_blocked):
        if is_blocked:
            self.status_label.setText("Status: Steam Blocked")
            self.status_label.setStyleSheet("color: #d35a74;")
            self.block_button.setEnabled(False)
            self.unblock_button.setEnabled(True)
        else:
            self.status_label.setText("Status: Not Blocked")
            self.status_label.setStyleSheet("color: #49d383;")  # Green color
            self.block_button.setEnabled(True)
            self.unblock_button.setEnabled(False)  # Disable unblock if not blocked

    def run_command(self, command):
        try:
            subprocess.run(command, shell=True, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except subprocess.CalledProcessError as e:
            print(f"Error running command: {command}")
            print(e.stderr.strip())

    def add_exe_rule(self, exe_path):
        rule_name_out = f"SteamBlock_Exe_Out_{exe_path}"
        rule_name_in = f"SteamBlock_Exe_In_{exe_path}"
        cmd_out = f'netsh advfirewall firewall add rule name="{rule_name_out}" dir=out program="{exe_path}" action=block'
        cmd_in = f'netsh advfirewall firewall add rule name="{rule_name_in}" dir=in program="{exe_path}" action=block'
        self.run_command(cmd_out)
        self.run_command(cmd_in)

    def delete_exe_rule(self, exe_path):
        rule_name_out = f"SteamBlock_Exe_Out_{exe_path}"
        rule_name_in = f"SteamBlock_Exe_In_{exe_path}"
        cmd_out = f'netsh advfirewall firewall delete rule name="{rule_name_out}"'
        cmd_in = f'netsh advfirewall firewall delete rule name="{rule_name_in}"'
        self.run_command(cmd_out)
        self.run_command(cmd_in)

    def add_ip_rule(self, ip_range):
        rule_name_out = f"SteamBlock_IP_Out_{ip_range}"
        rule_name_in = f"SteamBlock_IP_In_{ip_range}"
        cmd_out = f'netsh advfirewall firewall add rule name="{rule_name_out}" dir=out remoteip={ip_range} action=block'
        cmd_in = f'netsh advfirewall firewall add rule name="{rule_name_in}" dir=in remoteip={ip_range} action=block'
        self.run_command(cmd_out)
        self.run_command(cmd_in)

    def delete_ip_rule(self, ip_range):
        rule_name_out = f"SteamBlock_IP_Out_{ip_range}"
        rule_name_in = f"SteamBlock_IP_In_{ip_range}"
        cmd_out = f'netsh advfirewall firewall delete rule name="{rule_name_out}"'
        cmd_in = f'netsh advfirewall firewall delete rule name="{rule_name_in}"'
        self.run_command(cmd_out)
        self.run_command(cmd_in)

    def block_steam(self):
        print("Blocking Steam executables...")
        for exe in self.STEAM_EXECUTABLES:
            self.add_exe_rule(exe)
        print("Blocking Steam IP ranges...")
        for ip in self.STEAM_IP_RANGES:
            self.add_ip_rule(ip)
        print("Steam should now be blocked.")

    def unblock_steam(self):
        print("Unblocking Steam executables...")
        for exe in self.STEAM_EXECUTABLES:
            self.delete_exe_rule(exe)
        print("Unblocking Steam IP ranges...")
        for ip in self.STEAM_IP_RANGES:
            self.delete_ip_rule(ip)
        print("Steam should now be unblocked.")

    def on_block(self):
        self.status_label.setText("Status: Blocking, wait...")
        self.status_label.setStyleSheet("color: #f1f1f1;")
        self.block_button.setEnabled(False)
        self.unblock_button.setEnabled(False)
        self.worker = WorkerThread(self.block_steam, "Steam Blocked")
        self.worker.finished_signal.connect(self.on_task_finished_block)
        self.worker.start()

    def on_task_finished_block(self, status_text):
        self.status_label.setText(f"Status: {status_text}")
        self.status_label.setStyleSheet("color: #d35a74;")
        self.block_button.setEnabled(False)
        self.unblock_button.setEnabled(True)

    def on_unblock(self):
        self.status_label.setText("Status: Unblocking, wait...")
        self.status_label.setStyleSheet("color: #f1f1f1;")
        self.block_button.setEnabled(False)
        self.unblock_button.setEnabled(False)
        self.worker = WorkerThread(self.unblock_steam, "Steam Unblocked")
        self.worker.finished_signal.connect(self.on_task_finished_unblock)
        self.worker.start()

    def on_task_finished_unblock(self, status_text):
        self.status_label.setText(f"Status: {status_text}")
        self.status_label.setStyleSheet("color: #49d383;")
        self.block_button.setEnabled(True)
        self.unblock_button.setEnabled(False)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SteamBlockerGUI()
    window.show()
    sys.exit(app.exec())