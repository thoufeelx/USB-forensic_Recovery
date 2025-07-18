import sys
import os
import time
import struct
import pyudev
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QPushButton, QTreeWidget, QTreeWidgetItem, QProgressBar,
                             QComboBox, QFileDialog, QMessageBox, QGroupBox, QHeaderView)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QMutex
from PyQt5.QtGui import QFont, QIcon, QPalette, QColor
from PyQt5.QtWidgets import QAbstractItemView
import datetime
import hashlib

def eta(start, done, total):
    if done == 0: return "--:--:--"
    elapsed = time.time() - start
    remain = (elapsed / done) * (total - done)
    return str(datetime.timedelta(seconds=int(remain)))

class DarkTheme:
    def __init__(self, app):
        self.app = app
        self.set_dark_palette()

    def set_dark_palette(self):
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(30, 30, 30))
        palette.setColor(QPalette.WindowText, QColor(200, 200, 200))
        palette.setColor(QPalette.Base, QColor(25, 25, 25))
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(50, 50, 50))
        palette.setColor(QPalette.ButtonText, QColor(200, 200, 200))
        palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.HighlightedText, Qt.white)
        self.app.setPalette(palette)

        self.app.setStyleSheet("""
            QMainWindow { background: #1e1e1e; }
            QGroupBox {
                border: 1px solid #444;
                border-radius: 4px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #ccc;
            }
            QPushButton {
                background: #333;
                color: #ccc;
                border: 1px solid #555;
                border-radius: 4px;
                padding: 5px;
                min-width: 80px;
            }
            QPushButton:hover { background: #3a3a3a; }
            QPushButton:pressed { background: #2a2a2a; }
            QPushButton:disabled { color: #777; }
            QProgressBar {
                border: 1px solid #444;
                border-radius: 3px;
                text-align: center;
                background: #252525;
            }
            QProgressBar::chunk { background: #2a82da; }
            QTreeWidget {
                background: #252525;
                color: white;
                border: 1px solid #444;
                alternate-background-color: #2a2a2a;
            }
            QLabel { color: #ccc; }
            QComboBox {
                background: #333;
                color: white;
                border: 1px solid #555;
                padding: 3px;
            }
            QHeaderView::section {
                background: #333;
                color: white;
                padding: 5px;
                border: 1px solid #444;
            }
            QTreeWidget::item {
                border: 1px solid transparent;
                padding: 2px;
            }
            QTreeWidget::item:selected {
                background-color: #2a82da;
                color: white;
            }
        """)

class RecoveryEngine:
    def __init__(self):
        self.file_signatures = {
            'jpg': [(b'\xFF\xD8\xFF', b'\xFF\xD9')],
            'png': [(b'\x89PNG\r\n\x1a\n', b'IEND\xAE\x42\x60\x82')],
            'pdf': [(b'%PDF-', b'%%EOF')],
            'zip': [(b'PK\x03\x04', b'PK\x05\x06')],
            'mp3': [(b'ID3', None), (b'\xFF\xFB', None)],
            'mp4': [(b'\x00\x00\x00\x20ftyp', b'moov'), (b'\x00\x00\x00\x18ftyp', b'moov')],
            'docx': [(b'PK\x03\x04', b'[Content_Types].xml')],
            'gif': [(b'GIF87a', b'\x00\x3B'), (b'GIF89a', b'\x00\x3B')],
            'bmp': [(b'BM', None)],
            'exe': [(b'MZ', None)],
            'avi': [(b'RIFF', b'AVI ')],
            'wav': [(b'RIFF', b'WAVE')]
        }
        self.min_file_sizes = {
            'jpg': 1024,
            'png': 67,
            'pdf': 100,
            'zip': 100,
            'mp3': 1024,
            'mp4': 1024,
            'docx': 4096,
            'gif': 35,
            'bmp': 54,
            'exe': 128,
            'avi': 1024,
            'wav': 44
        }

    def deep_scan(self, device_path, callback_progress, chunk_size=4*1024*1024):
        files = []
        start_t = time.time()
        mutex = QMutex()
        
        try:
            with open(device_path, 'rb') as f:
                f.seek(0, os.SEEK_END)
                total_size = f.tell()
                f.seek(0)
                
                pos = 0
                last_pct = -1
                overlap = 64 * 1024  
                
                while pos < total_size:
                    mutex.lock()
                    if hasattr(self, '_cancel') and self._cancel:
                        mutex.unlock()
                        return []
                    mutex.unlock()
                    
                    
                    f.seek(pos)
                    chunk = f.read(chunk_size + overlap)
                    if not chunk:
                        break
                    
                
                    for filetype, signatures in self.file_signatures.items():
                        for sig_start, sig_end in signatures:
                            offset = 0
                            while True:
                                
                                start_idx = chunk.find(sig_start, offset)
                                if start_idx == -1:
                                    break
                                
                                file_start = pos + start_idx
                                offset = start_idx + 1  

                                
                                f.seek(file_start)
                                data = b''
                                while True:
                                    chunk = f.read(1024*1024)
                                    if not chunk:
                                        break
                                    data += chunk
                                    if sig_end and sig_end in data[-len(chunk)-len(sig_end):]:
                                        end = data.rfind(sig_end) + len(sig_end)
                                        data = data[:end]
                                        break
                                    
                                    if sig_start in data[len(sig_start):]:
                                        nxt = data.find(sig_start, len(sig_start))
                                        data = data[:nxt]
                                        break

                                if len(data) > self.min_file_sizes.get(filetype, 100):
                                    
                                    file_hash = hashlib.md5(data).hexdigest()
                                    
                                    files.append({
                                        'filetype': filetype,
                                        'offset': file_start,
                                        'size': len(data),
                                        'content': data,
                                        'hash': file_hash
                                    })

                                    
                                    pos = file_start + len(data)
                                    f.seek(pos)
                                    break  

                    pos += chunk_size  
                    pct = int((pos / total_size) * 100)
                    if pct != last_pct:
                        callback_progress(pct, eta(start_t, pos, total_size))
                        last_pct = pct
                        QApplication.processEvents()  

        except Exception as e:
            print(f"Scan error: {str(e)}")
            raise
        
        callback_progress(100, "00:00:00")
        return files

    def cancel_scan(self):
        """Cancel the ongoing scan"""
        self._cancel = True

class ScanWorker(QThread):
    progress_updated = pyqtSignal(int, str) 
    files_found = pyqtSignal(list)
    scan_complete = pyqtSignal(bool, str)  
    scan_error = pyqtSignal(str)  

    def __init__(self, engine, device_path):
        super().__init__()
        self.engine = engine
        self.device_path = device_path
        self._cancel = False

    def run(self):
        try:
            def progress_callback(pct, eta):
                if self._cancel:
                    raise Exception("Scan cancelled")
                self.progress_updated.emit(pct, eta)

            files = self.engine.deep_scan(self.device_path, progress_callback)
            
            if self._cancel:
                self.scan_complete.emit(False, "Scan cancelled")
            else:
                self.files_found.emit(files)
                self.scan_complete.emit(True, f"Found {len(files)} recoverable files")
                
        except Exception as e:
            self.scan_error.emit(str(e))
            self.scan_complete.emit(False, f"Error: {str(e)}")

    def cancel(self):
        
        self._cancel = True
        self.engine.cancel_scan()

class USBForensicTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("USB Forensic Recovery Tool")
        self.setWindowIcon(QIcon.fromTheme('drive-removable-media'))
        self.setMinimumSize(1024, 768)
        
        self.recovery_engine = RecoveryEngine()
        self.scan_worker = None
        self.scan_in_progress = False
        self.selected_device = None
        self.output_dir = os.path.expanduser('~/RecoveredFiles')
        
        self.init_ui()
        self.start_device_monitoring()
        
    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        
        # Header
        header = QLabel("USB Forensic Recovery Tool")
        header.setFont(QFont("Arial", 16, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)
        
        # Device selection
        device_group = QGroupBox("Device Selection")
        device_layout = QVBoxLayout()
        
        self.device_combo = QComboBox()
        self.device_combo.setFont(QFont("Courier", 10))
        self.device_info = QLabel("No device selected")
        
        refresh_btn = QPushButton("Refresh Devices")
        refresh_btn.clicked.connect(self.refresh_devices)
        
        device_layout.addWidget(self.device_combo)
        device_layout.addWidget(self.device_info)
        device_layout.addWidget(refresh_btn)
        device_group.setLayout(device_layout)
        layout.addWidget(device_group)
        
        # Scan controls
        scan_group = QGroupBox("Recovery Operations")
        scan_layout = QHBoxLayout()
        
        self.scan_btn = QPushButton("Start Deep Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        
        self.cancel_btn = QPushButton("Cancel Scan")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self.cancel_scan)
        
        scan_layout.addWidget(self.scan_btn)
        scan_layout.addWidget(self.cancel_btn)
        scan_group.setLayout(scan_layout)
        layout.addWidget(scan_group)
        
        # Progress
        self.progress = QProgressBar()
        self.status = QLabel("Ready")
        
        layout.addWidget(self.progress)
        layout.addWidget(self.status)
        
        # Results
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabels(["", "Name", "Size", "Type", "Offset", "Hash"])
        self.file_tree.setRootIsDecorated(False)
        self.file_tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.file_tree.setSortingEnabled(True)
        self.file_tree.sortByColumn(4, Qt.AscendingOrder)
        self.file_tree.setColumnWidth(0, 30)  # Make checkbox column narrower
        
        # Enable checkboxes for all items
        self.file_tree.setStyleSheet("""
            QTreeView::indicator {
                width: 16px;
                height: 16px;
            }
            QTreeView::indicator:unchecked {
                background-color: #333;
                border: 1px solid #555;
            }
            QTreeView::indicator:checked {
                background-color: #2a82da;
                border: 1px solid #555;
            }
        """)
        
        layout.addWidget(self.file_tree)
        
        recovery_group = QGroupBox("File Recovery")
        recovery_layout = QHBoxLayout()
        
        self.output_btn = QPushButton("Set Output Directory")
        self.output_btn.clicked.connect(self.set_output_directory)
        
        self.select_all_btn = QPushButton("Select All")
        self.select_all_btn.clicked.connect(self.select_all_files)
        
        self.deselect_all_btn = QPushButton("Deselect All")
        self.deselect_all_btn.clicked.connect(self.deselect_all_files)
        
        self.recover_btn = QPushButton("Recover Selected")
        self.recover_btn.setEnabled(False)
        self.recover_btn.clicked.connect(self.recover_selected_files)
        
        recovery_layout.addWidget(self.output_btn)
        recovery_layout.addWidget(self.select_all_btn)
        recovery_layout.addWidget(self.deselect_all_btn)
        recovery_layout.addWidget(self.recover_btn)
        recovery_group.setLayout(recovery_layout)
        layout.addWidget(recovery_group)
        
        # Set initial UI state
        self.update_ui_state()
    
    def update_ui_state(self):
        
        self.scan_btn.setEnabled(not self.scan_in_progress and self.selected_device is not None)
        self.cancel_btn.setEnabled(self.scan_in_progress)
        self.recover_btn.setEnabled(not self.scan_in_progress and self.file_tree.topLevelItemCount() > 0)
        self.select_all_btn.setEnabled(not self.scan_in_progress and self.file_tree.topLevelItemCount() > 0)
        self.deselect_all_btn.setEnabled(not self.scan_in_progress and self.file_tree.topLevelItemCount() > 0)
    
    def start_device_monitoring(self):
        
        self.usb_scanner = USBScanner()
        self.usb_scanner.devices_changed.connect(self.update_device_list)
        self.usb_scanner.start()
    
    def update_device_list(self, devices):
        
        current = self.device_combo.currentData()
        self.device_combo.clear()
        
        for device in devices:
            text = f"{device['node']} - {device['model']} ({device['size']})"
            self.device_combo.addItem(text, device['node'])
        
        
        if current:
            index = self.device_combo.findData(current)
            if index >= 0:
                self.device_combo.setCurrentIndex(index)
        
        
        elif self.device_combo.count() > 0 and not self.selected_device:
            self.device_combo.setCurrentIndex(0)
        
        self.on_device_selected(self.device_combo.currentIndex())
    
    def refresh_devices(self):
     
        self.status.setText("Refreshing device list...")
        QApplication.processEvents()
        self.usb_scanner.run()
    
    def on_device_selected(self, index):
        
        if index >=  self.device_combo.count():
            self.selected_device = None
            self.device_info.setText("No device selected")
        else:
            self.selected_device = self.device_combo.itemData(index)
            self.device_info.setText(f"Selected: {self.device_combo.itemText(index)}")
        
        self.update_ui_state()
    
    def start_scan(self):
       
        if not self.selected_device:
            QMessageBox.warning(self, "No Device", "Please select a USB device first")
            return
        
        if self.scan_in_progress:
            QMessageBox.warning(self, "Scan Running", "A scan is already in progress")
            return
        
        
        self.file_tree.clear()
        self.progress.setValue(0)
        self.status.setText("Starting deep scan...")
        self.scan_in_progress = True
        self.update_ui_state()
        
        
        self.scan_worker = ScanWorker(self.recovery_engine, self.selected_device)
        self.scan_worker.progress_updated.connect(self.update_progress)
        self.scan_worker.files_found.connect(self.display_files)
        self.scan_worker.scan_complete.connect(self.on_scan_complete)
        self.scan_worker.scan_error.connect(self.on_scan_error)
        self.scan_worker.start()
    
    def update_progress(self, percent, eta):
        
        self.progress.setValue(percent)
        self.status.setText(f"Scanning... {percent}% complete | ETA: {eta}")
    
    def display_files(self, files):
        
        self.file_tree.clear()
        
        for file_info in files:
            item = QTreeWidgetItem()
            item.setCheckState(0, Qt.Unchecked)
            
            
            filename = f"{file_info['filetype']}_{hex(file_info['offset'])}.{file_info['filetype']}"
            item.setText(1, filename)
            
           
            size = file_info['size']
            size_str = self.format_size(size)
            item.setText(2, size_str)
            
            
            item.setText(3, file_info['filetype'].upper())
            item.setText(4, hex(file_info['offset']))
            item.setText(5, file_info['hash'][:8])  # Show first 8 chars of hash
            
            
            item.setData(0, Qt.UserRole, file_info)
            
            self.file_tree.addTopLevelItem(item)
        
        self.file_tree.resizeColumnToContents(0)
        self.file_tree.resizeColumnToContents(1)
        self.file_tree.resizeColumnToContents(2)
        self.file_tree.resizeColumnToContents(3)
        self.file_tree.resizeColumnToContents(4)
        self.file_tree.resizeColumnToContents(5)
        self.update_ui_state()
    
    def format_size(self, bytes):
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes < 1024.0:
                return f"{bytes:.1f} {unit}"
            bytes /= 1024.0
        return f"{bytes:.1f} PB"
    
    def on_scan_complete(self, success, message):
        
        self.scan_in_progress = False
        self.status.setText(message)
        self.update_ui_state()
        
        if success:
            QMessageBox.information(self, "Scan Complete", message)
        else:
            QMessageBox.warning(self, "Scan Failed", message)
    
    def on_scan_error(self, error):
        
        self.scan_in_progress = False
        self.status.setText(f"Error: {error}")
        self.update_ui_state()
        QMessageBox.critical(self, "Scan Error", error)
    
    def cancel_scan(self):
        
        if self.scan_worker and self.scan_in_progress:
            self.status.setText("Cancelling scan...")
            self.scan_worker.cancel()
    
    def select_all_files(self):
        
        for i in range(self.file_tree.topLevelItemCount()):
            item = self.file_tree.topLevelItem(i)
            item.setCheckState(0, Qt.Checked)
    
    def deselect_all_files(self):
        
        for i in range(self.file_tree.topLevelItemCount()):
            item = self.file_tree.topLevelItem(i)
            item.setCheckState(0, Qt.Unchecked)
    
    def set_output_directory(self):
        
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Output Directory",
            self.output_dir,
            QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks
        )
        
        if directory:
            self.output_dir = directory
            QMessageBox.information(
                self,
                "Output Directory Set",
                f"Recovered files will be saved to:\n{directory}"
            )
    
    def recover_selected_files(self):
       
        # Get selected items
        selected = []
        for i in range(self.file_tree.topLevelItemCount()):
            item = self.file_tree.topLevelItem(i)
            if item.checkState(0) == Qt.Checked:
                selected.append(item)
        
        if not selected:
            QMessageBox.warning(self, "No Selection", "Please select files to recover")
            return
        
        # Create output directory if needed
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir)
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Directory Error",
                    f"Cannot create output directory:\n{str(e)}"
                )
                return
        
        
        success_count = 0
        errors = []
        
        for item in selected:
            file_info = item.data(0, Qt.UserRole)
            try:
                
                basename = f"{file_info['filetype']}_{file_info['offset']}"
                ext = file_info['filetype']
                filename = f"{basename}.{ext}"
                path = os.path.join(self.output_dir, filename)
                
               
                counter = 1
                while os.path.exists(path):
                    filename = f"{basename}_{counter}.{ext}"
                    path = os.path.join(self.output_dir, filename)
                    counter += 1
                
                
                with open(path, 'wb') as f:
                    f.write(file_info['content'])
                
                success_count += 1
            except Exception as e:
                errors.append(f"{filename}: {str(e)}")
        
        
        if errors:
            msg = f"Recovered {success_count} files\n\nErrors:\n" + "\n".join(errors)
            QMessageBox.warning(self, "Recovery Complete with Errors", msg)
        else:
            QMessageBox.information(
                self,
                "Recovery Complete",
                f"Successfully recovered {success_count} files to:\n{self.output_dir}"
            )

class USBScanner(QThread):
    devices_changed = pyqtSignal(list)
    
    def __init__(self):
        super().__init__()
        self.context = pyudev.Context()
        self.monitor = pyudev.Monitor.from_netlink(self.context)
        self.monitor.filter_by(subsystem='block')
        self.running = True
    
    def run(self):
        while self.running:
            devices = self.get_usb_devices()
            self.devices_changed.emit(devices)
            time.sleep(2)
    
    def get_usb_devices(self):
       
        devices = []
        
        for device in self.context.list_devices(subsystem='block'):
            if (device.get('ID_BUS') == 'usb' and 
                device.device_node and 
                device.device_node.startswith('/dev/sd')):
                
                size_bytes = int(device.attributes.get('size', 0)) * 512
                size_str = self.format_size(size_bytes)
                
                devices.append({
                    'node': device.device_node,
                    'model': device.get('ID_MODEL', 'Unknown USB Device'),
                    'size': size_str,
                    'vendor': device.get('ID_VENDOR', 'Unknown Vendor'),
                    'serial': device.get('ID_SERIAL_SHORT', ''),
                    'filesystem': device.get('ID_FS_TYPE', 'Unknown')
                })
        
        return devices
    
    def format_size(self, bytes):
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes < 1024.0:
                return f"{bytes:.1f} {unit}"
            bytes /= 1024.0
        return f"{bytes:.1f} PB"
    
    def stop(self):
       
        self.running = False
        self.wait()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    theme = DarkTheme(app)
    font = QFont("Segoe UI", 9)
    app.setFont(font)
    window = USBForensicTool()
    window.show()
    sys.exit(app.exec())