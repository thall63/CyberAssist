# hash is a tool to create hashes of a file and optionally submit them to Virus Total.
# https://docs.python.org/3/library/hashlib.html?highlight=hashlib#module-hashlib

# ::Import::
import sys
import hashlib
import zlib
import re
from vt import VT
from datetime import datetime as dt
from PyQt6.QtGui import QPalette, QColor

from PyQt6.QtGui import QAction, QFont

from PyQt6.QtCore import (
    Qt, 
    QObject, 
    QThreadPool, 
    pyqtSignal, 
    QRunnable, 
    pyqtSlot,
)

from PyQt6.QtWidgets import (
    QApplication, 
    QLabel, 
    QMainWindow,
    QTextEdit,
    QGridLayout,
    QWidget,
    QComboBox,
    QFileDialog,
    QMessageBox,
    QLineEdit,
    QSpinBox,
    QTableView,
    QDialog,
    QInputDialog,
    QPushButton
)

# ::PyQT Threads::
class ThreadSignal(QObject):
    finished = pyqtSignal()
    error = pyqtSignal(str)
    result = pyqtSignal(str)

class TBD(QRunnable):

    def __init__(self, ip, ip_cidr):
            super().__init__()
            self.signals = (ThreadSignal())
            self.ip = ip
            self.ip_cidr = ip_cidr

    @pyqtSlot()
    def run(self):
        '''
        Initialize the runner function with passed self.args,
        self.kwargs.
        '''
        pass

# ::View::
class Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.vt_key = ''
        self.threadpool = QThreadPool()
        self.setWindowTitle('Net')
        self.setFont(QFont('Arial', 14))
        #
        widget = QWidget(self)
        layout = QGridLayout(widget)
        #
        self.clear_output_button = QPushButton('Clear Output', self)
        layout.addWidget(self.clear_output_button, 0, 3)
        self.copy_output_button = QPushButton('Copy Output', self)
        layout.addWidget(self.copy_output_button, 0, 2)
        #
        self.output_text = QTextEdit()
        self.output_text.setPlaceholderText('Output')
        self.output_text.setAlignment(Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.output_text, 2, 0, 1, 4)
        #        
        self.hash_type = QComboBox(self)
        self.hash_type.setPlaceholderText('Hash Type')
        self.hash_type.setDisabled(False)
        self.hash_type.addItems(['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512','All'])
        layout.addWidget(self.hash_type, 1, 0)
        self.hash_type.setEditable(True)
        self.hash_type.setCurrentText('Hash Type')
        #
        self.open_file = QFileDialog(self)
        self.file_button = QPushButton('Select File', self)
        layout.addWidget(self.file_button, 1, 1)
        self.file_button.setDisabled(True)
        #
        self.get_hash = QInputDialog(self)
        self.vt_hash_button = QPushButton('VT Hash', self)
        self.vt_hash_button.setDisabled(True)
        layout.addWidget(self.vt_hash_button, 0, 0)
        #
        self.get_key = QInputDialog(self)
        self.vt_key_button = QPushButton('VT Key', self)
        layout.addWidget(self.vt_key_button, 0, 1)
        #
        self.msgBox = QMessageBox(self)
        self.msgBox.setIcon(QMessageBox.Icon.Information)
        #
        self.setCentralWidget(widget)
        self._createStatusBar()
        self._connectActions()
        
    def _createStatusBar(self):
        '''
        Status Bar
        '''
        self.statusbar = self.statusBar()
        self.statusbar.showMessage('CyberAssist == Hash')

    
    # ::Control Section::
    
    # ::Action Slots::
    
    def _connectActions(self):
        '''
        Event actions
        '''
        self.file_button.clicked.connect(self.file_hash)
        self.hash_type.activated.connect(self.enable_file_button)
        self.clear_output_button.clicked.connect(self.clear_output)
        self.copy_output_button.clicked.connect(self.copy_content)
        self.vt_hash_button.clicked.connect(self.vt_hash)
        self.vt_key_button.clicked.connect(self.get_vtkey)

    
    def regex_validate(self, hash_value):
        '''
        Validate hash value
        '''
        regex = re.compile(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$')
        if regex.match(hash_value):
            return True
        else:
            return False
    
    def enable_file_button(self):
        '''
        Enable file button
        '''
        self.file_button.setDisabled(False)
        self.clear_output()

    
    def file_hash(self):
        '''
        Create a set of hashes for a file
        '''
        algo_list = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512']
        self.output_text.clear()
        hash_algorithm = self.hash_type.currentText()
        file_name, file_types = self.open_file.getOpenFileName()
        if file_name and hash_algorithm != 'All':
            self.hash_output(f'File: {file_name}\n\n')
            file_object = open(file_name, 'rb')
            file_hash = eval(f'hashlib.{hash_algorithm}()')
            file_hash.update(file_object.read())
            hash_string = file_hash.hexdigest()
            self.hash_output(f'{hash_algorithm}: {hash_string}')
        elif file_name and hash_algorithm == 'All':
            self.hash_output(f'File: {file_name}\n\n')
            for algo in algo_list:
                file_object = open(file_name, 'rb')
                file_hash = eval(f'hashlib.{algo}()')
                file_hash.update(file_object.read())
                hash_string = file_hash.hexdigest()
                self.hash_output(f'{algo}: {hash_string}\n')
        else:
            self.hash_output('No valid file selected')
        self.file_button.setDisabled(True)
        self.hash_type.setCurrentText('Hash Type')
       
    def copy_content(self):
        '''
        Copy output content to clipboard
        '''
        self.output_text.selectAll()
        self.output_text.copy()


    def clear_output(self):
        '''
        Clear output content
        '''
        self.output_text.clear()


    def hash_output(self, s):
        '''
        Show calculation in output
        '''
        self.output_text.insertPlainText(s)

    def get_vtkey(self):
        '''
        Set Virus Total API key
        '''
        key, ok = self.get_key.getText(self, 'Virus Total Key', 'Enter your Virus Total API key')
        if ok:
            self.vt_key = key
            self.msgBox.setWindowTitle('Virus Total API Key Set') 
            self.msgBox.setDetailedText(f"Virus Total API key set as\n{self.vt_key}.\nKey will remain set until application is closed or key is changed.\n\nTo change the key, click the 'VT Key' button again.")
            self.msgBox.exec()
            self.vt_hash_button.setDisabled(False)

    def vt_hash(self):
        '''
        Submit a hash to Virus Total
        Add prommpt for API key
        '''
        self.clear_output()
        vt = VT(self.vt_key)
        hash_value, ok = self.get_hash.getText(self, 'Virus Total Hash', 'Enter an MD5, SHA1 or SHA256 hash only')
        if ok:
            valid_hash = self.regex_validate(hash_value)
            if valid_hash:
                try:
                    vt_data = vt.get_hash(hash_value)
                    self.output_text.clear()
                    self.hash_output(f'{vt_data}')
                except KeyError as e:
                    self.hash_output(f'Error: {e}')
            else:
                self.hash_output('Invalid hash value')

# ::Run Main::
if __name__ == '__main__':
    app = QApplication(sys.argv)
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Base, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.Window, Qt.GlobalColor.lightGray)
    palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.Button, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.black)
    palette.setColor(QPalette.ColorRole.PlaceholderText, Qt.GlobalColor.darkGray)
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, Qt.GlobalColor.gray)
    app.setPalette(palette)
    win = Window()
    win.setMinimumWidth(1100)
    win.setMinimumHeight(700)
    win.setWindowTitle('Hash')
    win.show()
    win.hash_type.setFocus()
    sys.exit(app.exec())
