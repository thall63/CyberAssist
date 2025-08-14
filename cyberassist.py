# Python built-in imports
import sys
import ipaddress
import re
import hashlib
from datetime import datetime as dt
import base64

# Custom imports
from vt import VT

# PyQt6 imports organized by module
from PyQt6.QtCore import (
    Qt, QObject, QThreadPool, pyqtSignal, QRunnable, pyqtSlot
)

from PyQt6.QtGui import (
    QPalette, QColor, QAction, QFont, QIcon, QCursor, 
    QKeySequence, QPixmap, QBrush
)

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
    QGridLayout, QLabel, QPushButton, QLineEdit, QTextEdit, 
    QSpinBox, QComboBox, QInputDialog, QFileDialog, 
    QMessageBox, QStatusBar, QPlainTextEdit
)

# ::PyQT Threads::
class ThreadSignal(QObject):
    finished = pyqtSignal()
    error = pyqtSignal(str)
    result = pyqtSignal(str)


class IP_calculate(QRunnable):

    def __init__(self, ip, ip_cidr):
            super().__init__()
            self.signals = ThreadSignal()
            self.ip = ip
            self.ip_cidr = ip_cidr

    @pyqtSlot()
    def run(self):
        '''
        Initialize the runner function with passed self.args,
        self.kwargs.
        '''
        try:
            ip_addr = ipaddress.ip_address(self.ip)
            global_ip = ip_addr.is_global
            multicast_ip = ip_addr.is_multicast
            private_ip = ip_addr.is_private
            reserved_ip = ip_addr.is_reserved
            unspecified_ip = ip_addr.is_unspecified
            loopback_ip = ip_addr.is_loopback
            link_local = ip_addr.is_link_local
            ip_net = ipaddress.ip_network(f'{self.ip}/{self.ip_cidr}', strict=False)
            first_host = ip_net[0]
            last_host = ip_net[-1]
            total_hosts = '{:,}'.format(ip_net.num_addresses)
            self.net_range = f'IP Address:  {ip_addr}\nGlobal IP:   {global_ip}\nPrivate IP:   {private_ip}\nMulticast IP:   {multicast_ip}\nReserved IP:   {reserved_ip}\nUnspecified IP:   {unspecified_ip}\nLoopback Address:   {loopback_ip}\nLink Local:   {link_local}\nIP Network:  {ip_net}\nFirst Host:  {first_host}\nLast Host:  {last_host}\nTotal Hosts:  {total_hosts}\n'
            self.signals.result.emit(self.net_range)
        except Exception as e:
            self.signals.error.emit(f'Invalid IP address, please try again --> {e}')


class TabbedWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cyber Assistant for Cyber Heroes")
        self.setGeometry(100, 100, 600, 400) # x, y, width, height

        # Create a QTabWidget instance
        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)

        # Create and add tabs
        self.add_tab1()
        self.add_tab2()
        self.add_tab3()
        self.add_tab4()

        self.threadpool = QThreadPool()

        # Status bar
        self.statusbar = self.statusBar()
        self.statusbar.showMessage('Cyber Assistant')

        # Set view mode
        self.view_mode()

        # Connect actions
        self._connectActions()


    def add_tab1(self):
        # Create a QWidget for Tab 1 - IP Calculator
        tab1_content = QWidget()
        
        # Create a grid layout for the IP calculator
        layout = QGridLayout()
        
        # IP Version toggle button
        self.ip_ver_btn = QPushButton('IPv6', tab1_content)
        self.ip_ver_btn.setStyleSheet('background-color: #f0f0f0')
        self.ip_ver_btn.clicked.connect(self.ip_version)
        layout.addWidget(self.ip_ver_btn, 0, 0)
        
        # IP Address input field
        self.ip_entry = QLineEdit(tab1_content)
        self.ip_entry.setPlaceholderText('Input IPv4 Address')
        layout.addWidget(self.ip_entry, 0, 1)
        
        # CIDR prefix label
        self.cidr_label = QLabel('Prefix', tab1_content)
        layout.addWidget(self.cidr_label, 0, 2)
        
        # CIDR prefix spinbox
        self.cidr_entry = QSpinBox(tab1_content)
        self.cidr_entry.setAccelerated(True)
        self.cidr_entry.setStyleSheet('background-color: #f0f0f0')
        self.cidr_entry.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.cidr_entry.setRange(0, 32)  # Set range for IPv4
        self.cidr_entry.setValue(0)     # Default value
        layout.addWidget(self.cidr_entry, 0, 3)
        
        # Calculate button
        self.ip_calc_btn = QPushButton('Calculate IP Range', tab1_content)
        # self.ip_calc_btn.setStyleSheet('background-color: #f0f0f0')
        self.ip_calc_btn.clicked.connect(self.calc_ip)
        layout.addWidget(self.ip_calc_btn, 0, 4)
        
        # Output text area
        self.ip_output_text = QPlainTextEdit(tab1_content)
        self.ip_output_text.setPlaceholderText('OUTPUT')
        # self.ip_output_text.setAlignment(Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.ip_output_text, 3, 0, 1, 5)

        # Add buttons for clearing and copying output
        self.clear_output_button = QPushButton('Clear Output', tab1_content)
        layout.addWidget(self.clear_output_button, 2, 3)
        self.clear_output_button.clicked.connect(lambda: self.clear_output(self.ip_output_text))
        self.copy_output_button = QPushButton('Copy Output', tab1_content)
        layout.addWidget(self.copy_output_button, 2, 4)
        self.copy_output_button.clicked.connect(lambda: self.copy_output(self.ip_output_text))

        # Set the layout for the tab content
        tab1_content.setLayout(layout)
        # Add the tab to the tab widget
        self.tab_widget.addTab(tab1_content, "Tab 1: IP Calculator")


    def add_tab2(self):
        # Create a QWidget for Tab 2
        tab2_content = QWidget()

        # Create a grid layout for the IP scraper
        layout = QGridLayout()

        # Add the tab to the tab widget
        self.tab_widget.addTab(tab2_content, "Tab 2: IP Scraper")

        # Add a button to scrape IP addresses
        self.ip_scraper_btn = QPushButton('Scrape IPs', tab2_content)
        self.ip_scraper_btn.clicked.connect(self.scrape_ip_address)
        layout.addWidget(self.ip_scraper_btn, 0, 0)

        # Add buttons for clearing and copying output
        self.clear_output_button = QPushButton('Clear Output', tab2_content)
        layout.addWidget(self.clear_output_button, 0, 1)
        self.clear_output_button.clicked.connect(lambda: self.clear_output(self.scrape_output_text))
        self.copy_output_button = QPushButton('Copy Output', tab2_content)
        layout.addWidget(self.copy_output_button, 0, 2)
        self.copy_output_button.clicked.connect(lambda: self.copy_output(self.scrape_output_text))

        # Output text area
        self.scrape_output_text = QPlainTextEdit(tab2_content)
        self.scrape_output_text.setPlaceholderText('OUTPUT')
        layout.addWidget(self.scrape_output_text, 2, 0, 1, 5)

        # Set the layout for the tab content        
        tab2_content.setLayout(layout)


    def add_tab3(self):
        # Create a QWidget for Tab 3
        tab3_content = QWidget()

        # Create a grid layout for the hashing tab
        layout = QGridLayout()

        # Add the tab to the tab widget
        self.tab_widget.addTab(tab3_content, "Tab 3: HASHING")

        # Add a label to Tab 3
        label = QLabel("Tab 3 Provides file hashing and reputation.")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(label)
        
        # Add buttons and input fields for hashing
        self.clear_output_button = QPushButton('Clear Output', self)
        layout.addWidget(self.clear_output_button, 0, 2)
        self.clear_output_button.clicked.connect(lambda: self.clear_output(self.hash_output_text))
        self.copy_output_button = QPushButton('Copy Output', self)
        layout.addWidget(self.copy_output_button, 1, 2)
        self.copy_output_button.clicked.connect(lambda: self.copy_output(self.hash_output_text))

        # Hash output area
        self.hash_output_text = QPlainTextEdit()
        self.hash_output_text.setPlaceholderText('OUTPUT')
        layout.addWidget(self.hash_output_text, 2, 0, 2, 5)
        
        # Add buttons for file selection and Virus Total 
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

        # Create a QWidget for Tab 3
        tab3_content.setLayout(layout)


    def add_tab4(self):
        # Create a QWidget for Tab 4
        tab4_content = QWidget()

        # Create a grid layout for the Base64 encoding/decoding tab
        layout = QGridLayout()

        # Add the tab to the tab widget
        self.tab_widget.addTab(tab4_content, "Tab 4: Base64")

        # Add a label to Tab 4
        label = QLabel("Tab 4: Base64 Encoding/Decoding")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(label)

        # base64 buttons
        self.base64_encode_button = QPushButton('Base64 Encode', self)
        layout.addWidget(self.base64_encode_button, 0, 0)
        self.base64_decode_button = QPushButton('Base64 Decode', self)
        layout.addWidget(self.base64_decode_button, 1, 0)

        # Input buttons
        self.clear_input_button = QPushButton('Clear Input', self)
        layout.addWidget(self.clear_input_button, 2, 0)
        self.clear_input_button.clicked.connect(lambda: self.clear_input(self.base64_input_text))

        # Output buttons
        self.clear_output_button = QPushButton('Clear Output', self)
        layout.addWidget(self.clear_output_button, 1, 1)
        self.clear_output_button.clicked.connect(lambda: self.clear_output(self.base64_output_text))
        
        self.clear_all_button = QPushButton('Clear All', self)
        layout.addWidget(self.clear_all_button, 0, 1)
        self.clear_all_button.clicked.connect(lambda: self.clear_all_input_ouput(self.base64_input_text, self.base64_output_text))
        
        self.copy_output_button = QPushButton('Copy Output', self)
        layout.addWidget(self.copy_output_button, 2, 1)
        self.copy_output_button.clicked.connect(lambda: self.copy_output(self.base64_output_text))

        self.swap_button = QPushButton('Swap Output to Input', self)
        layout.addWidget(self.swap_button, 3, 1)
        self.swap_button.clicked.connect(lambda: self.swap_output_to_input(self.base64_output_text, self.base64_input_text))
        
        # Base64 input and output text areas
        self.base64_input_text = QPlainTextEdit()
        self.base64_input_text.setBackgroundVisible(False)
        self.base64_output_text = QPlainTextEdit()
        self.base64_input_text.setPlaceholderText('INPUT')
        self.base64_input_text.setFont(QFont('Arial', 14))
        self.base64_output_text.setPlaceholderText('OUTPUT')
        self.base64_output_text.setFont(QFont('Arial', 14))
        layout.addWidget(self.base64_input_text, 4, 0)
        layout.addWidget(self.base64_output_text, 4, 1)

        # Set the layout for the tab content
        tab4_content.setLayout(layout)


    def ip_version(self):
        """Toggle between IPv4 and IPv6"""
        if self.ip_ver_btn.text() == 'IPv6':
            self.ip_ver_btn.setText('IPv4')
            self.ip_entry.setPlaceholderText('Input IPv6 Address')
            self.cidr_entry.setRange(0, 128)  # IPv6 range
            self.cidr_entry.setValue(64)      # Default IPv6 prefix
        else:
            self.ip_ver_btn.setText('IPv6')
            self.ip_entry.setPlaceholderText('Input IPv4 Address')
            self.cidr_entry.setRange(0, 32)   # IPv4 range
            self.cidr_entry.setValue(0)      # Default IPv4 prefix


    def calc_ip(self):
        """Calculate IP range using threading"""
        ip_text = self.ip_entry.text().strip()
        cidr_value = self.cidr_entry.value()
        
        if not ip_text:
            self.ip_output_text.setText("Please enter an IP address.")
            return
            
        # Clear previous output
        self.ip_output_text.clear()
        self.ip_output_text.insertPlainText("Calculating...")

        # Create and start the worker thread
        worker = IP_calculate(ip_text, cidr_value)
        worker.signals.result.connect(self.display_result)
        worker.signals.error.connect(self.display_error)
        
        self.threadpool.start(worker)
    

    def scrape_ip_address(self):
        '''
        Scrapes IPv4 and IPv6 addresses from a text file.
        Return formatted lists of IPv4 and IPv6 addresses.
        '''
        # Clear output text
        self.scrape_output_text.clear()

        # ::Regex for Scraper::
        ipv4_addr = re.compile(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
        ipv6_standard_compressed = re.compile(r'(([A-F0-9]{1,4}:){7}[A-F0-9]{1,4}|(?=([A-F0-9]{0,4}:){0,7}[A-F0-9]{0,4}(?![:.\w]))(([0-9A-F]{1,4}:){1,7}|:)((:[0-9A-F]{1,4}){1,7}|:)|([A-F0-9]{1,4}:){7}:|:(:[A-F0-9]{1,4}){7})', re.IGNORECASE)
        ipv6_mixed_compressed = re.compile(r'(?:(?:[a-fA-F0-9]{1,4}:){6}|(?=(?:[a-fA-F0-9]{0,4}:){0,6}(?:[0-9]{1,3}\.){3}[0-9]{1,3})(([a-fA-F0-9]{1,4}:){0,5}|:)((:[a-fA-F0-9]{1,4}){1,5}:|:)|::(?:[a-fA-F0-9]{1,4}:){5})(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])', re.IGNORECASE)
        scrape_title = "IP Address Search"
        label = "Retrieve IPv4 and/or IPv6 addresses"
        scrape_text = "Paste in text containting IPv4 or IPv6 addresses"
        ip_input_text, ok = QInputDialog.getMultiLineText(self, scrape_title, label, scrape_text)
        ip_input_list = []
        ipv4_list = []
        if ok == True:
            ip_input_list = ip_input_text.split()
        else:
            return      
        for item in ip_input_list:
            ipv4_result = ipv4_addr.fullmatch(item)
            if ipv4_result:
                ipv4_list.append(ipv4_result.group())
        standard_compressed_list = []
        for item in ip_input_list:
            std_result = ipv6_standard_compressed.fullmatch(item)
            if std_result:
                standard_compressed_list.append(std_result.group())
        mixed_compressed_list = []
        for item in ip_input_list:
            mixed_compressed_result = ipv6_mixed_compressed.fullmatch(item)
            if mixed_compressed_result:
                mixed_compressed_list.append(mixed_compressed_result.group())
        ipv4_text_block = '\n'.join(list(set(ipv4_list)))
        standard_compressed_text_block = '\n'.join(list(set(standard_compressed_list)))
        mixed_notation_text_block = '\n'.join(list(set(mixed_compressed_list)))
        scraped_ip_text = f'IPv4 Addresses:\n{ipv4_text_block}\n\nStandard and Compressed IPv6 Addresses:\n{standard_compressed_text_block}\n\nMixed and Mixed Compressed IPv6 Addresses:\n{mixed_notation_text_block}'
        self.clear_output(self.scrape_output_text)
        # Consider not printing scraped lists that are empty
        self.scrape_output_text.insertPlainText(scraped_ip_text)


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
        self.clear_output(self.hash_output_text)

    
    def file_hash(self):
        '''
        Create a set of hashes for a file
        '''
        algo_list = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512']
        self.clear_output(self.hash_output_text)
        hash_algorithm = self.hash_type.currentText()
        file_name, file_types = self.open_file.getOpenFileName()
        if file_name and hash_algorithm != 'All':
            self.hash_output_text.insertPlainText(f'File: {file_name}\n\n')
            with open(file_name, 'rb') as file_object:
                file_hash = getattr(hashlib, hash_algorithm)()
                file_hash.update(file_object.read())
                hash_string = file_hash.hexdigest()
                self.hash_output_text.insertPlainText(f'{hash_algorithm}: {hash_string}')
        elif file_name and hash_algorithm == 'All':
            self.hash_output_text.insertPlainText(f'File: {file_name}\n\n')
            for algo in algo_list:
                with open(file_name, 'rb') as file_object:
                    file_hash = getattr(hashlib, algo)()
                    file_hash.update(file_object.read())
                    hash_string = file_hash.hexdigest()
                    self.hash_output_text.insertPlainText(f'{algo}: {hash_string}\n')
        else:
            self.hash_output_text.insertPlainText('No valid file selected')
        self.file_button.setDisabled(True)
        self.hash_type.setCurrentText('Hash Type')


    def base64_encode(self):
        '''
        Encode text with Base64
        '''

        try:
            data = self.base64_input_text.toPlainText()
            if len(data) < 1:
                result = f'base64 encode: Paste text to encode to INPUT\n'
                self.base64_output_text.insertPlainText(result)
            else:
                data = data.encode(encoding='utf-8', errors='strict')
                result = base64.b64encode(data)
                result = result.decode(encoding='utf-8', errors='strict')
                self.base64_output_text.insertPlainText(result)
        except:
            self.base64_output_text.insertPlainText('Data could not be encoded')

        
    def base64_decode(self):
        '''
        Decode Base64 encoded text
        '''

        try:
            data = self.base64_input_text.toPlainText()
            if len(data) < 1:
                result = f'base64 decode: Paste text to decode to INPUT\n'
                self.base64_output_text.insertPlainText(result)
            else:
                data = data.encode(encoding='utf-8', errors='strict')
                result = base64.b64decode(data)
                result = result.decode(encoding='utf-8', errors='strict')
                self.base64_output_text.insertPlainText(result)
        except:
            self.base64_output_text.insertPlainText('Data could not be decoded')


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
        Add prompt for API key
        '''
        self.clear_output(self.hash_output_text)
        vt = VT(self.vt_key)
        hash_value, ok = self.get_hash.getText(self, 'Virus Total Hash', 'Enter an MD5, SHA1 or SHA256 hash only')
        if ok:
            valid_hash = self.regex_validate(hash_value)
            if valid_hash:
                try:
                    vt_data = vt.get_hash(hash_value)
                    self.clear_output(self.hash_output_text)
                    self.hash_output_text.insertPlainText(f'{vt_data}')
                except KeyError as e:
                    self.hash_output_text.insertPlainText(f'No Virus Total data for {hash_value}')
            else:
                self.hash_output_text.insertPlainText('Invalid hash value')

  
    def clear_input(self, input_widget):
        '''
        Clear input content
        '''
        input_widget.clear()


    def clear_output(self, output_widget):
        '''
        Clear output content
        '''
        output_widget.clear()


    def clear_all_input_ouput(self, input_widget, output_widget):
        '''
        Clear both input and output content
        '''
        self.clear_input(input_widget)
        self.clear_output(output_widget)


    def copy_output(self, output_widget):
        '''
        Copy output content to clipboard
        '''
        output_widget.selectAll()
        output_widget.copy()


    def swap_output_to_input(self, output_widget, input_widget):
        '''
        Swap output and input content
        '''
        
        temp = output_widget.toPlainText()
        input_widget.clear()
        input_widget.setPlainText(temp)
        output_widget.clear()


    def display_result(self, result):
        """Display calculation results"""
        self.ip_output_text.clear()
        self.ip_output_text.insertPlainText(result)
        self.ip_entry.clear()
        self.ip_entry.setPlaceholderText('Input IPv4 Address')
        self.cidr_entry.setRange(0, 32)  # Reset CIDR range
        self.cidr_entry.setValue(0)  # Reset CIDR to default for IPv4


    def display_error(self, error_msg):
        """Display error messages"""
        self.ip_output_text.clear()
        self.ip_output_text.insertPlainText(error_msg)


    def _createActions(self):
        """Create actions (placeholder)"""
        pass


    def _connectActions(self):
        """Connect actions (placeholder)"""
        self.file_button.clicked.connect(self.file_hash)
        self.hash_type.activated.connect(self.enable_file_button)
        self.vt_hash_button.clicked.connect(self.vt_hash)
        self.vt_key_button.clicked.connect(self.get_vtkey)
        self.base64_encode_button.pressed.connect(self.base64_encode)
        self.base64_decode_button.pressed.connect(self.base64_decode)

    def view_mode(self):
        '''
        QSS View Mode
        '''

        qss_bright_view = """
            QWidget {
                background-color: rgb(187, 226, 227);
                color: black;
                font-size:16px !important;
            }
            .QComboBox {
                color: black;
                background-color: white;
                selection-background-color: white;
                selection-color: black;
            }
            .QComboBox QAbstractItemView::item {
                color: black;
                background-color: white;
            }
            QPlainTextEdit {
                background-color: white;
                color: black;
            }
            QPlainTextEdit {
                background-color: white;
                color: black;
            }
            QProgressBar {
                border-style: solid;
                border-color: black;
                border-radius: 7px;
                border-width: 2px;
                text-align: center;
            }
            QProgressBar::chunk {
                width: 2px;
                background-color: green;
                margin: 0px;
            }
            QLineEdit {
                background-color: white;
            }
            QSpinBox {
                background-color: white;
            }
            .QPushButton {
                font-size:16px !important;
            }
            .QPushButton:hover {
                background-color: rgb(247, 174, 175);
                font-size:16px !important;
            }
            .QLabel {
                font-size:16px !important;
                font-weight: bold;
                }
            .QToolbar {
                font-size:16px !important;
            }
        """
        self.setStyleSheet(qss_bright_view)


if __name__ == "__main__":
    # Create the QApplication instance
    app = QApplication(sys.argv)
    # Create the main window
    window = TabbedWindow()
    # Show the window
    window.show()
    # Start the event loop
    sys.exit(app.exec())
