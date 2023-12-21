# net ranger is an IPv4/IPv6 subnet calculation tool. 
# Both IPv4 and IPv6 networks are calculated based on the IP address and subnet mask provided.
# IP Scraper will find and return all valid IPv4 and IPv6 addresses from a text input.
# CIDR Collapse will collapse all IPv4 and IPv6 CIDRs to the smallest possible CIDR.

# ::Import::
import sys
import ipaddress
import re
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
    QToolBar,
    QTextEdit,
    QGridLayout,
    QWidget,
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

class IP_calculate(QRunnable):

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
        try:
            start_time = dt.now()
            ip_addr = ipaddress.ip_address(self.ip)
            global_ip = ip_addr.is_global
            multicast_ip = ip_addr.is_multicast
            private_ip = ip_addr.is_private
            reserved_ip = ip_addr.is_reserved
            unspecified_ip = ip_addr.is_unspecified
            loopback_ip = ip_addr.is_loopback
            link_local = ip_addr.is_link_local
            ip_net = ipaddress.ip_network(f'{self.ip}/{self.ip_cidr}', strict=False)
            ip_host_list = list(ip_net.hosts()) 
            first_host = ip_host_list[0]
            last_host = ip_host_list[-1]
            total_hosts = '{:,}'.format(len(ip_host_list))
            end_time = dt.now()
            total_time = end_time - start_time
            self.net_range = f'IP Address:  {ip_addr}\nGlobal IP:   {global_ip}\nPrivate IP:   {private_ip}\nMulticast IP:   {multicast_ip}\nReserved IP:   {reserved_ip}\nUnspecified IP:   {unspecified_ip}\nLoopback Address:   {loopback_ip}\nLink Local:   {link_local}\nIP Subnet:  {ip_net}\nFirst Host:  {first_host}\nLast Host:  {last_host}\nTotal Hosts:  {total_hosts}\nTotal Calculation Time:  {total_time.total_seconds()} seconds'
            self.signals.result.emit(self.net_range)
        except Exception as e:
            self.signals.error.emit(f'Invalid IP address, please try again --> {e}')


# ::View::
class Window(QMainWindow):
    def __init__(self):
        super().__init__()
        # self.setFixedSize(1000, 700)
        self.threadpool = QThreadPool()
        self.setWindowTitle('Net')
        self.setFont(QFont('Arial', 14))
        #
        widget = QWidget(self)
        layout = QGridLayout(widget)
        #
        self.ip_ver_btn = QPushButton('Press to Toggle IP Version', self)
        self.ip_ver_btn.setFixedWidth(230)
        self.ip_ver_btn.clicked.connect(self.ip_version)
        layout.addWidget(self.ip_ver_btn, 0, 0)
        #
        self.output_text = QTextEdit()
        self.output_text.setPlaceholderText('Output')
        self.output_text.setAlignment(Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.output_text, 1, 0, 1, 4)
        #        
        self.ip_entry = QLineEdit(self)
        self.ip_entry.setPlaceholderText('IP Address')
        layout.addWidget(self.ip_entry, 0, 1)
        self.ip_entry.setDisabled(True)
        #
        self.cidr_label = QLabel('CIDR', self)
        self.cidr_label.setText('CIDR')
        layout.addWidget(self.cidr_label, 0, 2)
        #
        self.cidr_entry = QSpinBox(self)
        self.cidr_entry.setDisabled(True)
        self.cidr_entry.setAccelerated(True)
        self.cidr_entry.setAlignment(Qt.AlignmentFlag.AlignRight)
        layout.addWidget(self.cidr_entry, 0, 3)
        #
        self.setCentralWidget(widget)
        self._createStatusBar() 
        self._createActions()
        self._createToolBars()
        self._connectActions()
        
    def _createStatusBar(self):
        '''
        Status Bar
        '''
        self.statusbar = self.statusBar()
        self.statusbar.showMessage('CyberAssist == Net')

    def _createToolBars(self):
        '''
        Main toolbar widgets connected to actions
        '''

        self.main_toolbar = QToolBar('Calculate', self)
        self.main_toolbar.setMovable(False)
        self.addToolBar(Qt.ToolBarArea.LeftToolBarArea, self.main_toolbar)
        #
        self.main_toolbar.addAction(self.ip_calc_action)
        self.main_toolbar.addSeparator()
        #
        self.main_toolbar.addAction(self.cidr_collapse_action)
        self.main_toolbar.addSeparator()
        #
        self.main_toolbar.addAction(self.ip_address_scraper)
        self.main_toolbar.addSeparator()
        #
        self.main_toolbar.addAction(self.copyAction)
        self.main_toolbar.addSeparator()
        self.main_toolbar.addAction(self.clear_outputAction)

    # ::Control Section::
                                                                                                                                   
    def _createActions(self):      
        '''
        Event driven actions
        '''
        self.ip_calc_action = QAction('Calculate &IP Subnet', self)
        self.ip_calc_action.setDisabled(True)
        self.cidr_collapse_action = QAction('Collapse &CIDRs')
        self.ip_address_scraper = QAction('Scrape IP Addresses', self)
        self.copyAction = QAction('C&opy Output', self)
        self.clear_outputAction = QAction('Clear &Output', self)
       
    # ::Action Slots::
    def _connectActions(self):
        '''
        Event actions
        '''
        self.ip_calc_action.triggered.connect(self.calc_ip)
        self.cidr_collapse_action.triggered.connect(self.collapse_ip_subnets)
        self.ip_address_scraper.triggered.connect(self.scrape_ip_address)
        self.copyAction.triggered.connect(self.copy_content)
        self.clear_outputAction.triggered.connect(self.clear_output)


    def ip_version(self):
        '''
        Set IP Address to IPv4 or IPv6, default is IPv4, and set CIDR range to 32 or 128
        '''
        if self.ip_ver_btn.text() == 'Press to Toggle IP Version':
            self.ip_calc_action.setDisabled(False)
            self.ip_entry.setDisabled(False)
            self.ip_ver_btn.setText('IPv4')
            self.ip_entry.setFocus()
            self.ip_entry.setPlaceholderText('Input IPv4 Address')
            self.cidr_entry.setDisabled(False)
            self.cidr_entry.setRange(0,32)
        elif self.ip_ver_btn.text() == 'IPv4':
            self.ip_calc_action.setDisabled(False)
            self.ip_entry.setDisabled(False)
            self.ip_ver_btn.setText('IPv6')
            self.ip_entry.setFocus()
            self.ip_entry.setPlaceholderText('Input IPv6 Address')
            self.cidr_entry.setDisabled(False)
            self.cidr_entry.setRange(0,128)
        elif self.ip_ver_btn.text() == 'IPv6':
            self.ip_calc_action.setDisabled(True)
            self.ip_entry.setDisabled(True)
            self.ip_ver_btn.setText('Press to Toggle IP Version')
            self.ip_entry.setPlaceholderText('IP Address')
            self.cidr_entry.setRange(0,0)
            self.cidr_entry.setDisabled(True)

    def calc_ip(self):
        '''
        Calculate IP netowrk range
        '''
        self.output_text.clear()
        ip = self.ip_entry.text()
        ip_cidr = self.cidr_entry.text()
        ip_calculate = IP_calculate(ip, ip_cidr)
        ip_calculate.signals.result.connect(self.calc_output)
        ip_calculate.signals.error.connect(self.calc_output)  
        self.threadpool.setMaxThreadCount(5)    
        self.threadpool.start(ip_calculate)
        self.ip_calc_action.setDisabled(True)

    def collapse_ip_subnets(self):
        '''
        Collapse IP subnet CIDRs
        '''
        title = "Collapse CIDRs"
        label = "Collapse IPv4 and/or IPv6 CIDRs"
        text = "Input text containting IPv4 or IPv6 CIDRs"
        ip_collapse_multiline, ok = QInputDialog.getMultiLineText(self, title, label, text)
        text_search = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}')
        cidr_list = text_search.findall(ip_collapse_multiline)
        cidr_validated_list = []
        for cidr in cidr_list:
            try:
                cidr = ipaddress.ip_network(cidr)
                cidr_validated_list.append(cidr)
            except ValueError as e:
                self.output_text.insertPlainText(f'{cidr} is not a valid IP CIDR\n')
        collapsed_cidr = ipaddress.collapse_addresses(cidr_validated_list)
        self.output_text.insertPlainText('\nCollapsed CIDRs\n')
        for collapsed in collapsed_cidr:
            self.output_text.insertPlainText(f'{collapsed}\n')

    def scrape_ip_address(self):
        '''
        Scrapes IPv4 and IPv6 addresses from a text file.
        Return formatted lists of IPv4 and IPv6 addresses.
        '''
        # ::Regex for Scraper::
        ipv4_addr = re.compile(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
        ipv6_standard_compressed = re.compile('(([A-F0-9]{1,4}:){7}[A-F0-9]{1,4}|(?=([A-F0-9]{0,4}:){0,7}[A-F0-9]{0,4}(?![:.\w]))(([0-9A-F]{1,4}:){1,7}|:)((:[0-9A-F]{1,4}){1,7}|:)|([A-F0-9]{1,4}:){7}:|:(:[A-F0-9]{1,4}){7})', re.IGNORECASE)
        ipv6_mixed_compressed = re.compile('(?:(?:[a-fA-F0-9]{1,4}:){6}|(?=(?:[a-fA-F0-9]{0,4}:){0,6}(?:[0-9]{1,3}\.){3}[0-9]{1,3})(([a-fA-F0-9]{1,4}:){0,5}|:)((:[a-fA-F0-9]{1,4}){1,5}:|:)|::(?:[a-fA-F0-9]{1,4}:){5})(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])', re.IGNORECASE)

        scrape_title = "IP Address Search"
        label = "Retrieve IPv4 and/or IPv6 addresses"
        scrape_text = "Paste in text containting IPv4 or IPv6 addresses"
        ip_input_text, ok = QInputDialog.getMultiLineText(self, scrape_title, label, scrape_text)
        sep_title = 'Enter a separation character'
        sep_label = '(, ; | or press enter for space delimited)'
        ip_separator, ok = QInputDialog.getText(self, sep_title, sep_label)
        
        if ip_separator == '':
            ip_separator = ' '
        
        ipv4_list = []
        split_list = ip_input_text.split(ip_separator)
        for item in split_list:
            ipv4_result = ipv4_addr.fullmatch(item)
            if ipv4_result:
                ipv4_list.append(ipv4_result.group())
        
        standard_compressed_list = []
        split_list = ip_input_text.split(ip_separator)
        for item in split_list:
            std_result = ipv6_standard_compressed.fullmatch(item)
            if std_result:
                standard_compressed_list.append(std_result.group())
        
        mixed_compressed_list = []
        split_list = ip_input_text.split(ip_separator)
        for item in split_list:
            mixed_compressed_result = ipv6_mixed_compressed.fullmatch(item)
            if mixed_compressed_result:
                mixed_compressed_list.append(mixed_compressed_result.group())
        
        ipv4_text_block = '\n'.join(ipv4_list)
        standard_compressed_text_block = '\n'.join(standard_compressed_list)
        mixed_notation_text_block = '\n'.join(mixed_compressed_list)
        
        scraped_ip_text = f'IPv4 Addresses:\n{ipv4_text_block}\n\nStandard and Compressed IPv6 Addresses:\n{standard_compressed_text_block}\n\nMixed and Mixed Compressed IPv6 Addresses:\n{mixed_notation_text_block}'
        self.output_text.clear()
        self.output_text.insertPlainText(scraped_ip_text)
        
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


    def calc_output(self, s):
        '''
        Show calculation in output
        '''
        self.output_text.insertPlainText(s)
        self.ip_entry.clear()
        self.cidr_entry.clear()
        self.ip_entry.setFocus()
        self.ip_calc_action.setDisabled(False)


# ::Run Main::
if __name__ == '__main__':
    app = QApplication(sys.argv)
    # app.setStyle('Fusion')
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
    win.setWindowTitle('IP Subnet Helper')
    # base = win.baseSize()
    # win.setBaseSize(base)
    win.show()
    win.ip_entry.setFocus()
    sys.exit(app.exec())
