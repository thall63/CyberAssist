# net ranger is an IPv4/IPv6 subnet calculation tool. 
# Both IPv4 and IPv6 networks are calculated based on the IP address and subnet mask provided.
# IP Scraper will find and return all valid IPv4 and IPv6 addresses from a text input.
# CIDR Collapse will collapse IPv4 CIDRs to the smallest possible CIDR.

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


# ::View::
class Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.threadpool = QThreadPool()
        self.setWindowTitle('Net')
        self.setFont(QFont('Arial', 12))
        #
        widget = QWidget(self)
        layout = QGridLayout(widget)
        #
        self.ip_ver_btn = QPushButton('IPv6', self)
        self.ip_ver_btn.setStyleSheet('background-color: #f0f0f0')
        self.ip_ver_btn.clicked.connect(self.ip_version)
        layout.addWidget(self.ip_ver_btn, 0, 0)
        #
        self.ip_calc_btn = QPushButton('Calculate IP Range', self)
        self.ip_calc_btn.setStyleSheet('background-color: #f0f0f0')
        self.ip_calc_btn.clicked.connect(self.calc_ip)
        layout.addWidget(self.ip_calc_btn, 0, 4)
        #
        self.output_text = QTextEdit()
        self.output_text.setPlaceholderText('Output')
        self.output_text.setAlignment(Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.output_text, 1, 0, 1, 5)
        #        
        self.ip_entry = QLineEdit(self)
        self.ip_entry.setPlaceholderText('Input IPv4 Address')
        layout.addWidget(self.ip_entry, 0, 1)
        #
        self.cidr_label = QLabel('Prefix', self)
        self.cidr_label.setText('Prefix')
        layout.addWidget(self.cidr_label, 0, 2)
        #
        self.cidr_entry = QSpinBox(self)
        self.cidr_entry.setAccelerated(True)
        self.cidr_entry.setStyleSheet('background-color: #f0f0f0')
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
        self.main_toolbar.setStyleSheet('background-color: #f0f0f0')
        self.addToolBar(Qt.ToolBarArea.LeftToolBarArea, self.main_toolbar)
        #
        self.main_toolbar.addAction(self.cidr_collapse_action)
        self.main_toolbar.addSeparator()
        #   
        self.main_toolbar.addAction(self.collapsed_ipv6_prefixes)
        self.main_toolbar.addSeparator()
        #
        self.main_toolbar.addAction(self.ip_address_scraper)
        self.main_toolbar.addSeparator()
        #
        self.main_toolbar.addAction(self.copyAction)
        self.main_toolbar.addSeparator()
        self.main_toolbar.addAction(self.clear_outputAction)
        self.main_toolbar.addSeparator()
        self.main_toolbar.addAction(self.view_modeAction)


    # ::Control Section::
                                                                                                                                   
    def _createActions(self):      
        '''
        Event driven actions
        '''
        self.cidr_collapse_action = QAction('Collapse IPv4 &CIDRs')
        self.collapsed_ipv6_prefixes = QAction('Collapse IPv6 Prefixes')
        self.ip_address_scraper = QAction('Scrape \nIPv4 and IPv6 \nAddresses', self)
        self.copyAction = QAction('C&opy Output', self)
        self.clear_outputAction = QAction('Clear &Output', self)
        self.view_modeAction = QAction('Moon View', self)
       
    # ::Action Slots::
    def _connectActions(self):
        '''
        Event actions
        '''
        self.ip_calc_btn.clicked.connect(self.calc_ip)
        self.cidr_collapse_action.triggered.connect(self.collapse_ip_subnets)
        self.collapsed_ipv6_prefixes.triggered.connect(self.collapse_ipv6_prefixes)
        self.ip_address_scraper.triggered.connect(self.scrape_ip_address)
        self.copyAction.triggered.connect(self.copy_content)
        self.clear_outputAction.triggered.connect(self.clear_output)
        self.view_modeAction.triggered.connect(self.view_mode)


    def ip_version(self):
        '''
        Set IP Address to IPv4 or IPv6, default is IPv4, and set CIDR range to 32 or 128
        '''
        if self.ip_ver_btn.text() == 'IPv6':
            self.clear_output()
            self.ip_ver_btn.setText('IPv4')
            self.ip_entry.setFocus()
            self.ip_entry.setPlaceholderText('Input IPv6 Address')
            self.cidr_entry.setRange(0,128)
        elif self.ip_ver_btn.text() == 'IPv4':
            self.clear_output()
            self.ip_ver_btn.setText('IPv6')
            self.ip_entry.setPlaceholderText('Input IPv4 Address')
            self.cidr_entry.setRange(0,32)

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

    def collapse_ip_subnets(self):
        '''
        Collapse IP subnet CIDRs
        '''
        self.output_text.clear()
        title = "Collapse CIDRs"
        label = "Collapse IPv4 CIDRs"
        text = "Input text containting IPv4 CIDRs"
        ip_cidr_entry, ok = QInputDialog.getMultiLineText(self, title, label, text)
        cidr_list = []
        if ok == False:
            return
        sep, ok = QInputDialog.getText(self, "Separator", "Are the IP comma delimited? (y/n)")
        if sep == 'y':
            cidr_list = ip_cidr_entry.split(',')
        else:
            cidr_list = ip_cidr_entry.split() 
        cidr_validated_list = []
        cidr_invalidated_list = []
        for item in cidr_list:
            try:
                cidr = ipaddress.ip_network(item, strict=False)
                cidr_validated_list.append(cidr)
            except ValueError as e:
                cidr_invalidated_list.append(item)
        collapsed_cidr = ipaddress.collapse_addresses(cidr_validated_list)
        collapsed_cidr = '\n'.join(str(item) for item in collapsed_cidr)
        self.output_text.insertPlainText(f'Collapsed CIDRs\n{collapsed_cidr}\n')
        invalid_cidr = '\n'.join(cidr_invalidated_list)
        self.output_text.insertPlainText(f'\nInvalid CIDRs\n{invalid_cidr}')


    def collapse_ipv6_prefixes(self):
        '''
        Collapse IPv6 prefix CIDRs
        '''
        self.output_text.clear()
        title = "Collapse CIDRs"
        label = "Collapse IPv6 CIDRs"
        text = "Input text containting IPv6 CIDRs"
        ipv6_entry, ok = QInputDialog.getMultiLineText(self, title, label, text)
        if ok == False:
            return
        split_list = ipv6_entry.split()
        prefix_validated_list = []
        prefix_invalidated_list = []
        for item in split_list:
            try:
                ipv6_net = ipaddress.ip_network(f'{item}', strict=False)
                if ipv6_net:
                    prefix_validated_list.append(ipv6_net)
            except ValueError as e:
                prefix_invalidated_list.append(item)
        collapsed_ipv6_prefixes = ipaddress.collapse_addresses(prefix_validated_list)
        collapsed_ipv6_prefixes = '\n'.join(str(item) for item in collapsed_ipv6_prefixes)
        self.output_text.insertPlainText(f'Collapsed IPv6 Prefixes\n{collapsed_ipv6_prefixes}\n')
        invalid_ipv6_prefixes = '\n'.join(str(item) for item in prefix_invalidated_list)
        self.output_text.insertPlainText(f'\nInvalid IPv6 Prefixes\n{invalid_ipv6_prefixes}')   


    def scrape_ip_address(self):
        '''
        Scrapes IPv4 and IPv6 addresses from a text file.
        Return formatted lists of IPv4 and IPv6 addresses.
        '''
        # Clear output text
        self.output_text.clear()

        # ::Regex for Scraper::
        ipv4_addr = re.compile(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
        ipv6_standard_compressed = re.compile('(([A-F0-9]{1,4}:){7}[A-F0-9]{1,4}|(?=([A-F0-9]{0,4}:){0,7}[A-F0-9]{0,4}(?![:.\w]))(([0-9A-F]{1,4}:){1,7}|:)((:[0-9A-F]{1,4}){1,7}|:)|([A-F0-9]{1,4}:){7}:|:(:[A-F0-9]{1,4}){7})', re.IGNORECASE)
        ipv6_mixed_compressed = re.compile('(?:(?:[a-fA-F0-9]{1,4}:){6}|(?=(?:[a-fA-F0-9]{0,4}:){0,6}(?:[0-9]{1,3}\.){3}[0-9]{1,3})(([a-fA-F0-9]{1,4}:){0,5}|:)((:[a-fA-F0-9]{1,4}){1,5}:|:)|::(?:[a-fA-F0-9]{1,4}:){5})(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])', re.IGNORECASE)

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
        self.output_text.clear()
        # Consider not printing scraped lists that are empty
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
        self.ip_calc_btn.setDisabled(False)

    def view_mode(self):
        '''
        Sun or Moon Mode
        '''
        mode = self.view_modeAction.text()
        if mode == 'Sun View':
            self.view_modeAction.setText('Moon View')
            self.sun_palette = QPalette()
            self.sun_palette.setColor(QPalette.ColorRole.Base, Qt.GlobalColor.white)
            self.sun_palette.setColor(QPalette.ColorRole.Window, Qt.GlobalColor.white)
            self.sun_palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.black)
            self.sun_palette.setColor(QPalette.ColorRole.Button, Qt.GlobalColor.white)
            self.sun_palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.black)
            self.sun_palette.setColor(QPalette.ColorRole.PlaceholderText, Qt.GlobalColor.darkGray)
            self.sun_palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, Qt.GlobalColor.black)
            self.setPalette(self.sun_palette)
        elif mode == 'Moon View':
            self.view_modeAction.setText('Sun View')
            self.moon_palette = QPalette()
            self.moon_palette.setColor(QPalette.ColorRole.Base, Qt.GlobalColor.transparent)
            self.moon_palette.setColor(QPalette.ColorRole.Window, Qt.GlobalColor.gray)
            self.moon_palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.black)
            self.moon_palette.setColor(QPalette.ColorRole.Button, Qt.GlobalColor.white)
            self.moon_palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.black)
            self.moon_palette.setColor(QPalette.ColorRole.PlaceholderText, Qt.GlobalColor.darkGray)
            self.moon_palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, Qt.GlobalColor.black)
            self.setPalette(self.moon_palette)


# ::Run Main::
if __name__ == '__main__':
    app = QApplication(sys.argv)    # app.setStyle('Fusion')
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Base, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.Window, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.black)
    palette.setColor(QPalette.ColorRole.Button, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.black)
    palette.setColor(QPalette.ColorRole.PlaceholderText, Qt.GlobalColor.darkGray)
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, Qt.GlobalColor.black)
    app.setPalette(palette)
    win = Window()
    win.setWindowTitle('Net')
    win.show()
    win.ip_entry.setFocus()
    sys.exit(app.exec())
