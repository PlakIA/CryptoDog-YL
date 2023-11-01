from datetime import date

from PyQt5.QtCore import QDate, Qt
from PyQt5.QtWidgets import QMainWindow, QMessageBox

import main
from ui.cert_create import Ui_MainWindow


class MainForm(QMainWindow, Ui_MainWindow):
    def __init__(self, *args):
        super().__init__()
        self.setupUi(self)

        self.dateEdit.setDisabled(True)
        self.dateEdit.setDate(QDate(date.today().year + 5, date.today().month, date.today().day))
        self.lineEdit_passwd.setDisabled(True)
        self.checkBox_valid.clicked.connect(self.check)
        self.checkBox_passwd.clicked.connect(self.check)
        self.buttonDialog.rejected.connect(self.close)
        self.buttonDialog.accepted.connect(self.data_return)

    def message_display(self, title, text, msg_type=QMessageBox.Critical):
        msg = QMessageBox()
        with open('ui/theme_resources/stylesheet.qss', 'r', encoding='utf8') as f:
            msg.setStyleSheet(f.read())
        msg.setWindowTitle(title)
        msg.setText(text)
        msg.setIcon(msg_type)
        msg.exec_()

    def check(self):
        if self.sender().text() == self.checkBox_valid.text():
            if Qt.Checked == self.sender().checkState():
                self.dateEdit.setEnabled(True)
            else:
                self.dateEdit.setDisabled(True)
        elif self.sender().text() == self.checkBox_passwd.text():
            if Qt.Checked == self.sender().checkState():
                self.lineEdit_passwd.setEnabled(True)
            else:
                self.lineEdit_passwd.setDisabled(True)
                self.lineEdit_passwd.setText('')

    def data_return(self):
        data = {'name': self.lineEdit_name.text(),
                'email': self.lineEdit_email.text(),
                'method': self.comboBox_metod.currentText(),
                'is_date': True if self.checkBox_valid.checkState() == Qt.Checked else False,
                'is_passwd': True if self.checkBox_passwd.checkState() == Qt.Checked else False,
                'date': self.dateEdit.date().toPyDate(),
                'passwd': self.lineEdit_passwd.text()
                }
        if data['email'] in ('anya@hack.me', 'anna@hack.me') and data['name'] in ('Anya', 'Аня', 'Anna', 'Анна'):
            self.close()
            self.message_display('Horror', 'Have you ever felt sad?', msg_type=QMessageBox.Critical)
            return
        if data['name'] == '':
            self.message_display('Invalid input', 'Please enter your real name')
        elif data['email'] == '' or '@' not in data['email']:
            self.message_display('Invalid input', 'Please enter a valid email')
        elif data['is_date'] and data['date'] <= date.today().today():
            self.message_display('Invalid input', 'Please enter a valid date')
        elif data['is_passwd'] and data['passwd'] == '':
            self.message_display('Invalid input', 'Please enter your password')
        else:
            self.mainform = main.MainForm()
            self.mainform.new_cert(data)
            self.close()
