import sqlite3

import pyperclip
from PyQt5.QtWidgets import QMainWindow, QInputDialog

from ui.select_password import Ui_MainWindow


class MainForm(QMainWindow, Ui_MainWindow):
    def __init__(self, *args):
        super().__init__()

        self.connection = sqlite3.connect('database.sqlite')
        self.cursor = self.connection.cursor()

        self.setupUi(self)
        self.buttonBox.rejected.connect(self.close)
        self.btn_add.clicked.connect(self.add_item)
        self.btn_delete.clicked.connect(self.delete_item)
        self.btn_edit.clicked.connect(self.edit_item)
        self.buttonBox.accepted.connect(self.send_passwd)

        self.update_list()

    def closeEvent(self, event):
        self.connection.close()

    def update_list(self):
        self.comboBox.clear()
        self.comboBox.insertItem(0, '-')
        result = self.cursor.execute('''SELECT password FROM Passwords''').fetchall()
        for index, value in enumerate(result, start=1):
            self.comboBox.insertItem(index, *value)

    def add_item(self):
        passwd, ok_pressed = QInputDialog.getText(self, 'Add password', 'Please enter password to save')
        if passwd:
            self.cursor.execute('''INSERT INTO Passwords(password) VALUES(?)''', (passwd,))
            self.connection.commit()
            self.update_list()

    def delete_item(self):
        if self.comboBox.currentText() != '-':
            self.cursor.execute('''DELETE FROM Passwords WHERE password = ?''',
                                (self.comboBox.currentText(),))
            self.connection.commit()
            self.update_list()

    def edit_item(self):
        if self.comboBox.currentText() != '-':
            passwd, ok_pressed = QInputDialog.getText(self, 'Edit password',
                                                      f'Change saved password <{self.comboBox.currentText()}> to:')
            if passwd:
                self.cursor.execute('''UPDATE Passwords SET password = ? WHERE password = ?''',
                                    (passwd, self.comboBox.currentText()))
                self.connection.commit()
                self.update_list()

    def send_passwd(self):
        pyperclip.copy(self.comboBox.currentText())
        self.close()
