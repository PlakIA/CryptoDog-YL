import sqlite3
import pyperclip

from PyQt5.QtWidgets import QMainWindow, QInputDialog, QMessageBox
from ui.notepad import Ui_MainWindow
import gnupg


class MainForm(QMainWindow, Ui_MainWindow):
    def __init__(self, *args):
        super().__init__()

        self.gpg = gnupg.GPG(gnupghome='gpghome')
        self.gpg.encoding = 'utf-8'

        self.connection = sqlite3.connect("database.sqlite")
        self.cursor = self.connection.cursor()

        self.setupUi(self)
        self.btn_encrypt.clicked.connect(self.encrypt)
        self.btn_decrypt.clicked.connect(self.decrypt)
        self.btn_copy.clicked.connect(lambda: pyperclip.copy(self.plainTextEdit.toPlainText()))

    def closeEvent(self, event):
        self.connection.close()

    def message_display(self, title, text, msg_type=QMessageBox.Warning, details=None):
        msg = QMessageBox()
        msg.setWindowTitle(title)
        with open('ui/theme_resources/stylesheet.qss', 'r', encoding='utf8') as f:
            msg.setStyleSheet(f.read())
        msg.setText(text)
        if details:
            msg.setDetailedText(details)
        msg.setIcon(msg_type)
        msg.exec_()

    def encrypt(self):
        result = self.cursor.execute('''SELECT uid FROM Certificates''').fetchall()
        if not result:
            self.message_display('Error', "You don't have public certificates")
            return
        certs = list()
        for i in result:
            certs.append(*i)

        cert, ok_pressed = QInputDialog.getItem(self, "Encryption", "Encrypt for:", certs, 0, False)
        if ok_pressed:
            recipient = self.cursor.execute('''SELECT fingerprint FROM Certificates WHERE uid = ?''',
                                            (cert,)).fetchall()[0][0]
            crypted = self.gpg.encrypt(self.plainTextEdit.toPlainText(), recipients=recipient, always_trust=True)
            self.plainTextEdit.setPlainText(str(crypted))

    def decrypt(self):
        result = self.cursor.execute('''SELECT * FROM Certificates WHERE type = "secret"''').fetchall()
        if not result:
            self.message_display('Error', "You don't have secret certificates")
            return
        passwd, ok_pressed = QInputDialog.getText(self, 'Passphrase Request', 'Please enter your passphrase')
        if ok_pressed:
            decrypted = self.gpg.decrypt(self.plainTextEdit.toPlainText(), always_trust=True, passphrase=passwd)
            if not decrypted.ok:
                self.message_display('Fail', 'Failed to decrypt', msg_type=QMessageBox.Critical)
            else:
                self.plainTextEdit.setPlainText(str(decrypted))
