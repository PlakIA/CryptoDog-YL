import hashlib
import os
import sqlite3
import sys
import webbrowser
from datetime import datetime

import gnupg
import pyperclip
from PyQt5.QtGui import QIcon, QPixmap, QImage
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidgetItem, QFileDialog, QInputDialog, QMessageBox

import newkey_form
import notepad
from ui import main, about
from crypto.keyless import Hash, B64
from crypto.symmetric import AESx, SingleDES, TripleDES, RC4


class MainForm(QMainWindow, main.Ui_MainWindow):
    def __init__(self):
        super().__init__()

        if not os.path.exists('gpghome'):
            os.mkdir('gpghome')
        self.gpg = gnupg.GPG(gnupghome='gpghome')
        self.gpg.encoding = 'utf-8'

        if not os.path.exists('database.sqlite'):
            self.message_display('Critical Error', 'Database file not found', msg_type=QMessageBox.Critical)
            self.close()
        self.connection = sqlite3.connect("database.sqlite")
        self.cursor = self.connection.cursor()

        self.setupUi(self)
        self.setWindowIcon(QIcon('ui/images/icon.ico'))
        self.nokey_comboBox.textActivated.connect(self.nokey_combobox_update)
        self.nokey_btn_encrypt.clicked.connect(self.keyless_encryption)
        self.nokey_btn_decrypt.clicked.connect(self.b64_decryption)
        self.nokey_btn_copy.clicked.connect(lambda: pyperclip.copy(self.nokey_textEdit_output.toPlainText()))

        self.sym_comboBox.textActivated.connect(self.sym_combobox_update)
        self.sym_btn_encrypt.clicked.connect(self.symmetric_encryption)
        self.sym_btn_decrypt.clicked.connect(self.symmetric_decryption)
        self.sym_btn_copy.clicked.connect(lambda: pyperclip.copy(self.sym_textEdit_output.toPlainText()))

        self.actionAbout.triggered.connect(self.view_about)
        self.actionQuit.triggered.connect(self.close)
        self.actionNew_OpenPGP_key_pair.triggered.connect(self.call_newcert)
        self.actionImport.triggered.connect(self.import_key)
        self.actionPublic_Key.triggered.connect(self.export_public)
        self.actionSecret_Key.triggered.connect(self.export_secret)
        self.actionDelete.triggered.connect(self.delete_certificate)
        self.actionDatabase_Update.triggered.connect(self.db_update)
        self.actionGitHub_Page.triggered.connect(lambda: webbrowser.open('https://github.com/PlakIA/CryptoDog'))
        self.actionEncrypt.triggered.connect(self.encrypt)
        self.actionDecrypt.triggered.connect(self.decrypt)
        self.actionSign.triggered.connect(self.sign)
        self.actionVerify.triggered.connect(self.verify)
        self.actionNotepad.triggered.connect(self.notepad_mode)
        self.actionCreate_Checksum_File.triggered.connect(self.create_checksum_file)
        self.actionVerify_Checksum_File.triggered.connect(self.verify_checksum_file)

        self.db_update()

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

    def notepad_mode(self):
        self.notepad_form = notepad.MainForm(self, '')
        self.notepad_form.show()

    def view_about(self):
        self.about_form = AboutForm(self, "")
        self.about_form.show()

    def create_checksum_file(self):
        filepath = QFileDialog.getOpenFileName(self, 'Select File to Create Checksum', '',
                                               'All files (*))')[0]
        if not filepath:
            return

        BUFFER_SIZE = 65536
        with open(filepath, 'rb') as f:
            hash_object = hashlib.sha256()
            while True:
                data = f.read(BUFFER_SIZE)
                if not data:
                    break
                hash_object.update(data)

        with open('/'.join(filepath.split('/')[:-1]) + '/checksum_sha256.txt', 'w', encoding='utf8') as f:
            f.write(hash_object.hexdigest() + '\t' + filepath)

    def verify_checksum_file(self):
        filepath = QFileDialog.getOpenFileName(self, 'Select Checksum File to Verify', '',
                                               'Text files (*.txt);;Any files (*))')[0]
        if not filepath:
            return

        with open(filepath, 'r', encoding='utf8') as f:
            try:
                checksum, data_filepath = f.read().split('\t')
            except ValueError:
                self.message_display('Fail', 'Wrong checksum file')
                return
            if not os.path.exists(data_filepath):
                user_response = QMessageBox.question(self, 'File not found',
                                                     "The file specified in the checksum file was not found\n"
                                                     "Do you want to specify the path to the file?",
                                                     QMessageBox.Yes | QMessageBox.Cancel,
                                                     QMessageBox.Cancel)

                if user_response == QMessageBox.Yes:
                    data_filepath = QFileDialog.getOpenFileName(self, 'Select File to Verify', '',
                                                                'All files (*))')[0]
                else:
                    return

        BUFFER_SIZE = 65536
        with open(data_filepath, 'rb') as f:
            hash_object = hashlib.sha256()
            while True:
                data = f.read(BUFFER_SIZE)
                if not data:
                    break
                hash_object.update(data)

        if hash_object.hexdigest() == checksum:
            self.message_display('Good', 'The file is not damaged', msg_type=QMessageBox.Information)
        else:
            self.message_display('Failed', 'The file is damaged!', msg_type=QMessageBox.Critical)

    def nokey_combobox_update(self):
        self.nokey_textEdit_output.setPlainText('')
        self.nokey_textEdit_output.setStyleSheet('')
        self.nokey_label_warn.resize(160, 60)
        self.nokey_label_warn.setPixmap(QPixmap(''))
        self.nokey_label_warn.setText('')
        if self.nokey_comboBox.currentText() == 'Base64':
            self.nokey_btn_decrypt.setVisible(True)
            self.nokey_btn_decrypt.setEnabled(True)
            self.nokey_btn_encrypt.setText('Encode')
            self.nokey_btn_decrypt.setText('Decode')
        else:
            self.nokey_btn_encrypt.setText('Hash')
            self.nokey_btn_decrypt.setVisible(False)
            self.nokey_btn_decrypt.setDisabled(True)

    def keyless_encryption(self):
        self.nokey_label_warn.resize(160, 60)
        self.nokey_label_warn.setPixmap(QPixmap(''))
        self.nokey_label_warn.setText('')
        self.nokey_label_warn.setStyleSheet('')
        self.nokey_textEdit_output.setStyleSheet('')
        if self.nokey_comboBox.currentText() == 'MD5':
            self.nokey_textEdit_output.setPlainText(Hash.md5(self.nokey_textEdit_input.toPlainText()))
        elif self.nokey_comboBox.currentText() == 'SHA1':
            self.nokey_textEdit_output.setPlainText(Hash.sha1(self.nokey_textEdit_input.toPlainText()))
        elif self.nokey_comboBox.currentText() == 'SHA256':
            self.nokey_textEdit_output.setPlainText(Hash.sha256(self.nokey_textEdit_input.toPlainText()))
        elif self.nokey_comboBox.currentText() == 'SHA512':
            self.nokey_textEdit_output.setPlainText(Hash.sha512(self.nokey_textEdit_input.toPlainText()))
        elif self.nokey_comboBox.currentText() == 'Base64':
            self.nokey_textEdit_output.setPlainText(B64.encode(self.nokey_textEdit_input.toPlainText()))

    def b64_decryption(self):
        result = B64.decode(self.nokey_textEdit_input.toPlainText())
        if result == 'Decoding error':
            self.nokey_label_warn.resize(160, 60)
            self.nokey_label_warn.setPixmap(QPixmap(''))
            self.nokey_label_warn.setText('Decoding error!')
            self.nokey_label_warn.setStyleSheet('color: #b39205;')
            self.nokey_textEdit_output.setPlainText('')
        elif result == 'Easter Egg':
            self.nokey_label_warn.resize(160, 60)
            self.nokey_label_warn.setPixmap(QPixmap(''))
            self.nokey_label_warn.setText(u'\u2665')
            self.nokey_textEdit_output.setPlainText(u'\u2665')
            self.nokey_textEdit_output.setStyleSheet('font-size: 18pt;')
            self.nokey_label_warn.setStyleSheet('font-size: 36pt; color: #d54653;')
        elif result == 'Easter Dog':
            self.nokey_label_warn.resize(162, 216)
            self.nokey_label_warn.setPixmap(QPixmap(QImage('ui/images/original.jpg').scaled(162, 216)))
            self.nokey_textEdit_output.setPlainText('')
        else:
            self.nokey_label_warn.resize(160, 60)
            self.nokey_label_warn.setPixmap(QPixmap(''))
            self.nokey_textEdit_output.setPlainText(result)
            self.nokey_label_warn.setText('')
            self.nokey_textEdit_output.setStyleSheet('')
            self.nokey_label_warn.setStyleSheet('')

    def sym_combobox_update(self):
        self.sym_label_warn.setText('')
        if self.sym_comboBox.currentText() not in ('AES128', 'AES192', 'AES256'):
            self.sym_label_warn.setStyleSheet('color: #b39205; font-size: 9pt;')
            self.sym_label_warn.setText('Attention!\nThe encryption method\nyou selected is outdated.'
                                        '\nIts use may not be safe.')

    def symmetric_encryption(self):
        self.sym_label_warn.setText('')
        key = self.sym_lineEdit_key.text()
        if self.sym_comboBox.currentText() == 'AES128':
            self.sym_textEdit_output.setPlainText(AESx(key).encrypt(self.sym_textEdit_input.toPlainText()))
        elif self.sym_comboBox.currentText() == 'AES192':
            self.sym_textEdit_output.setPlainText(
                AESx(key, key_size=192).encrypt(self.sym_textEdit_input.toPlainText()))
        elif self.sym_comboBox.currentText() == 'AES256':
            self.sym_textEdit_output.setPlainText(
                AESx(key, key_size=256).encrypt(self.sym_textEdit_input.toPlainText()))
        elif self.sym_comboBox.currentText() == 'DES':
            self.sym_textEdit_output.setPlainText(SingleDES(key).encrypt(self.sym_textEdit_input.toPlainText()))
        elif self.sym_comboBox.currentText() == '3DES':
            self.sym_textEdit_output.setPlainText(TripleDES(key).encrypt(self.sym_textEdit_input.toPlainText()))
        elif self.sym_comboBox.currentText() == 'RC4':
            self.sym_textEdit_output.setPlainText(RC4(key).encrypt(self.sym_textEdit_input.toPlainText()))

    def symmetric_decryption(self):
        key = self.sym_lineEdit_key.text()
        result = ''
        if self.sym_comboBox.currentText() == 'AES128':
            result = AESx(key).decrypt(self.sym_textEdit_input.toPlainText())
        elif self.sym_comboBox.currentText() == 'AES192':
            result = AESx(key, key_size=192).decrypt(self.sym_textEdit_input.toPlainText())
        elif self.sym_comboBox.currentText() == 'AES256':
            result = AESx(key, key_size=256).decrypt(self.sym_textEdit_input.toPlainText())
        elif self.sym_comboBox.currentText() == 'DES':
            result = SingleDES(key).decrypt(self.sym_textEdit_input.toPlainText())
        elif self.sym_comboBox.currentText() == '3DES':
            result = TripleDES(key).decrypt(self.sym_textEdit_input.toPlainText())
        elif self.sym_comboBox.currentText() == 'RC4':
            result = RC4(key).decrypt(self.sym_textEdit_input.toPlainText())

        if result == 'Decrypt error':
            self.sym_label_warn.setText('Decrypt error!')
            self.sym_label_warn.setStyleSheet('color: #b39205;')
            self.sym_textEdit_output.setPlainText('')
        else:
            self.sym_textEdit_output.setPlainText(result)
            self.sym_label_warn.setText('')
            self.sym_textEdit_output.setStyleSheet('')
            self.sym_label_warn.setStyleSheet('')

    def call_newcert(self):
        self.newcert_form = newkey_form.MainForm(self, '')
        self.newcert_form.show()

    def new_cert(self, data):
        ex_date = data['date'] if data['is_date'] else 0
        no_passwd = True if not data['is_passwd'] else False
        passwd = None if no_passwd else data['passwd']
        if data:
            if data['method'] == 'RSA':
                input_data = self.gpg.gen_key_input(key_type="RSA", key_length=2048, subkey_type='RSA',
                                                    subkey_length='2048',
                                                    name_real=data['name'], name_email=data['email'],
                                                    expire_date=ex_date, passphrase=passwd, no_protection=no_passwd)
            elif data['method'] == 'DSA':
                input_data = self.gpg.gen_key_input(key_type="DSA", key_length=2048, subkey_type='ELG-E',
                                                    subkey_length='2048',
                                                    name_real=data['name'], name_email=data['email'],
                                                    expire_date=ex_date, passphrase=passwd, no_protection=no_passwd)
            elif data['method'] == 'EDDSA':
                input_data = self.gpg.gen_key_input(key_type='EDDSA', key_curve='ed25519', subkey_type='ECDH',
                                                    subkey_curve='cv25519',
                                                    name_real=data['name'], name_email=data['email'],
                                                    expire_date=ex_date, passphrase=passwd, no_protection=no_passwd)

        generated = self.gpg.gen_key(input_data)
        if generated.status != 'ok':
            self.message_display('Error', 'Failed to create new certificate', msg_type=QMessageBox.Critical)
        self.db_update()

    def db_update(self):
        self.cursor.execute('''DELETE FROM Certificates''')
        for i in self.gpg.list_keys(secret=True):
            date = datetime.utcfromtimestamp(int(i['date'])).strftime('%Y-%m-%d')
            ex_date = datetime.utcfromtimestamp(int(i['expires'])).strftime('%Y-%m-%d') if i['expires'] else 'unlimited'
            self.cursor.execute('''INSERT INTO
                                        Certificates(keyid, type, uid, fingerprint, create_date, expire_date)
                                        VALUES(?, "secret", ?, ?, ?, ?)''',
                                (i['keyid'], *i['uids'], i['fingerprint'], date, ex_date))

        secrets_fingerprints = list()
        for i in self.cursor.execute('''SELECT fingerprint FROM Certificates WHERE type = "secret"''').fetchall():
            secrets_fingerprints.append(*i)
        for i in self.gpg.list_keys():
            if i['fingerprint'] in secrets_fingerprints:
                continue
            date = datetime.utcfromtimestamp(int(i['date'])).strftime('%Y-%m-%d')
            ex_date = datetime.utcfromtimestamp(int(i['expires'])).strftime('%Y-%m-%d') if i['expires'] else 'unlimited'
            self.cursor.execute('''INSERT INTO
                                        Certificates(keyid, type, uid, fingerprint, create_date, expire_date)
                                        VALUES(?, "public", ?, ?, ?, ?)''',
                                (i['keyid'], *i['uids'], i['fingerprint'], date, ex_date))

        self.connection.commit()

        result = self.cursor.execute('''SELECT uid, type, create_date, fingerprint FROM Certificates''').fetchall()
        self.gpg_tableWidget.setRowCount(0)
        for i, row in enumerate(result):
            self.gpg_tableWidget.setRowCount(
                self.gpg_tableWidget.rowCount() + 1)
            for j, elem in enumerate(row):
                self.gpg_tableWidget.setItem(
                    i, j, QTableWidgetItem(str(elem)))

    def import_key(self):
        filepath = QFileDialog.getOpenFileName(self, 'Select Certificate File', '',
                                               'Certificates (*.asc *.cer *.cert *.crt *.der *.pem *.gpg *.p7c *.p12'
                                               ' *.pfx *.pgp *.kgrp);;Any files (*))')[0]
        if not filepath:
            return

        imported = self.gpg.import_keys_file(filepath)
        if 'ok' not in imported.results[0].keys():
            self.message_display('Not imported', 'The certificate was not imported',
                                 details=imported.results[0]['text'])
            return
        self.gpg.trust_keys(imported.results[0]['fingerprint'], 'TRUST_FULLY')
        self.db_update()

        key_type = self.cursor.execute('''SELECT type FROM Certificates WHERE fingerprint = ?''',
                                       (imported.results[0]['fingerprint'],)).fetchall()[0][0]
        if key_type == 'secret':
            self.gpg.trust_keys(imported.results[0]['fingerprint'], 'TRUST_ULTIMATE')
            self.db_update()

    def export_public(self):
        result = self.cursor.execute('''SELECT * FROM Certificates''').fetchall()
        if not result:
            self.message_display('Error', "You don't have any certificates")
            return

        try:
            keyid = self.cursor.execute('''SELECT keyid FROM Certificates WHERE fingerprint = ?''',
                                        (self.gpg_tableWidget.selectedItems()[3].text(),)).fetchall()[0][0]
            path = QFileDialog.getSaveFileName(self, 'Export OpenPGP Certificates', 'public.asc',
                                               'OpenPGP Certificates (*.asc *.gpg *.pgp)')[0]
            if not path:
                return
            self.gpg.export_keys(keyid, output=path)
        except IndexError:
            self.message_display('Error', 'Please select a certificate to export')

    def export_secret(self):
        result = self.cursor.execute('''SELECT * FROM Certificates WHERE type = "secret"''').fetchall()
        if not result:
            self.message_display('Error', "You don't have secret certificates")
            return

        try:
            keyid = self.cursor.execute('''SELECT keyid FROM Certificates WHERE fingerprint = ?''',
                                        (self.gpg_tableWidget.selectedItems()[3].text(),)).fetchall()[0][0]

            if not self.cursor.execute('''SELECT * FROM Certificates WHERE keyid = ? AND type = "secret"''',
                                       (keyid,)).fetchall():
                self.message_display('Fail', 'You do not have the private key for this certificate')
                return

            path = QFileDialog.getSaveFileName(self, 'Secret Key Backup', 'SECRET.asc',
                                               'OpenPGP Certificates (*.asc *.gpg *.pgp)')[0]
            if not path:
                return
            passwd, ok_pressed = QInputDialog.getText(self, 'Passphrase Request', 'Please enter your passphrase')
            passwd = passwd if passwd else None
            self.gpg.export_keys(keyid, secret=True, passphrase=passwd, output=path)
        except IndexError:
            self.message_display('Error', 'Please select a certificate to export')

    def delete_certificate(self):
        result = self.cursor.execute('''SELECT * FROM Certificates''').fetchall()
        if not result:
            self.message_display('Error', "You do not have certificates to delete")
            return

        try:
            key_type = self.cursor.execute('''SELECT type FROM Certificates WHERE fingerprint = ?''',
                                           (self.gpg_tableWidget.selectedItems()[3].text(),)
                                           ).fetchall()[0][0]
            if key_type == 'secret':
                user_response = QMessageBox.question(self, 'Removing a secret certificate',
                                                     "The certificate you want to delete has a private key\n"
                                                     "Are you sure you want to delete it?",
                                                     QMessageBox.Yes | QMessageBox.Cancel,
                                                     QMessageBox.Cancel)

                if user_response == QMessageBox.Yes:
                    passwd, ok_pressed = QInputDialog.getText(self, 'Passphrase Request',
                                                              'Please enter your passphrase')
                    self.gpg.delete_keys(self.gpg_tableWidget.selectedItems()[3].text(), secret=True, passphrase=passwd)
                else:
                    return
            self.gpg.delete_keys(self.gpg_tableWidget.selectedItems()[3].text())
            self.db_update()
        except IndexError:
            self.message_display('Error', 'Please select a certificate to delete')

    def encrypt(self):
        uids = self.cursor.execute('''SELECT uid FROM Certificates''').fetchall()
        if not uids:
            self.message_display('Error', "You don't have any certificates")
            return

        filepath = QFileDialog.getOpenFileName(self, 'Select File to Encrypt', '',
                                               'All files (*))')[0]
        if not filepath:
            return

        end_filepath = QFileDialog.getSaveFileName(self, 'Select Path to Save the Encrypted File', f'{filepath}.gpg',
                                                   'OpenPGP Files (*.gpg *.pgp)')[0]
        if not end_filepath:
            return

        certs = list()
        for i in uids:
            certs.append(*i)

        cert, ok_pressed = QInputDialog.getItem(self, "Encryption", "Encrypt for:", certs, 0, False)
        if ok_pressed:
            recipient = self.cursor.execute('''SELECT fingerprint FROM Certificates WHERE uid = ?''',
                                            (cert,)).fetchall()[0][0]
            crypted = self.gpg.encrypt_file(filepath, recipients=[recipient], always_trust=True, output=end_filepath)
            if not crypted.ok:
                self.message_display('Failed', 'Failed to encrypt file', msg_type=QMessageBox.Critical)

    def decrypt(self):
        result = self.cursor.execute('''SELECT * FROM Certificates WHERE type = "secret"''').fetchall()
        if not result:
            self.message_display('Error', "You don't have secret certificates")
            return

        filepath = QFileDialog.getOpenFileName(self, 'Select File to Decrypt', '',
                                               'OpenPGP Files (*.gpg *.pgp);;Any files (*))')[0]
        if not filepath:
            return

        passwd, ok_pressed = QInputDialog.getText(self, 'Passphrase Request', 'Please enter your passphrase')
        passwd = passwd if passwd else None
        decrypted = self.gpg.decrypt_file(filepath, always_trust=True, passphrase=passwd)
        if not decrypted.ok:
            self.message_display('Fail', 'Failed to decrypt file')
        else:
            file = filepath + '_decrypted' if not filepath.endswith('.gpg') and not filepath.endswith('.pgp') \
                else filepath[:-4]
            with open(file, 'wb') as f:
                f.write(decrypted.data)

    def sign(self):
        uids = self.cursor.execute('''SELECT uid FROM Certificates WHERE type="secret"''').fetchall()
        if not uids:
            self.message_display('Error', "You don't have secret certificates")
            return

        filepath = QFileDialog.getOpenFileName(self, 'Select File to Sign', '',
                                               'All files (*))')[0]
        if not filepath:
            return

        certs = list()
        for i in uids:
            certs.append(*i)

        cert, ok_pressed = QInputDialog.getItem(self, "Sign", "Sign as:", certs, 0, False)
        if ok_pressed:
            signer = self.cursor.execute('''SELECT keyid FROM Certificates WHERE uid = ?''',
                                         (cert,)).fetchall()[0][0]
            passwd, ok_pressed = QInputDialog.getText(self, 'Passphrase Request', 'Please enter your passphrase')
            passwd = passwd if passwd else None

            args = ['--sign', '--detach-sign']
            args.extend(['--default-key', signer])
            args.extend(['--output', filepath + '.sig'])
            args.append(filepath)
            signed = self.gpg._handle_io(args, filepath, self.gpg.result_map['sign'](self.gpg), passphrase=passwd,
                                         binary=True)
            if signed.status != 'signature created':
                self.message_display('Fail', 'The file was not signed')

    def verify(self):
        result = self.cursor.execute('''SELECT * FROM Certificates''').fetchall()
        if not result:
            self.message_display('Error', "You don't have any certificates")
            return

        filepath = QFileDialog.getOpenFileName(self, 'Select Sign File to Verify', '',
                                               'Sign File (*.sig);;Any files (*))')[0]
        if not filepath:
            return
        if os.path.exists(filepath[:-4]):
            data_filepath = filepath[:-4]
        else:

            data_filepath = QFileDialog.getOpenFileName(self, 'Select File to Verify', filepath[:-4],
                                                        'All files (*))')[0]
            if not data_filepath:
                return

        with open(filepath, 'rb') as f:
            verified = self.gpg.verify_file(f, data_filename=data_filepath)

        if verified.status != 'signature valid':
            self.message_display('Error', verified.status.capitalize() + '\t\t\t\t\t\n',
                                 details=f"Verified '{data_filepath}' with '{filepath}'\n"
                                         f'Failed to verify signature authenticity\n\n'
                                         f'Status:\t{verified.status}\n', msg_type=QMessageBox.Critical)
        else:
            sign_date = datetime.utcfromtimestamp(int(verified.sig_timestamp)).strftime("%Y-%m-%d %H:%M:%S")
            self.message_display('Signature', f'Data verified by signature\t\t\t\t\t\n'
                                              f'Valid signature by {verified.username}',
                                 details=f"Verified '{data_filepath}' with '{filepath}'\n"
                                         f'Valid signature by {verified.username}\n\n'
                                         f'Signer username: {verified.username}\n'
                                         f'Signature date:\t{sign_date} (UTC+0)\n'
                                         f'Status:\t{verified.status}\n'
                                         f'Fingerprint:\t{verified.pubkey_fingerprint}',
                                 msg_type=QMessageBox.Information)


class AboutForm(QMainWindow, about.Ui_MainWindow):
    def __init__(self, *args):
        super().__init__()
        self.setupUi(self)
        self.toolButton_mail_author.clicked.connect(lambda: webbrowser.open('mailto:Plak.I.A@yandex.ru'))
        self.toolButton_mail_publisher.clicked.connect(lambda: webbrowser.open('mailto:plaksin.network@gmail.com'))
        self.toolButton_license.clicked.connect(
            lambda: webbrowser.open('https://github.com/PlakIA/CryptoDog/blob/main/LICENSE'))


def except_hook(cls, exception, traceback):
    sys.__excepthook__(cls, exception, traceback)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    form = MainForm()
    form.show()
    sys.excepthook = except_hook
    sys.exit(app.exec())
