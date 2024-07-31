import webbrowser

from PyQt5.QtWidgets import QMainWindow

from ui import about


class AboutForm(QMainWindow, about.Ui_MainWindow):
    def __init__(self, *args):
        super().__init__()
        self.setupUi(self)
        self.toolButton_mail_author.clicked.connect(lambda: webbrowser.open('mailto:Plak.I.A@yandex.ru'))
        self.toolButton_mail_publisher.clicked.connect(lambda: webbrowser.open('mailto:plaksin.network@gmail.com'))
        self.toolButton_license.clicked.connect(
            lambda: webbrowser.open('https://github.com/PlakIA/CryptoDog/blob/main/LICENSE'))
