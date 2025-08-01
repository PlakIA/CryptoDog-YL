# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '.\ui\source\about.ui'
#
# Created by: PyQt5 UI code generator 5.15.11
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(280, 510)
        MainWindow.setMinimumSize(QtCore.QSize(280, 510))
        MainWindow.setMaximumSize(QtCore.QSize(280, 510))
        with open('./ui/theme_resources/stylesheet.qss', 'r', encoding='utf8') as f:
            MainWindow.setStyleSheet(f.read())
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.groupBox_2 = QtWidgets.QGroupBox(self.centralwidget)
        self.groupBox_2.setGeometry(QtCore.QRect(10, 210, 251, 121))
        self.groupBox_2.setStyleSheet("background-color: #1b1e20;\n"
                                      "border-radius: 3px;")
        self.groupBox_2.setTitle("")
        self.groupBox_2.setObjectName("groupBox_2")
        self.verticalLayoutWidget = QtWidgets.QWidget(self.groupBox_2)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(10, 10, 231, 101))
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.label = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label.setObjectName("label")
        self.verticalLayout.addWidget(self.label)
        self.line = QtWidgets.QFrame(self.verticalLayoutWidget)
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.verticalLayout.addWidget(self.line)
        self.label_lib = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_lib.setObjectName("label_lib")
        self.verticalLayout.addWidget(self.label_lib)
        self.groupBox = QtWidgets.QGroupBox(self.centralwidget)
        self.groupBox.setGeometry(QtCore.QRect(10, 0, 251, 201))
        self.groupBox.setStyleSheet("background-color: #1b1e20;\n"
                                    "border-radius: 3px;")
        self.groupBox.setTitle("")
        self.groupBox.setObjectName("groupBox")
        self.logo = QtWidgets.QLabel(self.groupBox)
        self.logo.setGeometry(QtCore.QRect(10, 20, 45, 50))
        self.logo.setPixmap(QtGui.QPixmap(".\\ui\\images/logo.png"))
        self.logo.setScaledContents(True)
        self.logo.setObjectName("logo")
        self.title = QtWidgets.QLabel(self.groupBox)
        self.title.setGeometry(QtCore.QRect(70, 10, 171, 61))
        self.title.setObjectName("title")
        self.line_2 = QtWidgets.QFrame(self.groupBox)
        self.line_2.setGeometry(QtCore.QRect(10, 80, 231, 3))
        self.line_2.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_2.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_2.setObjectName("line_2")
        self.label_copyright = QtWidgets.QLabel(self.groupBox)
        self.label_copyright.setGeometry(QtCore.QRect(10, 90, 141, 31))
        self.label_copyright.setObjectName("label_copyright")
        self.verticalLayoutWidget_2 = QtWidgets.QWidget(self.groupBox)
        self.verticalLayoutWidget_2.setGeometry(QtCore.QRect(10, 130, 231, 61))
        self.verticalLayoutWidget_2.setObjectName("verticalLayoutWidget_2")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_2)
        self.verticalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.label_3 = QtWidgets.QLabel(self.verticalLayoutWidget_2)
        self.label_3.setObjectName("label_3")
        self.verticalLayout_2.addWidget(self.label_3)
        self.line_4 = QtWidgets.QFrame(self.verticalLayoutWidget_2)
        self.line_4.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_4.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_4.setObjectName("line_4")
        self.verticalLayout_2.addWidget(self.line_4)
        self.toolButton_license = QtWidgets.QToolButton(self.verticalLayoutWidget_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.toolButton_license.sizePolicy().hasHeightForWidth())
        self.toolButton_license.setSizePolicy(sizePolicy)
        self.toolButton_license.setLayoutDirection(QtCore.Qt.RightToLeft)
        self.toolButton_license.setStyleSheet("border-radius: 0px;")
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(":/right_arrow_hover.svg"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.toolButton_license.setIcon(icon)
        self.toolButton_license.setPopupMode(QtWidgets.QToolButton.DelayedPopup)
        self.toolButton_license.setToolButtonStyle(QtCore.Qt.ToolButtonTextBesideIcon)
        self.toolButton_license.setAutoRaise(False)
        self.toolButton_license.setArrowType(QtCore.Qt.NoArrow)
        self.toolButton_license.setObjectName("toolButton_license")
        self.verticalLayout_2.addWidget(self.toolButton_license)
        self.groupBox_3 = QtWidgets.QGroupBox(self.centralwidget)
        self.groupBox_3.setGeometry(QtCore.QRect(10, 340, 251, 161))
        self.groupBox_3.setStyleSheet("background-color: #1b1e20;\n"
                                      "border-radius: 3px;")
        self.groupBox_3.setTitle("")
        self.groupBox_3.setObjectName("groupBox_3")
        self.verticalLayoutWidget_3 = QtWidgets.QWidget(self.groupBox_3)
        self.verticalLayoutWidget_3.setGeometry(QtCore.QRect(10, 20, 231, 24))
        self.verticalLayoutWidget_3.setObjectName("verticalLayoutWidget_3")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_3)
        self.verticalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.label_6 = QtWidgets.QLabel(self.verticalLayoutWidget_3)
        self.label_6.setObjectName("label_6")
        self.verticalLayout_3.addWidget(self.label_6)
        self.line_3 = QtWidgets.QFrame(self.verticalLayoutWidget_3)
        self.line_3.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_3.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_3.setObjectName("line_3")
        self.verticalLayout_3.addWidget(self.line_3)
        self.label_author = QtWidgets.QLabel(self.groupBox_3)
        self.label_author.setGeometry(QtCore.QRect(70, 60, 111, 31))
        self.label_author.setObjectName("label_author")
        self.ava_iaroslav = QtWidgets.QLabel(self.groupBox_3)
        self.ava_iaroslav.setGeometry(QtCore.QRect(10, 50, 45, 45))
        self.ava_iaroslav.setStyleSheet("border-radius: 100px;")
        self.ava_iaroslav.setText("")
        self.ava_iaroslav.setPixmap(QtGui.QPixmap(".\\ui\\images/Iarosalv.png"))
        self.ava_iaroslav.setScaledContents(True)
        self.ava_iaroslav.setObjectName("ava_iaroslav")
        self.label_pub = QtWidgets.QLabel(self.groupBox_3)
        self.label_pub.setGeometry(QtCore.QRect(10, 120, 181, 31))
        self.label_pub.setObjectName("label_pub")
        self.toolButton_mail_publisher = QtWidgets.QToolButton(self.groupBox_3)
        self.toolButton_mail_publisher.setGeometry(QtCore.QRect(200, 120, 41, 31))
        self.toolButton_mail_publisher.setText("")
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(":/mail-send.svg"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.toolButton_mail_publisher.setIcon(icon1)
        self.toolButton_mail_publisher.setIconSize(QtCore.QSize(22, 22))
        self.toolButton_mail_publisher.setToolButtonStyle(QtCore.Qt.ToolButtonIconOnly)
        self.toolButton_mail_publisher.setArrowType(QtCore.Qt.NoArrow)
        self.toolButton_mail_publisher.setObjectName("toolButton_mail_publisher")
        self.toolButton_mail_author = QtWidgets.QToolButton(self.groupBox_3)
        self.toolButton_mail_author.setGeometry(QtCore.QRect(200, 60, 41, 31))
        self.toolButton_mail_author.setText("")
        self.toolButton_mail_author.setIcon(icon1)
        self.toolButton_mail_author.setIconSize(QtCore.QSize(22, 22))
        self.toolButton_mail_author.setToolButtonStyle(QtCore.Qt.ToolButtonIconOnly)
        self.toolButton_mail_author.setArrowType(QtCore.Qt.NoArrow)
        self.toolButton_mail_author.setObjectName("toolButton_mail_author")
        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "About"))
        self.label.setText(_translate("MainWindow",
                                      "<html><head/><body><p><span style=\" font-weight:600;\">Libraries used:</span></p></body></html>"))
        self.label_lib.setText(_translate("MainWindow",
                                          "<html><head/><body><p>PyQt 5.15.10<br/>PyCryptodome 3.19.0<br/>python-gnupg 0.5.1<br/>pyperclip 1.9.0</p></body></html>"))
        self.title.setText(_translate("MainWindow",
                                      "<html><head/><body><p><span style=\" font-size:12pt; font-weight:600;\">CryptoDog alpha3</span><span style=\" font-size:14pt; font-weight:600;\"><br/></span><span style=\" font-size:11pt;\">CryptoDog</span></p></body></html>"))
        self.label_copyright.setText(_translate("MainWindow",
                                                "<html><head/><body><p><span style=\" font-weight:600;\">Copyright</span><br/>(c) 2023-2024 Iaroslav Plaksin</p></body></html>"))
        self.label_3.setText(_translate("MainWindow",
                                        "<html><head/><body><p><span style=\" font-weight:600;\">License:</span></p></body></html>"))
        self.toolButton_license.setText(_translate("MainWindow", "Apache 2.0"))
        self.label_6.setText(_translate("MainWindow",
                                        "<html><head/><body><p><span style=\" font-weight:600;\">Authors:</span></p></body></html>"))
        self.label_author.setText(_translate("MainWindow",
                                             "<html><head/><body><p>Iaroslav Plaksin<br/><span style=\" font-style:italic;\">Author, code, desing</span></p></body></html>"))
        self.label_pub.setText(_translate("MainWindow",
                                          "<html><head/><body><p>plaknet<br/><span style=\" font-style:italic;\">Publisher</span></p></body></html>"))
        self.toolButton_mail_publisher.setToolTip(_translate("MainWindow",
                                                             "<html><head/><body><p>Send an email to<br/>plaksin.network@gmail.com</p></body></html>"))
        self.toolButton_mail_author.setToolTip(_translate("MainWindow",
                                                          "<html><head/><body><p>Send an emaill to<br/>Plak.I.A@yandex.ru</p></body></html>"))

