# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'form.ui'
##
## Created by: Qt User Interface Compiler version 6.10.0
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QAction, QBrush, QColor, QConicalGradient,
    QCursor, QFont, QFontDatabase, QGradient,
    QIcon, QImage, QKeySequence, QLinearGradient,
    QPainter, QPalette, QPixmap, QRadialGradient,
    QTransform)
from PySide6.QtWidgets import (QApplication, QHBoxLayout, QHeaderView, QListWidget,
    QListWidgetItem, QMainWindow, QMenuBar, QPushButton,
    QSizePolicy, QSpacerItem, QSplitter, QStatusBar,
    QTabWidget, QTableView, QTableWidget, QTableWidgetItem,
    QTextBrowser, QTextEdit, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget)

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName(u"MainWindow")
        MainWindow.resize(963, 597)
        self.actionsfdgh = QAction(MainWindow)
        self.actionsfdgh.setObjectName(u"actionsfdgh")
        self.actionsdf = QAction(MainWindow)
        self.actionsdf.setObjectName(u"actionsdf")
        self.actionasdf = QAction(MainWindow)
        self.actionasdf.setObjectName(u"actionasdf")
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName(u"centralwidget")
        self.verticalLayout = QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.splitter_5 = QSplitter(self.centralwidget)
        self.splitter_5.setObjectName(u"splitter_5")
        self.splitter_5.setOrientation(Qt.Orientation.Horizontal)
        self.splitter_4 = QSplitter(self.splitter_5)
        self.splitter_4.setObjectName(u"splitter_4")
        self.splitter_4.setOrientation(Qt.Orientation.Vertical)
        self.layoutWidget = QWidget(self.splitter_4)
        self.layoutWidget.setObjectName(u"layoutWidget")
        self.horizontalLayout = QHBoxLayout(self.layoutWidget)
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.vl_editor_buttons = QVBoxLayout()
        self.vl_editor_buttons.setObjectName(u"vl_editor_buttons")
        self.pb_browse_yara = QPushButton(self.layoutWidget)
        self.pb_browse_yara.setObjectName(u"pb_browse_yara")

        self.vl_editor_buttons.addWidget(self.pb_browse_yara)

        self.pb_select_scan_dir = QPushButton(self.layoutWidget)
        self.pb_select_scan_dir.setObjectName(u"pb_select_scan_dir")

        self.vl_editor_buttons.addWidget(self.pb_select_scan_dir)

        self.pb_save_rule = QPushButton(self.layoutWidget)
        self.pb_save_rule.setObjectName(u"pb_save_rule")

        self.vl_editor_buttons.addWidget(self.pb_save_rule)

        self.pb_reset = QPushButton(self.layoutWidget)
        self.pb_reset.setObjectName(u"pb_reset")

        self.vl_editor_buttons.addWidget(self.pb_reset)

        self.verticalSpacer = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.vl_editor_buttons.addItem(self.verticalSpacer)

        self.pb_format_yara = QPushButton(self.layoutWidget)
        self.pb_format_yara.setObjectName(u"pb_format_yara")

        self.vl_editor_buttons.addWidget(self.pb_format_yara)

        self.pb_scan = QPushButton(self.layoutWidget)
        self.pb_scan.setObjectName(u"pb_scan")

        self.vl_editor_buttons.addWidget(self.pb_scan)


        self.horizontalLayout.addLayout(self.vl_editor_buttons)

        self.te_yara_editor = QTextEdit(self.layoutWidget)
        self.te_yara_editor.setObjectName(u"te_yara_editor")
        font = QFont()
        font.setFamilies([u"Cascadia Code"])
        self.te_yara_editor.setFont(font)

        self.horizontalLayout.addWidget(self.te_yara_editor)

        self.splitter_4.addWidget(self.layoutWidget)
        self.tb_compilation_output = QTextBrowser(self.splitter_4)
        self.tb_compilation_output.setObjectName(u"tb_compilation_output")
        sizePolicy = QSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.tb_compilation_output.sizePolicy().hasHeightForWidth())
        self.tb_compilation_output.setSizePolicy(sizePolicy)
        self.tb_compilation_output.setMaximumSize(QSize(16777215, 160))
        self.splitter_4.addWidget(self.tb_compilation_output)
        self.splitter_5.addWidget(self.splitter_4)
        self.tabWidget = QTabWidget(self.splitter_5)
        self.tabWidget.setObjectName(u"tabWidget")
        self.tabWidget.setTabBarAutoHide(False)
        self.tab_scan_dir = QWidget()
        self.tab_scan_dir.setObjectName(u"tab_scan_dir")
        self.horizontalLayout_9 = QHBoxLayout(self.tab_scan_dir)
        self.horizontalLayout_9.setObjectName(u"horizontalLayout_9")
        self.splitter_3 = QSplitter(self.tab_scan_dir)
        self.splitter_3.setObjectName(u"splitter_3")
        self.splitter_3.setOrientation(Qt.Orientation.Vertical)
        self.treeWidget = QTreeWidget(self.splitter_3)
        __qtreewidgetitem = QTreeWidgetItem()
        __qtreewidgetitem.setText(0, u"1");
        self.treeWidget.setHeaderItem(__qtreewidgetitem)
        self.treeWidget.setObjectName(u"treeWidget")
        self.splitter_3.addWidget(self.treeWidget)
        self.listWidget = QListWidget(self.splitter_3)
        self.listWidget.setObjectName(u"listWidget")
        self.listWidget.setMaximumSize(QSize(16777215, 120))
        self.splitter_3.addWidget(self.listWidget)

        self.horizontalLayout_9.addWidget(self.splitter_3)

        self.tabWidget.addTab(self.tab_scan_dir, "")
        self.tab_scan_results = QWidget()
        self.tab_scan_results.setObjectName(u"tab_scan_results")
        self.verticalLayout_3 = QVBoxLayout(self.tab_scan_results)
        self.verticalLayout_3.setObjectName(u"verticalLayout_3")
        self.splitter_2 = QSplitter(self.tab_scan_results)
        self.splitter_2.setObjectName(u"splitter_2")
        self.splitter_2.setOrientation(Qt.Orientation.Vertical)
        self.splitter = QSplitter(self.splitter_2)
        self.splitter.setObjectName(u"splitter")
        self.splitter.setOrientation(Qt.Orientation.Horizontal)
        self.tabWidget_2 = QTabWidget(self.splitter)
        self.tabWidget_2.setObjectName(u"tabWidget_2")
        self.tabWidget_2.setTabBarAutoHide(True)
        self.tab_scan_file_hits = QWidget()
        self.tab_scan_file_hits.setObjectName(u"tab_scan_file_hits")
        self.horizontalLayout_4 = QHBoxLayout(self.tab_scan_file_hits)
        self.horizontalLayout_4.setObjectName(u"horizontalLayout_4")
        self.tv_file_hits = QTableView(self.tab_scan_file_hits)
        self.tv_file_hits.setObjectName(u"tv_file_hits")

        self.horizontalLayout_4.addWidget(self.tv_file_hits)

        self.tabWidget_2.addTab(self.tab_scan_file_hits, "")
        self.tab_scan_file_misses = QWidget()
        self.tab_scan_file_misses.setObjectName(u"tab_scan_file_misses")
        self.horizontalLayout_5 = QHBoxLayout(self.tab_scan_file_misses)
        self.horizontalLayout_5.setObjectName(u"horizontalLayout_5")
        self.tv_file_misses = QTableView(self.tab_scan_file_misses)
        self.tv_file_misses.setObjectName(u"tv_file_misses")

        self.horizontalLayout_5.addWidget(self.tv_file_misses)

        self.tabWidget_2.addTab(self.tab_scan_file_misses, "")
        self.splitter.addWidget(self.tabWidget_2)
        self.tabWidget_3 = QTabWidget(self.splitter)
        self.tabWidget_3.setObjectName(u"tabWidget_3")
        self.tab_rule_details = QWidget()
        self.tab_rule_details.setObjectName(u"tab_rule_details")
        self.horizontalLayout_7 = QHBoxLayout(self.tab_rule_details)
        self.horizontalLayout_7.setObjectName(u"horizontalLayout_7")
        self.tv_rule_details = QTableView(self.tab_rule_details)
        self.tv_rule_details.setObjectName(u"tv_rule_details")

        self.horizontalLayout_7.addWidget(self.tv_rule_details)

        self.tabWidget_3.addTab(self.tab_rule_details, "")
        self.tab_2 = QWidget()
        self.tab_2.setObjectName(u"tab_2")
        self.horizontalLayout_8 = QHBoxLayout(self.tab_2)
        self.horizontalLayout_8.setObjectName(u"horizontalLayout_8")
        self.tw_similar_files = QTreeWidget(self.tab_2)
        __qtreewidgetitem1 = QTreeWidgetItem()
        __qtreewidgetitem1.setText(0, u"1");
        self.tw_similar_files.setHeaderItem(__qtreewidgetitem1)
        self.tw_similar_files.setObjectName(u"tw_similar_files")

        self.horizontalLayout_8.addWidget(self.tw_similar_files)

        self.tabWidget_3.addTab(self.tab_2, "")
        self.tab_similar_tag = QWidget()
        self.tab_similar_tag.setObjectName(u"tab_similar_tag")
        self.horizontalLayout_2 = QHBoxLayout(self.tab_similar_tag)
        self.horizontalLayout_2.setObjectName(u"horizontalLayout_2")
        self.tw_similar_tags = QTreeWidget(self.tab_similar_tag)
        __qtreewidgetitem2 = QTreeWidgetItem()
        __qtreewidgetitem2.setText(0, u"1");
        self.tw_similar_tags.setHeaderItem(__qtreewidgetitem2)
        self.tw_similar_tags.setObjectName(u"tw_similar_tags")

        self.horizontalLayout_2.addWidget(self.tw_similar_tags)

        self.tabWidget_3.addTab(self.tab_similar_tag, "")
        self.splitter.addWidget(self.tabWidget_3)
        self.splitter_2.addWidget(self.splitter)
        self.tabWidget_4 = QTabWidget(self.splitter_2)
        self.tabWidget_4.setObjectName(u"tabWidget_4")
        self.tab = QWidget()
        self.tab.setObjectName(u"tab")
        self.horizontalLayout_6 = QHBoxLayout(self.tab)
        self.horizontalLayout_6.setObjectName(u"horizontalLayout_6")
        self.tw_yara_match_details = QTableWidget(self.tab)
        self.tw_yara_match_details.setObjectName(u"tw_yara_match_details")

        self.horizontalLayout_6.addWidget(self.tw_yara_match_details)

        self.tabWidget_4.addTab(self.tab, "")
        self.splitter_2.addWidget(self.tabWidget_4)

        self.verticalLayout_3.addWidget(self.splitter_2)

        self.tabWidget.addTab(self.tab_scan_results, "")
        self.splitter_5.addWidget(self.tabWidget)

        self.verticalLayout.addWidget(self.splitter_5)

        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QMenuBar(MainWindow)
        self.menubar.setObjectName(u"menubar")
        self.menubar.setGeometry(QRect(0, 0, 963, 21))
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QStatusBar(MainWindow)
        self.statusbar.setObjectName(u"statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)

        self.tabWidget.setCurrentIndex(1)
        self.tabWidget_2.setCurrentIndex(0)
        self.tabWidget_3.setCurrentIndex(0)
        self.tabWidget_4.setCurrentIndex(0)


        QMetaObject.connectSlotsByName(MainWindow)
    # setupUi

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate("MainWindow", u"MainWindow", None))
        self.actionsfdgh.setText(QCoreApplication.translate("MainWindow", u"sfdgh", None))
        self.actionsdf.setText(QCoreApplication.translate("MainWindow", u"sdf", None))
        self.actionasdf.setText(QCoreApplication.translate("MainWindow", u"asdf", None))
        self.pb_browse_yara.setText(QCoreApplication.translate("MainWindow", u"Browse  YARA", None))
        self.pb_select_scan_dir.setText(QCoreApplication.translate("MainWindow", u"Select Scan Dir", None))
        self.pb_save_rule.setText(QCoreApplication.translate("MainWindow", u"Save Rule", None))
        self.pb_reset.setText(QCoreApplication.translate("MainWindow", u"Reset", None))
        self.pb_format_yara.setText(QCoreApplication.translate("MainWindow", u"Format YARA", None))
        self.pb_scan.setText(QCoreApplication.translate("MainWindow", u"SCAN", None))
        self.te_yara_editor.setHtml(QCoreApplication.translate("MainWindow", u"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><meta charset=\"utf-8\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"hr { height: 1px; border-width: 0; }\n"
"li.unchecked::marker { content: \"\\2610\"; }\n"
"li.checked::marker { content: \"\\2612\"; }\n"
"</style></head><body style=\" font-family:'Cascadia Code'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">import &quot;pe&quot;</p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">rule myRuleName : myTag{</p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-"
                        "left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">  meta:</p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">    author=&quot;  &quot;</p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">    description=&quot; &quot;</p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">    hash = &quot; &quot;</p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">    date = &quot; &quot;</p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">  strings:</p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">    $s1 = &quot;&quot;</p>\n"
"<p style=\"-qt-paragraph-typ"
                        "e:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">  condition:</p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">    pe.is_pe and all of them</p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">}</p></body></html>", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_scan_dir), QCoreApplication.translate("MainWindow", u"Scan Dir", None))
        self.tabWidget_2.setTabText(self.tabWidget_2.indexOf(self.tab_scan_file_hits), QCoreApplication.translate("MainWindow", u"Hits :D", None))
        self.tabWidget_2.setTabText(self.tabWidget_2.indexOf(self.tab_scan_file_misses), QCoreApplication.translate("MainWindow", u"Misses :O", None))
        self.tabWidget_3.setTabText(self.tabWidget_3.indexOf(self.tab_rule_details), QCoreApplication.translate("MainWindow", u"Rule Details", None))
        self.tabWidget_3.setTabText(self.tabWidget_3.indexOf(self.tab_2), QCoreApplication.translate("MainWindow", u"Similar Files", None))
        self.tabWidget_3.setTabText(self.tabWidget_3.indexOf(self.tab_similar_tag), QCoreApplication.translate("MainWindow", u"Similar Tags", None))
        self.tabWidget_4.setTabText(self.tabWidget_4.indexOf(self.tab), QCoreApplication.translate("MainWindow", u"All", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_scan_results), QCoreApplication.translate("MainWindow", u"Scan Result", None))
    # retranslateUi

