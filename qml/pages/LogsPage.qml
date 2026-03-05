import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

Item {
    id: root
    property var filteredLogs: []

    function rebuildLogs() {
        const level = levelFilter.currentText
        const keyword = keywordInput.text.trim().toLowerCase()
        const source = Security.logs
        const out = []

        for (let i = 0; i < source.length; ++i) {
            const row = source[i]
            if (level !== "ALL" && row.level !== level)
                continue
            if (keyword.length > 0 && row.message.toLowerCase().indexOf(keyword) === -1)
                continue
            out.push(row)
            if (out.length >= 400)
                break
        }

        filteredLogs = out
    }

    Connections {
        target: Security
        function onLogsChanged() { root.rebuildLogs() }
    }

    Component.onCompleted: rebuildLogs()

    ColumnLayout {
        anchors.fill: parent
        spacing: 12

        RowLayout {
            Layout.fillWidth: true
            ThemedTextField {
                id: logInput
                Layout.fillWidth: true
                placeholderText: I18n.tr("输入手动日志内容", "Enter manual log message")
            }
            ThemedComboBox {
                id: levelBox
                model: ["INFO", "WARN", "ALERT", "CRITICAL"]
                currentIndex: 0
            }
            ThemedButton {
                text: I18n.tr("写入日志", "Write Log")
                enabled: logInput.text.length > 0
                onClicked: {
                    Security.addManualLog(levelBox.currentText, logInput.text)
                    logInput.clear()
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            ThemedComboBox {
                id: levelFilter
                model: ["ALL", "INFO", "WARN", "ALERT", "CRITICAL", "ERROR"]
                currentIndex: 0
                onCurrentTextChanged: root.rebuildLogs()
            }
            ThemedTextField {
                id: keywordInput
                Layout.fillWidth: true
                placeholderText: I18n.tr("按关键字筛选日志", "Filter by keyword")
                onTextChanged: root.rebuildLogs()
            }
            ThemedButton {
                text: I18n.tr("导出日志", "Export Logs")
                onClicked: {
                    const path = "./build/visualsafety-export.log"
                    Security.exportLogs(path)
                }
            }
        }

        SectionCard {
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: I18n.tr("日志记录", "Logs")
            icon: Icons.log

            ListView {
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                model: root.filteredLogs
                spacing: 6

                delegate: Rectangle {
                    width: ListView.view.width
                    implicitHeight: 54
                    radius: 8
                    color: Theme.cardAltBg

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 10

                        Label {
                            text: modelData.time
                            color: Theme.textSecondary
                            Layout.preferredWidth: 140
                            Layout.maximumWidth: 140
                            horizontalAlignment: Text.AlignRight
                            elide: Text.ElideRight
                            clip: true
                        }

                        StatusTag {
                            text: I18n.logLevelLabel(modelData.level)
                            tone: modelData.level === "CRITICAL" || modelData.level === "ALERT" || modelData.level === "ERROR" ? "danger"
                                : modelData.level === "WARN" ? "warning" : "normal"
                        }

                        Label {
                            text: modelData.message
                            color: Theme.textPrimary
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }
                    }
                }
            }
        }
    }
}
