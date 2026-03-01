import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

Item {
    id: root

    ColumnLayout {
        anchors.fill: parent
        spacing: 12

        RowLayout {
            Layout.fillWidth: true
            ThemedTextField {
                id: logInput
                Layout.fillWidth: true
                placeholderText: "输入手动日志内容"
            }
            ThemedComboBox {
                id: levelBox
                model: ["INFO", "WARN", "ALERT", "CRITICAL"]
                currentIndex: 0
            }
            ThemedButton {
                text: "写入日志"
                enabled: logInput.text.length > 0
                onClicked: {
                    Security.addManualLog(levelBox.currentText, logInput.text)
                    logInput.clear()
                }
            }
        }

        SectionCard {
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: "日志记录"
            icon: Icons.log

            ListView {
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                model: Security.logs
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
                            Layout.preferredWidth: 70
                        }

                        StatusTag {
                            text: modelData.level
                            tone: modelData.level === "CRITICAL" || modelData.level === "ALERT" ? "danger"
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

