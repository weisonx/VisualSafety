import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

ScrollView {
    id: root
    clip: true
    ScrollBar.vertical: ThemedScrollBar {}
    ScrollBar.horizontal: ThemedScrollBar {}

    ColumnLayout {
        width: root.availableWidth
        spacing: 12

        SectionCard {
            Layout.fillWidth: true
            title: "端口与高危端口使用情况"
            icon: Icons.port

            Repeater {
                model: Security.ports
                delegate: Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: 62
                    radius: 8
                    color: Theme.cardAltBg

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 10

                        Label {
                            text: modelData.protocol + ":" + modelData.port
                            color: Theme.textPrimary
                            font.bold: true
                            Layout.preferredWidth: 120
                        }

                        Label {
                            text: modelData.process
                            color: Theme.textSecondary
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }

                        StatusTag {
                            text: modelData.risk
                            tone: modelData.risk === "Critical" ? "danger"
                                : modelData.risk === "High" ? "warning"
                                : modelData.risk === "Low" ? "success" : "normal"
                        }

                        ThemedButton {
                            text: modelData.action === "Block" ? (Icons.block + " 阻断") : "观察"
                            enabled: modelData.action === "Block"
                            onClicked: Security.blockAction(modelData.process, "Port " + modelData.port)
                        }
                    }
                }
            }
        }
    }
}

