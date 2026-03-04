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
            title: "密钥与凭证"
            icon: Icons.credential

            Repeater {
                model: Security.credentials
                delegate: Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: 62
                    radius: 8
                    color: Theme.cardAltBg
                    border.width: 1
                    border.color: Theme.borderColor

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 10

                        Label {
                            text: modelData.type
                            color: Theme.textPrimary
                            font.bold: true
                            Layout.preferredWidth: 140
                        }

                        Label {
                            text: modelData.owner
                            color: Theme.textSecondary
                            Layout.preferredWidth: 220
                            elide: Text.ElideRight
                        }

                        Label {
                            text: "到期: " + modelData.expires
                            color: Theme.textSecondary
                            Layout.fillWidth: true
                        }

                        StatusTag {
                            text: modelData.exposure
                            tone: modelData.exposure === "Masked" || modelData.exposure === "Vault Protected" ? "success" : "warning"
                        }
                    }
                }
            }
        }
    }
}

