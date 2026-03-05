import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

ScrollView {
    id: root
    clip: true

    ColumnLayout {
        width: root.availableWidth
        spacing: 12

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("密钥与凭证", "Secrets & Credentials")
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
                            text: I18n.tr("到期: ", "Expires: ") + modelData.expires
                            color: Theme.textSecondary
                            Layout.fillWidth: true
                        }

                        StatusTag {
                            text: I18n.exposureLabel(modelData.exposure)
                            tone: modelData.exposure === "Masked" || modelData.exposure === "Vault Protected" ? "success" : "warning"
                        }
                    }
                }
            }
        }
    }
}

