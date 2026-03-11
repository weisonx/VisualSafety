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
            tip: I18n.tr("凭证信息总览与暴露状态（示例）。", "Credential inventory and exposure state (demo).")

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
                            HoverHandler { id: typeHover }
                        }

                        Label {
                            text: modelData.owner
                            color: Theme.textSecondary
                            Layout.preferredWidth: 220
                            elide: Text.ElideRight
                            HoverHandler { id: ownerHover }
                        }

                        Label {
                            text: I18n.tr("到期: ", "Expires: ") + modelData.expires
                            color: Theme.textSecondary
                            Layout.fillWidth: true
                            HoverHandler { id: expiresHover }
                        }

                        StatusTag {
                            text: I18n.exposureLabel(modelData.exposure)
                            tone: modelData.exposure === "Masked" || modelData.exposure === "Vault Protected" ? "success" : "warning"
                            tip: I18n.tr("暴露状态：Masked/Vault 表示更安全；Exposed 表示需要立即处理。", "Exposure: Masked/Vault is safer; Exposed requires remediation.")
                        }
                    }
                }
            }
        }
    }
}

