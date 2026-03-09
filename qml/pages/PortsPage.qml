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
            title: I18n.tr("端口与高危端口使用情况", "Ports & High-Risk Ports")
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
                            text: modelData.bindScope === "Any" ? I18n.tr("对外监听", "All IF")
                                : modelData.bindScope === "Public" ? I18n.tr("绑定公网", "Public bind")
                                : modelData.bindScope === "Private" ? I18n.tr("内网监听", "LAN")
                                : modelData.bindScope === "Loopback" ? I18n.tr("仅本机", "Loopback")
                                : I18n.tr("未知", "Unknown")
                            tone: (modelData.bindScope === "Any" || modelData.bindScope === "Public") ? "warning"
                                : modelData.bindScope === "Private" ? "normal"
                                : modelData.bindScope === "Loopback" ? "success" : "normal"
                        }

                        StatusTag {
                            text: I18n.riskLabel(modelData.risk)
                            tone: modelData.risk === "Critical" ? "danger"
                                : modelData.risk === "High" ? "warning"
                                : modelData.risk === "Low" ? "success" : "normal"
                        }

                        ThemedButton {
                            text: modelData.action === "Block"
                                ? (Icons.block + " " + I18n.tr("阻断", "Block"))
                                : I18n.tr("观察", "Observe")
                            enabled: modelData.action === "Block"
                            onClicked: Security.blockAction(modelData.process, (I18n.tr("端口 ", "Port ") + modelData.port))
                        }
                    }
                }
            }
        }
    }
}

