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
                            text: modelData.bindScope === "Any" ? I18n.tr("全网监听", "All IF")
                                : modelData.bindScope === "Public" ? I18n.tr("公网IP", "Public IP")
                                : modelData.bindScope === "Private" ? I18n.tr("私网", "Private")
                                : I18n.tr("本机", "Local")
                            tone: (modelData.bindScope === "Any" || modelData.bindScope === "Public") ? "warning"
                                : modelData.bindScope === "Private" ? "normal" : "success"
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

