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
            title: "策略引擎"
            icon: Icons.block

            RowLayout {
                Layout.fillWidth: true
                spacing: 16

                ThemedSwitch {
                    text: "自动阻断高危端口"
                    checked: Security.autoBlockHighRiskPorts
                    onToggled: Security.autoBlockHighRiskPorts = checked
                }

                ThemedSwitch {
                    text: "自动终止不可信 Shell"
                    checked: Security.autoKillUntrustedShell
                    onToggled: Security.autoKillUntrustedShell = checked
                }
            }

            ThemedTextField {
                Layout.fillWidth: true
                placeholderText: "白名单进程 (逗号分隔)"
                text: Security.processWhitelist
                onEditingFinished: Security.processWhitelist = text
            }

            ThemedTextField {
                Layout.fillWidth: true
                placeholderText: "黑名单进程 (逗号分隔)"
                text: Security.processBlacklist
                onEditingFinished: Security.processBlacklist = text
            }

            ThemedButton {
                text: "立即执行策略"
                onClicked: Security.applyPolicyNow()
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: "安全告警与异常行为"
            icon: Icons.alert

            Repeater {
                model: Security.alerts
                delegate: Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: 92
                    radius: 8
                    color: Theme.cardAltBg
                    border.width: 1
                    border.color: modelData.severity === "Critical" ? Theme.dangerColor : Theme.borderColor

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 10
                        spacing: 6

                        RowLayout {
                            Layout.fillWidth: true

                            Label {
                                text: modelData.time
                                color: Theme.textSecondary
                                Layout.preferredWidth: 140
                                Layout.maximumWidth: 140
                                horizontalAlignment: Text.AlignRight
                                elide: Text.ElideRight
                                clip: true
                            }

                            Label {
                                text: modelData.title
                                color: Theme.textPrimary
                                font.bold: true
                                Layout.fillWidth: true
                                elide: Text.ElideRight
                            }

                            StatusTag {
                                text: modelData.severity
                                tone: modelData.severity === "Critical" ? "danger"
                                    : modelData.severity === "High" ? "warning" : "normal"
                            }
                        }

                        Label {
                            text: modelData.detail
                            color: Theme.textSecondary
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                        }
                    }
                }
            }
        }
    }
}
