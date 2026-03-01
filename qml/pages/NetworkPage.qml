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
            title: "网络、防火墙、流量"
            icon: Icons.network

            Label {
                text: Icons.firewall + " 防火墙规则"
                color: Theme.textPrimary
                font.bold: true
                font.pixelSize: 15
            }

            Repeater {
                model: Security.firewallRules
                delegate: Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: 56
                    radius: 8
                    color: Theme.cardAltBg

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 10

                        Label {
                            text: modelData.rule
                            color: Theme.textPrimary
                            Layout.preferredWidth: 290
                            elide: Text.ElideRight
                        }

                        Label {
                            text: modelData.target
                            color: Theme.textSecondary
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }

                        StatusTag {
                            text: modelData.risk
                            tone: modelData.risk === "Critical" ? "danger"
                                : modelData.risk === "High" ? "warning" : "success"
                        }
                    }
                }
            }

            Label {
                text: Icons.traffic + " 流量基线"
                color: Theme.textPrimary
                font.bold: true
                font.pixelSize: 15
            }

            Repeater {
                model: Security.traffic
                delegate: Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: 50
                    radius: 8
                    color: Theme.cardAltBg

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 10

                        Label {
                            text: modelData.direction
                            color: Theme.textPrimary
                            Layout.preferredWidth: 120
                        }

                        Label {
                            text: modelData.mbps + " Mbps"
                            color: Theme.textSecondary
                            Layout.preferredWidth: 100
                        }

                        StatusTag {
                            text: modelData.unusual === "Yes" ? "异常" : "正常"
                            tone: modelData.unusual === "Yes" ? "warning" : "success"
                        }
                    }
                }
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: "告警通知通道"
            icon: Icons.alert

            RowLayout {
                Layout.fillWidth: true
                spacing: 18

                ThemedSwitch {
                    text: Icons.desktop + " 桌面通知"
                    checked: Security.desktopNotify
                    onToggled: Security.desktopNotify = checked
                }

                ThemedSwitch {
                    text: Icons.mail + " 邮件通知"
                    checked: Security.emailNotify
                    onToggled: Security.emailNotify = checked
                }

                ThemedSwitch {
                    text: Icons.sms + " 短信通知"
                    checked: Security.smsNotify
                    onToggled: Security.smsNotify = checked
                }
            }
        }
    }
}

