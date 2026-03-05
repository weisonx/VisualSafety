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
            title: I18n.tr("网络、防火墙、流量", "Network, Firewall & Traffic")
            icon: Icons.network

            Label {
                text: Icons.firewall + " " + I18n.tr("防火墙规则", "Firewall Rules")
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
                text: Icons.traffic + " " + I18n.tr("流量速率（Mbps）", "Traffic Rate (Mbps)")
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
                            text: modelData.unusual === "Yes" ? I18n.tr("异常", "Unusual") : I18n.tr("正常", "Normal")
                            tone: modelData.unusual === "Yes" ? "warning" : "success"
                        }
                    }
                }
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("告警通知通道", "Notification Channels")
            icon: Icons.alert

            RowLayout {
                Layout.fillWidth: true
                spacing: 18

                ThemedSwitch {
                    text: Icons.desktop + " " + I18n.tr("桌面通知", "Desktop")
                    checked: Security.desktopNotify
                    onToggled: Security.desktopNotify = checked
                }

                ThemedSwitch {
                    text: Icons.mail + " " + I18n.tr("邮件通知", "Email")
                    checked: Security.emailNotify
                    onToggled: Security.emailNotify = checked
                }

                ThemedSwitch {
                    text: Icons.sms + " " + I18n.tr("短信通知", "SMS")
                    checked: Security.smsNotify
                    onToggled: Security.smsNotify = checked
                }
            }

            GridLayout {
                columns: 2
                Layout.fillWidth: true
                columnSpacing: 8
                rowSpacing: 8

                ThemedTextField {
                    Layout.fillWidth: true
                    placeholderText: I18n.tr("SMTP 服务器", "SMTP Server")
                    text: Security.smtpServer
                    onEditingFinished: Security.smtpServer = text
                }

                ThemedTextField {
                    Layout.fillWidth: true
                    placeholderText: I18n.tr("SMTP 端口", "SMTP Port")
                    text: String(Security.smtpPort)
                    inputMethodHints: Qt.ImhDigitsOnly
                    onEditingFinished: Security.smtpPort = Number(text)
                }

                ThemedTextField {
                    Layout.fillWidth: true
                    placeholderText: I18n.tr("发件人", "Sender")
                    text: Security.smtpSender
                    onEditingFinished: Security.smtpSender = text
                }

                ThemedTextField {
                    Layout.fillWidth: true
                    placeholderText: I18n.tr("收件人", "Recipient")
                    text: Security.smtpRecipient
                    onEditingFinished: Security.smtpRecipient = text
                }

                ThemedTextField {
                    Layout.fillWidth: true
                    placeholderText: I18n.tr("短信 Webhook URL", "SMS Webhook URL")
                    text: Security.smsWebhookUrl
                    onEditingFinished: Security.smsWebhookUrl = text
                }

                ThemedTextField {
                    Layout.fillWidth: true
                    placeholderText: I18n.tr("短信接收标识", "SMS Recipient ID")
                    text: Security.smsRecipient
                    onEditingFinished: Security.smsRecipient = text
                }
            }

            ThemedButton {
                text: I18n.tr("测试通知", "Test Notifications")
                onClicked: Security.testNotifications()
            }
        }
    }
}
