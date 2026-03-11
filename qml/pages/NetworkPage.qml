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
            tip: I18n.tr("防火墙规则与流量概览（示例）。", "Firewall rules and traffic overview (demo).")

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
                            ToolTip.delay: 350
                            ToolTip.timeout: 8000
                            HoverHandler { id: ruleHover }
                            ToolTip.visible: ruleHover.hovered
                            ToolTip.text: String(modelData.rule || "")
                        }

                        Label {
                            text: modelData.target
                            color: Theme.textSecondary
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                            ToolTip.delay: 350
                            ToolTip.timeout: 8000
                            HoverHandler { id: targetHover }
                            ToolTip.visible: targetHover.hovered
                            ToolTip.text: String(modelData.target || "")
                        }

                        StatusTag {
                            text: I18n.riskLabel(modelData.risk)
                            tone: modelData.risk === "Critical" ? "danger"
                                : modelData.risk === "High" ? "warning" : "success"
                            tip: I18n.tr("规则风险：重点关注 Disabled 或广泛放行的入站规则。", "Rule risk: watch Disabled profiles or wide inbound allows.")
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
                            tip: I18n.tr("异常为示例判断：与基线偏离的流量方向/速率。", "Unusual is a demo heuristic vs baseline direction/rate.")
                        }
                    }
                }
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("告警通知通道", "Notification Channels")
            icon: Icons.alert
            tip: I18n.tr("配置告警通知的通道与参数（示例）。", "Configure alert notification channels (demo).")

            RowLayout {
                Layout.fillWidth: true
                spacing: 18

                ThemedSwitch {
                    text: Icons.desktop + " " + I18n.tr("桌面通知", "Desktop")
                    checked: Security.desktopNotify
                    onToggled: Security.desktopNotify = checked
                    tip: I18n.tr("本机桌面弹窗通知（示例）。", "Local desktop notifications (demo).")
                }

                ThemedSwitch {
                    text: Icons.mail + " " + I18n.tr("邮件通知", "Email")
                    checked: Security.emailNotify
                    onToggled: Security.emailNotify = checked
                    tip: I18n.tr("通过 SMTP 发送邮件通知（示例）。", "Send alerts via SMTP email (demo).")
                }

                ThemedSwitch {
                    text: Icons.sms + " " + I18n.tr("短信通知", "SMS")
                    checked: Security.smsNotify
                    onToggled: Security.smsNotify = checked
                    tip: I18n.tr("通过 Webhook 推送短信/IM 网关（示例）。", "Send alerts via webhook to SMS/IM gateway (demo).")
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
                    tip: I18n.tr("例如 smtp.example.com", "e.g. smtp.example.com")
                }

                ThemedTextField {
                    Layout.fillWidth: true
                    placeholderText: I18n.tr("SMTP 端口", "SMTP Port")
                    text: String(Security.smtpPort)
                    inputMethodHints: Qt.ImhDigitsOnly
                    onEditingFinished: Security.smtpPort = Number(text)
                    tip: I18n.tr("常见端口：25/465/587（取决于服务配置）。", "Common: 25/465/587 depending on service.")
                }

                ThemedTextField {
                    Layout.fillWidth: true
                    placeholderText: I18n.tr("发件人", "Sender")
                    text: Security.smtpSender
                    onEditingFinished: Security.smtpSender = text
                    tip: I18n.tr("发件人邮箱地址。", "Sender email address.")
                }

                ThemedTextField {
                    Layout.fillWidth: true
                    placeholderText: I18n.tr("收件人", "Recipient")
                    text: Security.smtpRecipient
                    onEditingFinished: Security.smtpRecipient = text
                    tip: I18n.tr("收件人邮箱地址。", "Recipient email address.")
                }

                ThemedTextField {
                    Layout.fillWidth: true
                    placeholderText: I18n.tr("短信 Webhook URL", "SMS Webhook URL")
                    text: Security.smsWebhookUrl
                    onEditingFinished: Security.smsWebhookUrl = text
                    tip: I18n.tr("你的短信/消息网关 HTTP 接口地址。", "HTTP endpoint of your SMS/IM gateway.")
                }

                ThemedTextField {
                    Layout.fillWidth: true
                    placeholderText: I18n.tr("短信接收标识", "SMS Recipient ID")
                    text: Security.smsRecipient
                    onEditingFinished: Security.smsRecipient = text
                    tip: I18n.tr("例如手机号/用户ID/群ID（取决于网关）。", "Phone/user/group id depending on gateway.")
                }
            }

            ThemedButton {
                text: I18n.tr("测试通知", "Test Notifications")
                onClicked: Security.testNotifications()
            }
        }
    }
}
