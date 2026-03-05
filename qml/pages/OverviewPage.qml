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

        RowLayout {
            Layout.fillWidth: true
            spacing: 12

            MetricCard {
                Layout.fillWidth: true
                icon: Icons.alert
                title: I18n.tr("严重告警", "Critical Alerts")
                value: String(Security.criticalAlertCount)
                tone: Security.criticalAlertCount > 0 ? "danger" : "success"
            }

            MetricCard {
                Layout.fillWidth: true
                icon: Icons.app
                title: I18n.tr("运行应用", "Running Apps")
                value: String(Security.runningAppCount)
            }

            MetricCard {
                Layout.fillWidth: true
                icon: Icons.block
                title: I18n.tr("已阻断动作", "Blocked Actions")
                value: String(Security.blockedActionCount)
                tone: Security.blockedActionCount > 0 ? "warning" : "normal"
            }

            MetricCard {
                Layout.fillWidth: true
                icon: Icons.safe
                title: I18n.tr("通知渠道", "Notification Channels")
                value: (Security.desktopNotify ? (I18n.tr("桌面 ", "Desktop ")) : "")
                       + (Security.emailNotify ? (I18n.tr("邮件 ", "Email ")) : "")
                       + (Security.smsNotify ? (I18n.tr("短信", "SMS")) : "")
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("高危权限使用情况", "High-Risk Permission Usage")
            icon: Icons.risk

            Repeater {
                model: Security.highRiskPermissions
                delegate: Rectangle {
                    Layout.fillWidth: true
                    radius: 8
                    color: Theme.cardAltBg
                    border.width: 1
                    border.color: Theme.borderColor
                    implicitHeight: 62

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 10
                        spacing: 10

                        Label {
                            text: modelData.process
                            color: Theme.textPrimary
                            font.bold: true
                            Layout.preferredWidth: 180
                        }

                        Label {
                            text: modelData.permission + " / " + modelData.action
                            color: Theme.textSecondary
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }

                        StatusTag {
                            text: modelData.risk
                            tone: modelData.risk === "Critical" ? "danger" : "warning"
                        }

                        Label {
                            text: modelData.time
                            color: Theme.textSecondary
                            Layout.preferredWidth: 140
                            Layout.maximumWidth: 140
                            horizontalAlignment: Text.AlignRight
                            elide: Text.ElideRight
                            clip: true
                        }
                    }
                }
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 12

            SectionCard {
                Layout.fillWidth: true
                title: I18n.tr("最新告警", "Latest Alerts")
                icon: Icons.alert

                Repeater {
                    model: Math.min(4, Security.alerts.length)
                    delegate: Rectangle {
                        readonly property var rowData: Security.alerts[index]
                        Layout.fillWidth: true
                        radius: 8
                        color: Theme.cardAltBg
                        implicitHeight: 52

                        RowLayout {
                            anchors.fill: parent
                            anchors.margins: 10
                            Label {
                                text: rowData.time
                                color: Theme.textSecondary
                                Layout.preferredWidth: 140
                                Layout.maximumWidth: 140
                                horizontalAlignment: Text.AlignRight
                                elide: Text.ElideRight
                                clip: true
                            }
                            Label {
                                text: rowData.title
                                color: Theme.textPrimary
                                Layout.fillWidth: true
                                elide: Text.ElideRight
                            }
                        }
                    }
                }
            }

            SectionCard {
                Layout.fillWidth: true
                title: I18n.tr("受监控应用", "Monitored Apps")
                icon: Icons.app

                Repeater {
                    model: Math.min(10, Security.appMonitors.length)
                    delegate: Rectangle {
                        readonly property var rowData: Security.appMonitors[index]
                        Layout.fillWidth: true
                        radius: 8
                        color: Theme.cardAltBg
                        implicitHeight: 52

                        RowLayout {
                            anchors.fill: parent
                            anchors.margins: 10
                            Label {
                                text: rowData.app + " (PID " + rowData.pid + ")"
                                color: Theme.textPrimary
                                Layout.fillWidth: true
                                elide: Text.ElideRight
                            }
                            StatusTag {
                                text: rowData.trust
                                tone: rowData.trust === "Trusted" ? "success" : "warning"
                            }
                        }
                    }
                }
            }
        }
    }
}

