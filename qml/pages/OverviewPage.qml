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

        RowLayout {
            Layout.fillWidth: true
            spacing: 12

            MetricCard {
                Layout.fillWidth: true
                icon: Icons.alert
                title: "严重告警"
                value: String(Security.criticalAlertCount)
                tone: Security.criticalAlertCount > 0 ? "danger" : "success"
            }

            MetricCard {
                Layout.fillWidth: true
                icon: Icons.app
                title: "运行应用"
                value: String(Security.runningAppCount)
            }

            MetricCard {
                Layout.fillWidth: true
                icon: Icons.block
                title: "已阻断动作"
                value: String(Security.blockedActionCount)
                tone: Security.blockedActionCount > 0 ? "warning" : "normal"
            }

            MetricCard {
                Layout.fillWidth: true
                icon: Icons.safe
                title: "通知渠道"
                value: (Security.desktopNotify ? "桌面 " : "")
                       + (Security.emailNotify ? "邮件 " : "")
                       + (Security.smsNotify ? "短信" : "")
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: "高危权限使用情况"
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
                title: "最新告警"
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
                title: "受监控应用"
                icon: Icons.app

                Repeater {
                    model: Security.appMonitors
                    delegate: Rectangle {
                        Layout.fillWidth: true
                        radius: 8
                        color: Theme.cardAltBg
                        implicitHeight: 52

                        RowLayout {
                            anchors.fill: parent
                            anchors.margins: 10
                            Label {
                                text: modelData.app + " (PID " + modelData.pid + ")"
                                color: Theme.textPrimary
                                Layout.fillWidth: true
                                elide: Text.ElideRight
                            }
                            StatusTag {
                                text: modelData.trust
                                tone: modelData.trust === "Trusted" ? "success" : "warning"
                            }
                        }
                    }
                }
            }
        }
    }
}

