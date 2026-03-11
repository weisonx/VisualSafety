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
                tip: I18n.tr("当前扫描与运行期合并后的 Critical 级告警数量。", "Number of merged Critical alerts from scans/runtime.")
            }

            MetricCard {
                Layout.fillWidth: true
                icon: Icons.app
                title: I18n.tr("运行应用", "Running Apps")
                value: String(Security.runningAppCount)
                tip: I18n.tr("被监控且状态为 Running 的进程数量。", "Count of monitored processes marked Running.")
            }

            MetricCard {
                Layout.fillWidth: true
                icon: Icons.block
                title: I18n.tr("已阻断动作", "Blocked Actions")
                value: String(Security.blockedActionCount)
                tone: Security.blockedActionCount > 0 ? "warning" : "normal"
                tip: I18n.tr("策略引擎或人工操作触发的阻断次数。", "Number of blocked actions by policy or operator.")
            }

            MetricCard {
                Layout.fillWidth: true
                icon: Icons.safe
                title: I18n.tr("通知渠道", "Notification Channels")
                value: (Security.desktopNotify ? (I18n.tr("桌面 ", "Desktop ")) : "")
                       + (Security.emailNotify ? (I18n.tr("邮件 ", "Email ")) : "")
                       + (Security.smsNotify ? (I18n.tr("短信", "SMS")) : "")
                tip: I18n.tr("当前启用的告警通知通道。", "Currently enabled notification channels.")
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("高危权限使用情况", "High-Risk Permission Usage")
            icon: Icons.risk
            tip: I18n.tr("基于进程、端口与策略推导的高危行为摘要（示例）。", "High-risk behavior summary derived from processes/ports/policy (demo).")

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
                            id: procLabel
                            text: modelData.process
                            color: Theme.textPrimary
                            font.bold: true
                            Layout.preferredWidth: 180

                            readonly property string tipText: Security.knownProcessTip(modelData.process)
                            HoverHandler { id: procHover }
                            ToolTip.delay: 350
                            ToolTip.timeout: 8000
                            ToolTip.visible: procHover.hovered && procLabel.tipText.length > 0
                            ToolTip.text: procLabel.tipText
                        }

                        Label {
                            text: modelData.permission + " / " + modelData.action
                            color: Theme.textSecondary
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }

                        StatusTag {
                            text: I18n.riskLabel(modelData.risk)
                            tone: modelData.risk === "Critical" ? "danger" : "warning"
                            tip: I18n.tr("风险等级用于提示优先处置顺序。", "Risk level indicates remediation priority.")
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
                tip: I18n.tr("展示最近的告警条目（点击告警页查看完整详情）。", "Recent alert entries (see Alerts page for full details).")

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
                                id: alertTitle
                                text: rowData.title
                                color: Theme.textPrimary
                                Layout.fillWidth: true
                                elide: Text.ElideRight

                                HoverHandler { id: alertHover }
                                ToolTip.delay: 350
                                ToolTip.timeout: 8000
                                ToolTip.visible: alertHover.hovered && String(rowData.detail || "").length > 0
                                ToolTip.text: String(rowData.detail || "")
                            }
                        }
                    }
                }
            }

            SectionCard {
                Layout.fillWidth: true
                title: I18n.tr("受监控应用", "Monitored Apps")
                icon: Icons.app
                tip: I18n.tr("当前被纳入监控的应用列表（仅展示前若干条）。", "Current monitored apps (top entries).")

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
                                id: appName
                                text: rowData.app + " (PID " + rowData.pid + ")"
                                color: Theme.textPrimary
                                Layout.fillWidth: true
                                elide: Text.ElideRight

                                readonly property string tipText: Security.knownProcessTip(rowData.app)
                                HoverHandler { id: appHover }
                                ToolTip.delay: 350
                                ToolTip.timeout: 8000
                                ToolTip.visible: appHover.hovered && appName.tipText.length > 0
                                ToolTip.text: appName.tipText
                            }
                            StatusTag {
                                text: I18n.trustLabel(rowData.trust)
                                tone: rowData.trust === "Trusted" ? "success" : "warning"
                                tip: I18n.tr("Trusted/Untrusted 为示例标签，可结合进程路径/父子关系进一步判断。", "Trusted/Untrusted is a demo label; validate with path/parent relationships.")
                            }
                        }
                    }
                }
            }
        }
    }
}

