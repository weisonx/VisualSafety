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
            title: I18n.tr("策略引擎", "Policy Engine")
            icon: Icons.block
            tip: I18n.tr("自动阻断/处置的策略开关与名单设置（示例）。", "Policy toggles and allow/deny lists for automatic actions (demo).")

            RowLayout {
                Layout.fillWidth: true
                spacing: 16

                ThemedSwitch {
                    text: I18n.tr("自动阻断高危端口", "Auto-block high-risk ports")
                    checked: Security.autoBlockHighRiskPorts
                    onToggled: Security.autoBlockHighRiskPorts = checked
                    tip: I18n.tr("命中高危端口时尝试自动阻断（需管理员才能真正生效）。", "Attempt to auto-block high-risk ports (admin required to take effect).")
                }

                ThemedSwitch {
                    text: I18n.tr("自动终止不可信 Shell", "Auto-kill untrusted shells")
                    checked: Security.autoKillUntrustedShell
                    onToggled: Security.autoKillUntrustedShell = checked
                    tip: I18n.tr("检测到不可信 Shell 行为时尝试终止进程（高风险操作）。", "Attempt to terminate untrusted shells (high-impact action).")
                }
            }

            ThemedTextField {
                Layout.fillWidth: true
                placeholderText: I18n.tr("白名单进程 (逗号分隔)", "Whitelisted processes (comma-separated)")
                text: Security.processWhitelist
                onEditingFinished: Security.processWhitelist = text
                tip: I18n.tr("白名单用于降低误报/误杀风险。", "Allowlist reduces false positives/terminations.")
            }

            ThemedTextField {
                Layout.fillWidth: true
                placeholderText: I18n.tr("黑名单进程 (逗号分隔)", "Blacklisted processes (comma-separated)")
                text: Security.processBlacklist
                onEditingFinished: Security.processBlacklist = text
                tip: I18n.tr("黑名单用于优先拦截高风险脚本/命令执行进程。", "Denylist targets common scripting/command runtimes.")
            }

            ThemedButton {
                text: I18n.tr("立即执行策略", "Apply Policy Now")
                onClicked: Security.applyPolicyNow()
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("安全告警与异常行为", "Security Alerts & Anomalies")
            icon: Icons.alert
            tip: I18n.tr("合并运行期与扫描结果的告警列表。", "Merged alert list from runtime and scans.")

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
                                ToolTip.delay: 350
                                ToolTip.timeout: 8000
                                HoverHandler { id: titleHover }
                                ToolTip.visible: titleHover.hovered
                                ToolTip.text: String(modelData.title || "") + "\n" + String(modelData.detail || "")
                            }

                            StatusTag {
                                text: I18n.severityLabel(modelData.severity)
                                tone: modelData.severity === "Critical" ? "danger"
                                    : modelData.severity === "High" ? "warning" : "normal"
                                tip: I18n.tr("严重级别用于决定优先级与处置方式。", "Severity indicates triage priority and response.")
                            }
                        }

                        Label {
                            text: modelData.detail
                            color: Theme.textSecondary
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            ToolTip.delay: 350
                            ToolTip.timeout: 8000
                            HoverHandler { id: detailHover }
                            ToolTip.visible: detailHover.hovered
                            ToolTip.text: String(modelData.detail || "")
                        }
                    }
                }
            }
        }
    }
}
