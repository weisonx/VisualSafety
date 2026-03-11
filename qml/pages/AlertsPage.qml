import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

ScrollView {
    id: root
    clip: true
    readonly property var ctl: Security.controls

    function missingRealtimePrereqs() {
        if (!root.ctl)
            return false
        const psOk = (root.ctl.powershellScriptBlockLoggingKnown === true && root.ctl.powershellScriptBlockLoggingEnabled === true)
        const auditOk = (root.ctl.auditProcessCreationKnown === true && root.ctl.auditProcessCreationEnabled === true)
        const cmdOk = (root.ctl.processCreationCmdlineKnown === true && root.ctl.processCreationCmdlineEnabled === true)
        return !(psOk && auditOk && cmdOk)
    }

    Dialog {
        id: prereqGuide
        parent: root.Window.window ? root.Window.window.contentItem : root
        modal: true
        title: I18n.tr("启用实时监控指引（仅展示，不自动修改）", "Enable Realtime Monitoring Guide (display only)")
        standardButtons: Dialog.Ok
        width: Math.min(760, root.width * 0.92)

        ColumnLayout {
            spacing: 10
            width: parent.width

            Label {
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                color: Theme.textSecondary
                text: I18n.tr(
                          "提示：以下命令需要管理员 PowerShell 执行。启用后建议运行 gpupdate /force，并重新打开本程序以生效。",
                          "Tip: Run these commands in an elevated PowerShell. After enabling, consider `gpupdate /force` and restart this app.")
            }

            TextArea {
                Layout.fillWidth: true
                Layout.preferredHeight: 360
                readOnly: true
                wrapMode: TextArea.Wrap
                text: I18n.tr(
                          "1) 启用 PowerShell Script Block Logging (4104)\n"
                          + "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force | Out-Null\n"
                          + "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -Type DWord -Value 1\n\n"
                          + "2) （可选）启用 PowerShell Module Logging (4103)\n"
                          + "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' -Force | Out-Null\n"
                          + "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' -Name EnableModuleLogging -Type DWord -Value 1\n\n"
                          + "3) 启用进程创建审计 (4688)\n"
                          + "auditpol /set /subcategory:\"Process Creation\" /success:enable /failure:enable\n\n"
                          + "4) 在 4688 中记录命令行\n"
                          + "New-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Force | Out-Null\n"
                          + "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Type DWord -Value 1\n\n"
                          + "5) 刷新策略\n"
                          + "gpupdate /force\n",
                          "1) Enable PowerShell Script Block Logging (4104)\n"
                          + "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force | Out-Null\n"
                          + "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -Type DWord -Value 1\n\n"
                          + "2) (Optional) Enable PowerShell Module Logging (4103)\n"
                          + "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' -Force | Out-Null\n"
                          + "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' -Name EnableModuleLogging -Type DWord -Value 1\n\n"
                          + "3) Enable process creation auditing (4688)\n"
                          + "auditpol /set /subcategory:\"Process Creation\" /success:enable /failure:enable\n\n"
                          + "4) Include command line in 4688\n"
                          + "New-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Force | Out-Null\n"
                          + "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Type DWord -Value 1\n\n"
                          + "5) Refresh policy\n"
                          + "gpupdate /force\n")
                background: Rectangle {
                    radius: 8
                    color: Theme.inputBg
                    border.width: 1
                    border.color: Theme.borderColor
                }
            }
        }
    }

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

                ThemedSwitch {
                    text: I18n.tr("实时事件监控", "Realtime event monitoring")
                    checked: Security.realtimeEnabled
                    onToggled: Security.realtimeEnabled = checked
                    tip: I18n.tr("后台定时拉取事件日志并追加到告警列表（轻量实现）。", "Periodically polls event logs and appends alerts (lightweight).")
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
            visible: Security.realtimeEnabled && root.missingRealtimePrereqs()
            title: I18n.tr("实时监控依赖未满足", "Realtime prerequisites missing")
            icon: Icons.warning
            tip: I18n.tr("未启用审计/日志策略时，实时监控会显著缺失关键证据（如 4104/4688）。", "If auditing/logging is disabled, realtime evidence (4104/4688) will be missing.")

            RowLayout {
                Layout.fillWidth: true
                spacing: 10

                StatusTag {
                    text: I18n.tr("4104 脚本块", "4104 ScriptBlock")
                    tone: (root.ctl && root.ctl.powershellScriptBlockLoggingEnabled === true) ? "success" : "warning"
                    tip: I18n.tr("PowerShell Script Block Logging（推荐）。", "PowerShell Script Block Logging (recommended).")
                }

                StatusTag {
                    text: I18n.tr("4688 进程创建", "4688 Proc Create")
                    tone: (root.ctl && root.ctl.auditProcessCreationEnabled === true) ? "success" : "warning"
                    tip: I18n.tr("安全日志进程创建审计。", "Security log auditing for process creation.")
                }

                StatusTag {
                    text: I18n.tr("命令行", "Command line")
                    tone: (root.ctl && root.ctl.processCreationCmdlineEnabled === true) ? "success" : "warning"
                    tip: I18n.tr("4688 记录命令行用于研判。", "Include command line in 4688 for investigation.")
                }

                Item { Layout.fillWidth: true }

                ThemedButton {
                    text: I18n.tr("打开指引", "Open Guide")
                    onClicked: prereqGuide.open()
                }
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
                                HoverHandler { id: titleHover }
                            }

                            StatusTag {
                                text: I18n.severityLabel(modelData.severity)
                                tone: modelData.severity === "Critical" ? "danger"
                                    : modelData.severity === "High" ? "warning" : "normal"
                                tip: I18n.tr("严重级别用于决定优先级与处置方式。", "Severity indicates triage priority and response.")
                            }

                            ThemedButton {
                                visible: modelData.canBlock === true
                                enabled: modelData.canBlock === true
                                text: Icons.block + " " + I18n.tr("阻断", "Block")
                                onClicked: Security.blockAction(String(modelData.blockSource || ""), String(modelData.blockAction || ""))
                            }
                        }

                        Label {
                            text: modelData.detail
                            color: Theme.textSecondary
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            HoverHandler { id: detailHover }
                        }
                    }
                }
            }
        }
    }
}
