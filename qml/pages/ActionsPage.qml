import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

Item {
    id: root

    Dialog {
        id: shutdownDialog
        parent: root.Window.window ? root.Window.window.contentItem : root
        modal: true
        title: I18n.tr("确认强制关机", "Confirm Force Shutdown")
        standardButtons: Dialog.Ok | Dialog.Cancel

        Label {
            text: I18n.tr("确认执行强制关机？系统将在 5 秒后关机，未保存的数据可能丢失。",
                          "Force shutdown now? The system will shut down in 5 seconds and unsaved data may be lost.")
            color: Theme.textSecondary
            wrapMode: Text.WordWrap
            width: Math.min(420, root.width * 0.9)
        }

        onAccepted: Security.shutdownNow()
    }

    Dialog {
        id: restartDialog
        parent: root.Window.window ? root.Window.window.contentItem : root
        modal: true
        title: I18n.tr("确认强制重启", "Confirm Force Restart")
        standardButtons: Dialog.Ok | Dialog.Cancel

        Label {
            text: I18n.tr("确认执行强制重启？系统将在 5 秒后重启，未保存的数据可能丢失。",
                          "Force restart now? The system will restart in 5 seconds and unsaved data may be lost.")
            color: Theme.textSecondary
            wrapMode: Text.WordWrap
            width: Math.min(420, root.width * 0.9)
        }

        onAccepted: Security.restartNow()
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 12

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("高危动作拦截", "High-Risk Action Blocking")
            icon: Icons.block
            tip: I18n.tr("用于手动记录并阻断高危动作（示例）。", "Manually record and block high-risk actions (demo).")

            ThemedTextField {
                id: sourceField
                Layout.fillWidth: true
                placeholderText: I18n.tr("来源进程，如 AgentRunner.exe", "Source process, e.g. AgentRunner.exe")
                text: ""
                tip: I18n.tr("填写触发动作的进程名/组件名。", "Process/component that triggered the action.")
            }

            ThemedTextField {
                id: actionField
                Layout.fillWidth: true
                placeholderText: I18n.tr("动作描述，如 Invoke-Expression", "Action description, e.g. Invoke-Expression")
                text: ""
                tip: I18n.tr("建议包含关键 API/命令、参数或目的。", "Include key API/command, params, and intent.")
            }

            ThemedButton {
                text: Icons.block + " " + I18n.tr("立即阻断动作", "Block Action Now")
                enabled: sourceField.text.length > 0 && actionField.text.length > 0
                onClicked: Security.blockAction(sourceField.text, actionField.text)
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("端口阻断回滚", "Rollback Port Blocks")
            icon: Icons.port
            tip: I18n.tr("撤销 VisualSafety 创建的防火墙端口阻断规则。", "Remove firewall port-block rules created by VisualSafety.")

            ThemedTextField {
                id: unblockPortField
                Layout.fillWidth: true
                placeholderText: I18n.tr("端口号，如 3389", "Port number, e.g. 3389")
                inputMethodHints: Qt.ImhDigitsOnly
                tip: I18n.tr("仅影响 VisualSafety_Block_* 规则。", "Only affects VisualSafety_Block_* rules.")
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: 12

                ThemedButton {
                    Layout.fillWidth: true
                    text: Icons.safe + " " + I18n.tr("解除该端口阻断", "Unblock This Port")
                    enabled: unblockPortField.text.length > 0
                    onClicked: Security.unblockPort(parseInt(unblockPortField.text))
                }

                ThemedButton {
                    Layout.fillWidth: true
                    text: Icons.block + " " + I18n.tr("清理所有端口阻断", "Clear All Port Blocks")
                    tip: I18n.tr("需要管理员权限。", "Administrator privileges required.")
                    onClicked: Security.clearAllPortBlocks()
                }
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("紧急系统操作", "Emergency System Actions")
            icon: Icons.warning
            tip: I18n.tr("强制关机/重启属于高影响操作，请谨慎。", "Force shutdown/restart is high impact; use carefully.")

            Label {
                text: I18n.tr("在同一界面执行强制关机或重启，执行前请确认现场环境。",
                              "Force shutdown or restart from one screen. Confirm the environment before executing.")
                color: Theme.textSecondary
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: 12

                ThemedButton {
                    Layout.fillWidth: true
                    text: Icons.power + " " + I18n.tr("强制关机", "Force Shutdown")
                    onClicked: shutdownDialog.open()
                }

                ThemedButton {
                    Layout.fillWidth: true
                    text: Icons.restart + " " + I18n.tr("强制重启", "Force Restart")
                    onClicked: restartDialog.open()
                }
            }
        }
    }
}

