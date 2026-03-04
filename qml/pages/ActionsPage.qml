import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

Item {
    id: root

    ColumnLayout {
        anchors.fill: parent
        spacing: 12

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("高危动作拦截", "High-Risk Action Blocking")
            icon: Icons.block

            ThemedTextField {
                id: sourceField
                Layout.fillWidth: true
                placeholderText: I18n.tr("来源进程，如 AgentRunner.exe", "Source process, e.g. AgentRunner.exe")
                text: "AgentRunner.exe"
            }

            ThemedTextField {
                id: actionField
                Layout.fillWidth: true
                placeholderText: I18n.tr("动作描述，如 Invoke-Expression", "Action description, e.g. Invoke-Expression")
                text: "Invoke-Expression"
            }

            ThemedButton {
                text: Icons.block + " " + I18n.tr("立即阻断动作", "Block Action Now")
                enabled: sourceField.text.length > 0 && actionField.text.length > 0
                onClicked: Security.blockAction(sourceField.text, actionField.text)
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("紧急系统操作", "Emergency System Actions")
            icon: Icons.warning

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
                    onClicked: Security.shutdownNow()
                }

                ThemedButton {
                    Layout.fillWidth: true
                    text: Icons.restart + " " + I18n.tr("强制重启", "Force Restart")
                    onClicked: Security.restartNow()
                }
            }
        }
    }
}

