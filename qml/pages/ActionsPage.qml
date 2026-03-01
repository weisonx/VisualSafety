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
            title: "高危动作拦截"
            icon: Icons.block

            ThemedTextField {
                id: sourceField
                Layout.fillWidth: true
                placeholderText: "来源进程，如 AgentRunner.exe"
                text: "AgentRunner.exe"
            }

            ThemedTextField {
                id: actionField
                Layout.fillWidth: true
                placeholderText: "动作描述，如 Invoke-Expression"
                text: "Invoke-Expression"
            }

            ThemedButton {
                text: Icons.block + " 立即阻断动作"
                enabled: sourceField.text.length > 0 && actionField.text.length > 0
                onClicked: Security.blockAction(sourceField.text, actionField.text)
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: "紧急系统操作"
            icon: Icons.warning

            Label {
                text: "在同一界面执行强制关机或重启，执行前请确认现场环境。"
                color: Theme.textSecondary
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: 12

                ThemedButton {
                    Layout.fillWidth: true
                    text: Icons.power + " 强制关机"
                    onClicked: Security.shutdownNow()
                }

                ThemedButton {
                    Layout.fillWidth: true
                    text: Icons.restart + " 强制重启"
                    onClicked: Security.restartNow()
                }
            }
        }
    }
}

