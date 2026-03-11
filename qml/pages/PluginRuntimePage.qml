import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

ScrollView {
    id: root
    clip: true

    required property var plugin
    property string lastResult: ""

    ColumnLayout {
        width: root.availableWidth
        spacing: 12

        SectionCard {
            Layout.fillWidth: true
            title: (root.plugin.icon || Icons.plugin) + "  " + (root.plugin.title || root.plugin.id)
            icon: ""
            tip: root.plugin.description || ""

            Label {
                text: root.plugin.description || ""
                visible: (root.plugin.description || "").length > 0
                color: Theme.textSecondary
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            GridLayout {
                Layout.fillWidth: true
                columns: 2
                columnSpacing: 10
                rowSpacing: 6

                Label { text: I18n.tr("ID", "ID"); color: Theme.textSecondary }
                Label { text: root.plugin.id || ""; color: Theme.textPrimary; elide: Text.ElideRight; Layout.fillWidth: true }

                Label { text: I18n.tr("版本", "Version"); color: Theme.textSecondary }
                Label { text: root.plugin.version || ""; color: Theme.textPrimary; elide: Text.ElideRight; Layout.fillWidth: true }

                Label { text: I18n.tr("作者", "Author"); color: Theme.textSecondary }
                Label { text: root.plugin.author || ""; color: Theme.textPrimary; elide: Text.ElideRight; Layout.fillWidth: true }

                Label { text: I18n.tr("输入", "Inputs"); color: Theme.textSecondary }
                Label { text: root.plugin.inputs || "-"; color: Theme.textPrimary; elide: Text.ElideRight; Layout.fillWidth: true }

                Label { text: I18n.tr("参数", "Params"); color: Theme.textSecondary }
                Label { text: root.plugin.params || "-"; color: Theme.textPrimary; elide: Text.ElideRight; Layout.fillWidth: true }

                Label { text: I18n.tr("输出", "Outputs"); color: Theme.textSecondary }
                Label { text: root.plugin.outputs || "-"; color: Theme.textPrimary; elide: Text.ElideRight; Layout.fillWidth: true }
            }

            ThemedButton {
                text: Icons.refresh + " " + I18n.tr("运行（演示）", "Run (Demo)")
                onClicked: {
                    const result = Security.runPlugin(root.plugin.id, {})
                    root.lastResult = JSON.stringify(result, null, 2)
                }
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("运行结果", "Result")
            icon: Icons.log
            tip: I18n.tr("这是演示输出：插件运行会把摘要写入日志。", "Demo output: plugin execution writes a summary into Logs.")

            TextArea {
                Layout.fillWidth: true
                readOnly: true
                wrapMode: TextArea.Wrap
                text: root.lastResult.length > 0 ? root.lastResult : I18n.tr("尚未运行。", "Not executed yet.")
                background: Rectangle {
                    radius: 8
                    color: Theme.inputBg
                    border.width: 1
                    border.color: Theme.borderColor
                }
            }
        }
    }
}

