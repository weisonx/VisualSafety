import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

ScrollView {
    id: root
    clip: true

    function isInstalled(pluginId) {
        for (let i = 0; i < Security.installedPlugins.length; i++) {
            if (Security.installedPlugins[i].id === pluginId)
                return true
        }
        return false
    }

    ColumnLayout {
        width: root.availableWidth
        spacing: 12

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("插件市场", "Plugin Marketplace")
            icon: Icons.plugin
            tip: I18n.tr(
                     "插件由本项目发布与维护，安装后会出现在左侧导航中（示例实现）。",
                     "Plugins are published with this project. Installed plugins appear in the left navigation (demo implementation).")

            Label {
                text: I18n.tr(
                          "开发规范（初版）：插件至少包含 id/title/description/version/author/icon 与输入/参数/输出说明；运行入口为 Security.runPlugin(id, params)。",
                          "Initial spec: each plugin provides id/title/description/version/author/icon + I/O/params info; runtime entry is Security.runPlugin(id, params).")
                color: Theme.textSecondary
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("可用插件", "Available Plugins")
            icon: Icons.plugin
            tip: I18n.tr("悬浮查看说明，点击安装/卸载以更新左侧导航。", "Hover for help, install/uninstall to update navigation.")

            Repeater {
                model: Security.availablePlugins
                delegate: Rectangle {
                    Layout.fillWidth: true
                    radius: 10
                    color: Theme.cardAltBg
                    border.width: 1
                    border.color: Theme.borderColor
                    implicitHeight: 96

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 12
                        spacing: 12

                        Label {
                            text: modelData.icon || Icons.plugin
                            font.pixelSize: 20
                            Layout.preferredWidth: 28
                            horizontalAlignment: Text.AlignHCenter
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 4

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 8

                                Label {
                                    text: modelData.title
                                    color: Theme.textPrimary
                                    font.bold: true
                                    Layout.fillWidth: true
                                    elide: Text.ElideRight
                                }

                                StatusTag {
                                    text: "v" + (modelData.version || "0.0.0")
                                    tone: "normal"
                                    tip: (modelData.author ? ("Author: " + modelData.author) : "")
                                }
                            }

                            Label {
                                text: modelData.description
                                color: Theme.textSecondary
                                Layout.fillWidth: true
                                elide: Text.ElideRight
                            }

                            Label {
                                text: "I: " + (modelData.inputs || "-") + "   P: " + (modelData.params || "-") + "   O: " + (modelData.outputs || "-")
                                color: Theme.textSecondary
                                Layout.fillWidth: true
                                elide: Text.ElideRight
                            }
                        }

                        ThemedButton {
                            Layout.preferredWidth: 120
                            text: root.isInstalled(modelData.id)
                                  ? (Icons.block + " " + I18n.tr("卸载", "Remove"))
                                  : (Icons.safe + " " + I18n.tr("安装", "Install"))
                            onClicked: {
                                if (root.isInstalled(modelData.id))
                                    Security.uninstallPlugin(modelData.id)
                                else
                                    Security.installPlugin(modelData.id)
                            }
                        }
                    }
                }
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("已安装", "Installed")
            icon: Icons.safe
            tip: I18n.tr("已安装插件会自动追加到左侧导航，并生成对应页面。", "Installed plugins are appended to navigation with a generated page.")

            Repeater {
                model: Security.installedPlugins
                delegate: Rectangle {
                    Layout.fillWidth: true
                    radius: 10
                    color: Theme.cardAltBg
                    border.width: 1
                    border.color: Theme.borderColor
                    implicitHeight: 52

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 12

                        Label {
                            text: modelData.icon || Icons.plugin
                            font.pixelSize: 18
                            Layout.preferredWidth: 28
                            horizontalAlignment: Text.AlignHCenter
                        }

                        Label {
                            text: modelData.title + "  (" + modelData.id + ")"
                            color: Theme.textPrimary
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }

                        ThemedButton {
                            text: Icons.block + " " + I18n.tr("卸载", "Remove")
                            onClicked: Security.uninstallPlugin(modelData.id)
                        }
                    }
                }
            }
        }
    }
}

