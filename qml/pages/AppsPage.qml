import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

Item {
    id: root
    property string query: ""

    function matchesApp(row) {
        const q = query.trim().toLowerCase()
        if (q.length === 0)
            return true
        const app = String(row.app || "").toLowerCase()
        const pid = String(row.pid || "").toLowerCase()
        const hint = String(row.hint || "").toLowerCase()
        const trust = String(row.trust || "").toLowerCase()
        return app.indexOf(q) >= 0 || pid.indexOf(q) >= 0 || hint.indexOf(q) >= 0 || trust.indexOf(q) >= 0
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 12

        SectionCard {
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: I18n.tr("应用监控列表", "App Monitor List")
            icon: Icons.app
            tip: I18n.tr("悬浮应用名查看常见系统进程说明（示例）。", "Hover app name for common system process notes (demo).")

            ThemedTextField {
                Layout.fillWidth: true
                placeholderText: Icons.search + " " + I18n.tr("搜索应用 / PID / 标签", "Search app / PID / tags")
                text: root.query
                onTextEdited: root.query = text
                tip: I18n.tr("支持按应用名、PID、标签、可信度筛选。", "Filter by app name, PID, tags, or trust.")
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                spacing: 0

                ListView {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true
                    spacing: 8
                    reuseItems: true
                    cacheBuffer: 800
                    model: Security.appMonitors
                    ScrollBar.vertical: vbar

                    delegate: Rectangle {
                        required property var modelData

                        visible: root.matchesApp(modelData)
                        height: visible ? implicitHeight : 0
                        width: ListView.view.width
                        implicitHeight: 108
                        radius: 8
                        color: Theme.cardAltBg
                        border.width: 1
                        border.color: modelData.trust === "Untrusted" ? Theme.dangerColor : Theme.borderColor

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 10
                            spacing: 6

                            RowLayout {
                                Layout.fillWidth: true

                                Label {
                                    id: appLabel
                                    text: modelData.app + "  (PID " + modelData.pid + ")"
                                    color: Theme.textPrimary
                                    font.bold: true
                                    Layout.fillWidth: true
                                    elide: Text.ElideRight

                                    readonly property string tipText: Security.knownProcessTip(modelData.app)
                                    HoverHandler { id: appHover }
                                    ToolTip.delay: 350
                                    ToolTip.timeout: 8000
                                    ToolTip.visible: appHover.hovered && appLabel.tipText.length > 0
                                    ToolTip.text: appLabel.tipText
                                }

                                StatusTag {
                                    text: I18n.trustLabel(modelData.trust)
                                    tone: modelData.trust === "Trusted" ? "success"
                                        : modelData.trust === "Untrusted" ? "danger" : "warning"
                                }
                            }

                            Flow {
                                Layout.fillWidth: true
                                spacing: 8

                                Repeater {
                                    model: modelData.tags || []
                                    delegate: StatusTag {
                                        text: I18n.tr(modelData.zh, modelData.en)
                                        tone: modelData.tone || "normal"
                                    }
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true

                                Label {
                                    id: hintLabel
                                    text: modelData.hint
                                    color: Theme.textSecondary
                                    Layout.fillWidth: true
                                    elide: Text.ElideRight

                                    readonly property string tipText: Security.knownProcessTip(modelData.app)
                                    HoverHandler { id: hintHover }
                                    ToolTip.delay: 350
                                    ToolTip.timeout: 8000
                                    ToolTip.visible: hintHover.hovered && hintLabel.tipText.length > 0
                                    ToolTip.text: hintLabel.tipText
                                }

                                ThemedButton {
                                    text: Icons.kill + " " + I18n.tr("强制退出", "Force Quit")
                                    enabled: modelData.status === "Running"
                                    onClicked: Security.forceQuitApp(modelData.app)
                                }
                            }
                        }
                    }
                }

                ScrollBar {
                    id: vbar
                    Layout.fillHeight: true
                    policy: ScrollBar.AsNeeded
                    minimumSize: 0.15
                    implicitWidth: 10
                }
            }
        }
    }
}

