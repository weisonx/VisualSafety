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

            ThemedTextField {
                Layout.fillWidth: true
                placeholderText: Icons.search + " " + I18n.tr("搜索应用 / PID / 标签", "Search app / PID / tags")
                text: root.query
                onTextEdited: root.query = text
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
                                    text: modelData.app + "  (PID " + modelData.pid + ")"
                                    color: Theme.textPrimary
                                    font.bold: true
                                    Layout.fillWidth: true
                                    elide: Text.ElideRight
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
                                    text: modelData.hint
                                    color: Theme.textSecondary
                                    Layout.fillWidth: true
                                    elide: Text.ElideRight
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

