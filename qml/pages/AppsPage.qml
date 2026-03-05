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
            Layout.fillHeight: true
            title: I18n.tr("应用监控列表", "App Monitor List")
            icon: Icons.app

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

                        width: ListView.view.width
                        implicitHeight: 90
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
                                    text: modelData.trust
                                    tone: modelData.trust === "Trusted" ? "success"
                                        : modelData.trust === "Untrusted" ? "danger" : "warning"
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

