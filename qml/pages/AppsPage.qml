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
            title: I18n.tr("应用监控列表", "App Monitor List")
            icon: Icons.app

            Repeater {
                model: Security.appMonitors
                delegate: Rectangle {
                    Layout.fillWidth: true
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
        }
    }
}

