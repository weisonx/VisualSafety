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
            title: "权限列表"
            icon: Icons.permission

            Repeater {
                model: Security.permissions
                delegate: Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: 58
                    radius: 8
                    color: Theme.cardAltBg
                    border.width: 1
                    border.color: Theme.borderColor

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 10

                        Label {
                            text: modelData.name
                            color: Theme.textPrimary
                            font.bold: true
                            Layout.preferredWidth: 160
                        }

                        Label {
                            text: modelData.scope
                            color: Theme.textSecondary
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }

                        StatusTag {
                            text: modelData.level
                            tone: modelData.level === "Critical" ? "danger"
                                : modelData.level === "High" ? "warning" : "normal"
                        }

                        StatusTag {
                            text: modelData.status
                            tone: modelData.status === "Denied" || modelData.status === "Restricted" ? "warning" : "success"
                        }
                    }
                }
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: "应用权限情况"
            icon: Icons.app

            Repeater {
                model: Security.appPermissions
                delegate: Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: 58
                    radius: 8
                    color: Theme.cardAltBg

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 10

                        Label {
                            text: modelData.app
                            color: Theme.textPrimary
                            Layout.preferredWidth: 180
                            elide: Text.ElideRight
                        }

                        Label {
                            text: modelData.permission
                            color: Theme.textSecondary
                            Layout.preferredWidth: 160
                        }

                        StatusTag {
                            text: modelData.status
                            tone: modelData.status === "Denied" ? "danger"
                                : modelData.status === "Allowed" ? "success" : "warning"
                        }

                        Label {
                            text: modelData.lastUsed
                            color: Theme.textSecondary
                            Layout.fillWidth: true
                            horizontalAlignment: Text.AlignRight
                        }
                    }
                }
            }
        }
    }
}

