import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

ScrollView {
    id: root
    clip: true
    property string permissionsQuery: ""
    property string appPermissionsQuery: ""

    function matchesPermission(row) {
        const q = permissionsQuery.trim().toLowerCase()
        if (q.length === 0)
            return true
        const name = String(row.name || "").toLowerCase()
        const scope = String(row.scope || "").toLowerCase()
        const level = String(row.level || "").toLowerCase()
        const status = String(row.status || "").toLowerCase()
        return name.indexOf(q) >= 0 || scope.indexOf(q) >= 0 || level.indexOf(q) >= 0 || status.indexOf(q) >= 0
    }

    function matchesAppPermission(row) {
        const q = appPermissionsQuery.trim().toLowerCase()
        if (q.length === 0)
            return true
        const app = String(row.app || "").toLowerCase()
        const permission = String(row.permission || "").toLowerCase()
        const status = String(row.status || "").toLowerCase()
        return app.indexOf(q) >= 0 || permission.indexOf(q) >= 0 || status.indexOf(q) >= 0
    }

    ColumnLayout {
        width: root.availableWidth
        spacing: 12

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("权限列表", "Permission List")
            icon: Icons.permission

            ThemedTextField {
                Layout.fillWidth: true
                placeholderText: Icons.search + " " + I18n.tr("搜索权限 / 范围 / 状态", "Search permission / scope / status")
                text: root.permissionsQuery
                onTextEdited: root.permissionsQuery = text
            }

            Repeater {
                model: Security.permissions
                delegate: Rectangle {
                    visible: root.matchesPermission(modelData)
                    Layout.preferredHeight: visible ? implicitHeight : 0
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
                            text: I18n.riskLabel(modelData.level)
                            tone: modelData.level === "Critical" ? "danger"
                                : modelData.level === "High" ? "warning" : "normal"
                        }

                        StatusTag {
                            text: I18n.statusLabel(modelData.status)
                            tone: (modelData.status === "Enabled" || modelData.status === "Elevated")
                                ? (modelData.level === "Critical" ? "danger" : "warning")
                                : (modelData.status === "Unavailable" ? "warning" : "success")
                        }
                    }
                }
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("应用权限情况", "App Permissions")
            icon: Icons.app

            ThemedTextField {
                Layout.fillWidth: true
                placeholderText: Icons.search + " " + I18n.tr("搜索应用 / 权限 / 状态", "Search app / permission / status")
                text: root.appPermissionsQuery
                onTextEdited: root.appPermissionsQuery = text
            }

            Repeater {
                model: Security.appPermissions
                delegate: Rectangle {
                    visible: root.matchesAppPermission(modelData)
                    Layout.preferredHeight: visible ? implicitHeight : 0
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

