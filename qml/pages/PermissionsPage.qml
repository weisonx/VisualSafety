import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

ScrollView {
    id: root
    clip: true
    property string permissionsQuery: ""
    property string appPermissionsQuery: ""
    readonly property var ctl: Security.controls

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
            title: I18n.tr("快速控制（需管理员）", "Quick Controls (Admin)")
            icon: Icons.power

            RowLayout {
                Layout.fillWidth: true
                spacing: 10

                StatusTag {
                    text: (root.ctl && root.ctl.isAdmin === true) ? I18n.tr("管理员", "Admin") : I18n.tr("非管理员", "Not admin")
                    tone: (root.ctl && root.ctl.isAdmin === true) ? "success" : "warning"
                }

                ThemedButton {
                    text: I18n.tr("以管理员重启", "Restart as Admin")
                    visible: !(root.ctl && root.ctl.isAdmin === true)
                    enabled: !(root.ctl && root.ctl.isAdmin === true)
                    onClicked: Security.restartAsAdmin()
                }

                Label {
                    Layout.fillWidth: true
                    text: I18n.tr("优先级：防火墙入站 → 远程桌面 → 文件共享/SMB", "Priority: Firewall inbound → Remote Desktop → File sharing/SMB")
                    color: Theme.textSecondary
                    elide: Text.ElideRight
                }

                ThemedButton {
                    text: I18n.tr("强化防火墙", "Harden Firewall")
                    enabled: root.ctl && root.ctl.isAdmin === true
                    onClicked: Security.hardenFirewall()
                }
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: 12

                ThemedSwitch {
                    id: rdpSwitch
                    text: Icons.risk + " " + I18n.tr("远程桌面 (RDP)", "Remote Desktop (RDP)")
                    enabled: root.ctl && root.ctl.isAdmin === true && root.ctl.remoteDesktopKnown === true
                    checked: root.ctl && root.ctl.remoteDesktopEnabled === true
                    onToggled: Security.setRemoteDesktopEnabled(checked)
                }

                StatusTag {
                    text: root.ctl && root.ctl.remoteDesktopKnown === true
                        ? (root.ctl.remoteDesktopEnabled === true ? I18n.tr("已开启", "Enabled") : I18n.tr("已关闭", "Disabled"))
                        : I18n.tr("未知", "Unknown")
                    tone: root.ctl && root.ctl.remoteDesktopEnabled === true ? "warning" : "success"
                }

                StatusTag {
                    text: root.ctl && root.ctl.remoteDesktopFirewallKnown === true
                        ? (root.ctl.remoteDesktopFirewallEnabled === true ? I18n.tr("防火墙放行", "FW Allowed") : I18n.tr("防火墙未放行", "FW Blocked"))
                        : I18n.tr("防火墙未知", "FW Unknown")
                    tone: root.ctl && root.ctl.remoteDesktopFirewallEnabled === true ? "warning" : "normal"
                }
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: 12

                ThemedSwitch {
                    id: shareSwitch
                    text: Icons.port + " " + I18n.tr("文件共享/SMB", "File Sharing / SMB")
                    enabled: root.ctl && root.ctl.isAdmin === true && root.ctl.fileSharingFirewallKnown === true
                    checked: root.ctl && root.ctl.fileSharingEnabled === true
                    onToggled: Security.setFileSharingEnabled(checked)
                }

                StatusTag {
                    text: root.ctl && root.ctl.fileSharingFirewallKnown === true
                        ? (root.ctl.fileSharingEnabled === true ? I18n.tr("已放行", "Allowed") : I18n.tr("已阻止", "Blocked"))
                        : I18n.tr("未知", "Unknown")
                    tone: root.ctl && root.ctl.fileSharingEnabled === true ? "warning" : "success"
                }

                ThemedButton {
                    text: I18n.tr("禁用 SMBv1", "Disable SMBv1")
                    enabled: root.ctl && root.ctl.isAdmin === true
                    onClicked: Security.disableSmb1()
                }

                StatusTag {
                    text: root.ctl && root.ctl.smb1Known === true
                        ? (root.ctl.smb1Enabled === true ? I18n.tr("SMBv1 开启", "SMBv1 On") : I18n.tr("SMBv1 已禁用", "SMBv1 Off"))
                        : I18n.tr("SMBv1 未知", "SMBv1 Unknown")
                    tone: root.ctl && root.ctl.smb1Enabled === true ? "warning" : "success"
                }
            }

            Connections {
                target: Security
                function onDataChanged() {
                    rdpSwitch.checked = root.ctl && root.ctl.remoteDesktopEnabled === true
                    shareSwitch.checked = root.ctl && root.ctl.fileSharingEnabled === true
                }
            }
        }

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
                            Layout.maximumWidth: 220
                            elide: Text.ElideRight
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
                            Layout.maximumWidth: 220
                            elide: Text.ElideRight
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

