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
            tip: I18n.tr("对防火墙、RDP、文件共享等进行快速处置（需管理员权限）。", "Quick actions for firewall/RDP/file sharing (requires admin).")

            RowLayout {
                Layout.fillWidth: true
                spacing: 10

                StatusTag {
                    text: (root.ctl && root.ctl.isAdmin === true) ? I18n.tr("管理员", "Admin") : I18n.tr("非管理员", "Not admin")
                    tone: (root.ctl && root.ctl.isAdmin === true) ? "success" : "warning"
                    tip: I18n.tr("管理员权限用于读取/修改系统安全配置。", "Admin privileges are required to read/modify system security settings.")
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
                    tip: I18n.tr("开启会增加远程登录暴露面；建议配合防火墙限源、NLA、MFA/VPN。", "Enabling increases remote exposure; use allowlists, NLA, MFA/VPN.")
                }

                StatusTag {
                    text: root.ctl && root.ctl.remoteDesktopKnown === true
                        ? (root.ctl.remoteDesktopEnabled === true ? I18n.tr("已开启", "Enabled") : I18n.tr("已关闭", "Disabled"))
                        : I18n.tr("未知", "Unknown")
                    tone: root.ctl && root.ctl.remoteDesktopEnabled === true ? "warning" : "success"
                    tip: I18n.tr("RDP 服务开关状态。", "RDP service enable/disable state.")
                }

                StatusTag {
                    text: root.ctl && root.ctl.remoteDesktopFirewallKnown === true
                        ? (root.ctl.remoteDesktopFirewallEnabled === true ? I18n.tr("防火墙放行", "FW Allowed") : I18n.tr("防火墙未放行", "FW Blocked"))
                        : I18n.tr("防火墙未知", "FW Unknown")
                    tone: root.ctl && root.ctl.remoteDesktopFirewallEnabled === true ? "warning" : "normal"
                    tip: I18n.tr("RDP 相关入站规则是否允许。", "Whether inbound firewall rules allow RDP.")
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
                    tip: I18n.tr("SMB 暴露在公网风险极高；建议仅内网使用并限制来源。", "SMB Internet exposure is critical risk; keep LAN-only and restrict sources.")
                }

                StatusTag {
                    text: root.ctl && root.ctl.fileSharingFirewallKnown === true
                        ? (root.ctl.fileSharingEnabled === true ? I18n.tr("已放行", "Allowed") : I18n.tr("已阻止", "Blocked"))
                        : I18n.tr("未知", "Unknown")
                    tone: root.ctl && root.ctl.fileSharingEnabled === true ? "warning" : "success"
                    tip: I18n.tr("文件共享相关入站规则是否放行。", "Whether inbound firewall rules allow file sharing.")
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
            tip: I18n.tr("系统层面的安全能力与暴露面概览（示例数据/推导）。", "High-level security capabilities/exposure overview (demo).")

            ThemedTextField {
                Layout.fillWidth: true
                placeholderText: Icons.search + " " + I18n.tr("搜索权限 / 范围 / 状态", "Search permission / scope / status")
                text: root.permissionsQuery
                onTextEdited: root.permissionsQuery = text
                tip: I18n.tr("按名称、范围、等级或状态筛选。", "Filter by name/scope/level/status.")
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
                            id: permName
                            text: modelData.name
                            color: Theme.textPrimary
                            font.bold: true
                            Layout.preferredWidth: 160
                            Layout.maximumWidth: 220
                            elide: Text.ElideRight

                            HoverHandler { id: permHover }
                            ToolTip.delay: 350
                            ToolTip.timeout: 8000
                            ToolTip.visible: permHover.hovered
                            ToolTip.text: String(modelData.name || "") + "\n" + String(modelData.scope || "")
                        }

                        Label {
                            id: permScope
                            text: modelData.scope
                            color: Theme.textSecondary
                            Layout.fillWidth: true
                            elide: Text.ElideRight

                            HoverHandler { id: scopeHover }
                            ToolTip.delay: 350
                            ToolTip.timeout: 8000
                            ToolTip.visible: scopeHover.hovered
                            ToolTip.text: String(modelData.scope || "")
                        }

                        StatusTag {
                            text: I18n.riskLabel(modelData.level)
                            tone: modelData.level === "Critical" ? "danger"
                                : modelData.level === "High" ? "warning" : "normal"
                            tip: I18n.tr("权限等级：越高表示越需要重点关注与限制。", "Privilege level: higher means more scrutiny and restriction.")
                        }

                        StatusTag {
                            text: I18n.statusLabel(modelData.status)
                            tone: (modelData.status === "Enabled" || modelData.status === "Elevated")
                                ? (modelData.level === "Critical" ? "danger" : "warning")
                                : (modelData.status === "Unavailable" ? "warning" : "success")
                            tip: I18n.tr("状态反映当前是否可用/启用/受限。", "Status indicates enabled/available/restricted state.")
                        }
                    }
                }
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("应用权限情况", "App Permissions")
            icon: Icons.app
            tip: I18n.tr("从进程特征与端口行为推导的应用权限使用情况（示例）。", "App permission usage derived from process/port behavior (demo).")

            ThemedTextField {
                Layout.fillWidth: true
                placeholderText: Icons.search + " " + I18n.tr("搜索应用 / 权限 / 状态", "Search app / permission / status")
                text: root.appPermissionsQuery
                onTextEdited: root.appPermissionsQuery = text
                tip: I18n.tr("按应用名、权限或状态筛选。", "Filter by app/permission/status.")
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
                            id: appName
                            text: modelData.app
                            color: Theme.textPrimary
                            Layout.preferredWidth: 180
                            elide: Text.ElideRight

                            readonly property string tipText: Security.knownProcessTip(modelData.app)
                            HoverHandler { id: appHover }
                            ToolTip.delay: 350
                            ToolTip.timeout: 8000
                            ToolTip.visible: appHover.hovered && appName.tipText.length > 0
                            ToolTip.text: appName.tipText
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
                            tip: I18n.tr("Allowed/Denied/Prompt 为示例状态，用于提示权限风险。", "Allowed/Denied/Prompt is demo state used for risk hinting.")
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

