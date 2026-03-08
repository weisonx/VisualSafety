import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Qt.labs.settings
import "../components"

ScrollView {
    id: root
    clip: true

    Settings {
        id: exposureSettings
        category: "exposure"
        property string publicIp: ""
        property string ipPublicFlagsJson: "{}"
    }

    function countSeverity(level) {
        let n = 0
        for (let i = 0; i < Security.publicExposure.length; ++i) {
            if (String(Security.publicExposure[i].severity) === String(level))
                n++
        }
        return n
    }

    function loadIpFlags() {
        try { return JSON.parse(exposureSettings.ipPublicFlagsJson || "{}") } catch (e) { return {} }
    }

    function saveIpFlags(flags) {
        try { exposureSettings.ipPublicFlagsJson = JSON.stringify(flags || {}) } catch (e) { exposureSettings.ipPublicFlagsJson = "{}" }
    }

    function isIpMarkedPublic(ip, guessedPublic) {
        const flags = loadIpFlags()
        if (flags.hasOwnProperty(ip))
            return flags[ip] === true
        return guessedPublic === true
    }

    function setIpMarkedPublic(ip, value) {
        const flags = loadIpFlags()
        flags[ip] = value === true
        saveIpFlags(flags)
    }

    function localPublicIpList() {
        const out = []
        for (let i = 0; i < Security.ipAddresses.length; ++i) {
            const row = Security.ipAddresses[i]
            const ip = String(row.ip || "")
            if (!ip || ip === "Unavailable" || ip === "N/A")
                continue
            if (isIpMarkedPublic(ip, row.guessedPublic))
                out.push(ip)
        }
        return out
    }

    function isDirectPublicIp() {
        const wan = String(exposureSettings.publicIp || "").trim()
        if (wan.length === 0)
            return false
        const localList = localPublicIpList()
        return localList.indexOf(wan) >= 0
    }

    function exposesWanIp(portRow) {
        const wan = String(exposureSettings.publicIp || "").trim()
        const bindScope = String(portRow.bindScope || "")
        const localAddr = String(portRow.localAddress || "")
        const localList = localPublicIpList()
        const anyPublicMarked = localList.length > 0

        if (wan.length > 0) {
            if (localAddr.indexOf(wan + ":") === 0)
                return "Yes"
            if (bindScope === "Any" && isDirectPublicIp())
                return "Yes"
            return "No"
        }

        if (bindScope === "Any" && anyPublicMarked)
            return "Yes"

        if (bindScope === "Public") {
            for (let i = 0; i < localList.length; ++i) {
                if (localAddr.indexOf(localList[i] + ":") === 0)
                    return "Yes"
            }
        }

        return anyPublicMarked ? "No" : "Unknown"
    }

    ColumnLayout {
        width: root.availableWidth
        spacing: 12

        GridLayout {
            Layout.fillWidth: true
            columns: 3
            columnSpacing: 12
            rowSpacing: 12

            MetricCard {
                icon: Icons.warning
                title: I18n.tr("严重项", "Critical")
                value: String(root.countSeverity("Critical"))
                tone: value !== "0" ? "danger" : "success"
                Layout.fillWidth: true
            }

            MetricCard {
                icon: Icons.risk
                title: I18n.tr("高风险项", "High")
                value: String(root.countSeverity("High"))
                tone: value !== "0" ? "warning" : "success"
                Layout.fillWidth: true
            }

            MetricCard {
                icon: Icons.network
                title: I18n.tr("总发现", "Findings")
                value: String(Security.publicExposure.length)
                tone: "normal"
                Layout.fillWidth: true
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("公网 IP 与对外可达性提示", "Public IP & Reachability Hints")
            icon: Icons.exposure

            Label {
                Layout.fillWidth: true
                text: I18n.tr("说明：是否“能从公网访问”还取决于路由器 NAT / 端口转发 / 运营商策略。这里提供本机可见信息 + 让你手动确认公网 IP。",
                              "Note: Internet reachability depends on NAT/port-forwarding/ISP policy. This page shows local signals and lets you confirm WAN IP.")
                color: Theme.textSecondary
                wrapMode: Text.Wrap
            }

            GridLayout {
                Layout.fillWidth: true
                columns: 2
                columnSpacing: 8
                rowSpacing: 8

                ThemedTextField {
                    Layout.fillWidth: true
                    placeholderText: I18n.tr("输入真实公网 IP（WAN）", "Enter real public IP (WAN)")
                    text: exposureSettings.publicIp
                    onEditingFinished: exposureSettings.publicIp = text.trim()
                }

                Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: 44
                    radius: 8
                    color: Theme.cardAltBg
                    border.width: 1
                    border.color: Theme.borderColor

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 10
                        spacing: 10

                        Label {
                            text: I18n.tr("直连公网：", "Direct public: ")
                            color: Theme.textSecondary
                        }

                        StatusTag {
                            text: root.isDirectPublicIp() ? I18n.tr("是", "Yes") : I18n.tr("否", "No")
                            tone: root.isDirectPublicIp() ? "warning" : "normal"
                        }

                        Label {
                            Layout.fillWidth: true
                            text: root.isDirectPublicIp()
                                ? I18n.tr("WAN IP 出现在本机网卡上", "WAN IP is assigned to a local NIC")
                                : I18n.tr("可能在 NAT 后（WAN IP 不在本机网卡上）", "Likely behind NAT (WAN IP not on local NIC)")
                            color: Theme.textSecondary
                            elide: Text.ElideRight
                        }
                    }
                }
            }

            Label {
                text: I18n.tr("本机可用 IP（可手动勾选哪些算“公网 IP”）", "Local IPs (mark which ones you consider public)")
                color: Theme.textPrimary
                font.bold: true
                font.pixelSize: 15
            }

            Repeater {
                model: Security.ipAddresses
                delegate: Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: 56
                    radius: 8
                    color: Theme.cardAltBg

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 10
                        spacing: 10

                        Label {
                            text: (modelData.iface ? (modelData.iface + "  ") : "") + modelData.ip
                            color: Theme.textPrimary
                            font.bold: true
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }

                        StatusTag {
                            text: modelData.state ? modelData.state : "N/A"
                            tone: "normal"
                        }

                        CheckBox {
                            text: I18n.tr("公网IP", "Public")
                            checked: root.isIpMarkedPublic(String(modelData.ip), modelData.guessedPublic === true)
                            onToggled: root.setIpMarkedPublic(String(modelData.ip), checked)
                        }
                    }
                }
            }

            Label {
                text: I18n.tr("对外监听端口（结合你输入的 WAN IP/勾选来标记“是否暴露公网 IP”）",
                              "Listening ports (use WAN IP / selections to mark “exposes WAN IP”)")
                color: Theme.textPrimary
                font.bold: true
                font.pixelSize: 15
            }

            Repeater {
                model: Security.ports
                delegate: Rectangle {
                    visible: modelData.bindScope === "Any" || modelData.bindScope === "Public"
                    Layout.preferredHeight: visible ? implicitHeight : 0
                    Layout.fillWidth: true
                    implicitHeight: 62
                    radius: 8
                    color: Theme.cardAltBg

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 10
                        spacing: 10

                        Label {
                            text: modelData.protocol + ":" + modelData.port
                            color: Theme.textPrimary
                            font.bold: true
                            Layout.preferredWidth: 120
                        }

                        Label {
                            text: modelData.process + " | " + modelData.localAddress
                            color: Theme.textSecondary
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }

                        StatusTag {
                            text: root.exposesWanIp(modelData) === "Yes" ? I18n.tr("暴露公网IP", "Exposes WAN")
                                : root.exposesWanIp(modelData) === "No" ? I18n.tr("不暴露", "Not Exposed")
                                : I18n.tr("未知", "Unknown")
                            tone: root.exposesWanIp(modelData) === "Yes" ? "danger"
                                : root.exposesWanIp(modelData) === "No" ? "success" : "normal"
                        }

                        StatusTag {
                            text: I18n.riskLabel(modelData.risk)
                            tone: modelData.risk === "Critical" ? "danger"
                                : modelData.risk === "High" ? "warning"
                                : modelData.risk === "Low" ? "success" : "normal"
                        }

                        ThemedButton {
                            text: Icons.block + " " + I18n.tr("阻断", "Block")
                            enabled: modelData.action === "Block"
                            visible: modelData.action === "Block"
                            onClicked: Security.blockAction(modelData.process, (I18n.tr("端口 ", "Port ") + modelData.port))
                        }
                    }
                }
            }

            Label {
                text: I18n.tr("系统推断提示（参考）", "Heuristic hints (reference)")
                color: Theme.textPrimary
                font.bold: true
                font.pixelSize: 15
            }

            Repeater {
                model: Security.publicExposure
                delegate: Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: 68
                    radius: 8
                    color: Theme.cardAltBg

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 10
                        spacing: 10

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2

                            Label {
                                text: modelData.title
                                color: Theme.textPrimary
                                font.bold: true
                                elide: Text.ElideRight
                            }
                            Label {
                                text: modelData.detail
                                color: Theme.textSecondary
                                elide: Text.ElideRight
                            }
                        }

                        StatusTag {
                            text: I18n.severityLabel(modelData.severity)
                            tone: modelData.severity === "Critical" ? "danger"
                                : modelData.severity === "High" ? "warning"
                                : modelData.severity === "Low" ? "success" : "normal"
                        }

                        ThemedButton {
                            text: Icons.block + " " + I18n.tr("阻断", "Block")
                            visible: modelData.canBlock === true
                            enabled: modelData.canBlock === true
                            onClicked: Security.blockAction(modelData.process, (I18n.tr("端口 ", "Port ") + modelData.port))
                        }
                    }
                }
            }
        }
    }
}
