import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

ScrollView {
    id: root
    clip: true

    function localIps() {
        const out = []
        for (let i = 0; i < Security.ipAddresses.length; ++i) {
            const row = Security.ipAddresses[i]
            const ip = String(row.ip || "")
            if (!ip || ip === "Unavailable" || ip === "N/A")
                continue
            out.push(ip)
        }
        return out
    }

    function localMarkedPublicIps() {
        const out = []
        for (let i = 0; i < Security.ipAddresses.length; ++i) {
            const row = Security.ipAddresses[i]
            const ip = String(row.ip || "")
            if (!ip || ip === "Unavailable" || ip === "N/A")
                continue
            if (Config.isIpMarkedPublic(ip, row.guessedPublic === true))
                out.push(ip)
        }
        return out
    }

    function isDirectPublic() {
        const wanIps = parseWanIps(Config.wanIps)
        if (wanIps.length === 0)
            return false
        const local = localMarkedPublicIps()
        for (let i = 0; i < wanIps.length; ++i) {
            if (local.indexOf(wanIps[i]) >= 0)
                return true
        }
        return false
    }

    function firewallInboundOpenHeuristic() {
        for (let i = 0; i < Security.firewallRules.length; ++i) {
            const row = Security.firewallRules[i]
            if (String(row.decision) === "Disabled")
                return true
            if (String(row.target || "").toLowerCase().indexOf("inbound=allow") >= 0)
                return true
        }
        return false
    }

    function parsePortsCsv(csv) {
        const out = {}
        const raw = String(csv || "").trim()
        if (raw.length === 0)
            return out
        const parts = raw.split(",")
        for (let i = 0; i < parts.length; ++i) {
            const p = String(parts[i]).trim()
            const n = Number(p)
            if (!isNaN(n) && n > 0 && n <= 65535)
                out[String(n)] = true
        }
        return out
    }

    function parseWanIps(rawValue) {
        const out = []
        const raw = String(rawValue || "").trim()
        if (raw.length === 0)
            return out

        const tokens = raw.split(/[\s,;]+/).filter(s => String(s).trim().length > 0)
        for (let i = 0; i < tokens.length; ++i) {
            const ip = String(tokens[i]).trim()
            const parts = ip.split(".")
            if (parts.length !== 4)
                continue
            let ok = true
            for (let k = 0; k < 4; ++k) {
                const n = Number(parts[k])
                if (!Number.isInteger(n) || n < 0 || n > 255) {
                    ok = false
                    break
                }
            }
            if (ok && out.indexOf(ip) < 0)
                out.push(ip)
        }
        return out
    }

    function hasWanIp() {
        return parseWanIps(Config.wanIps).length > 0
    }

    function exposureStatus(portRow) {
        if (!hasWanIp())
            return "Unknown"

        const bindScope = String(portRow.bindScope || "")
        const port = String(portRow.port || "")
        const inboundOpen = firewallInboundOpenHeuristic()

        const forwarded = Config.dmzEnabled === true
            || (Config.portForwardEnabled === true && parsePortsCsv(Config.forwardedPortsCsv).hasOwnProperty(port))
        const tunneled = Config.tunnelEnabled === true && parsePortsCsv(Config.tunnelPortsCsv).hasOwnProperty(port)

        // 内网穿透会绕过 NAT：即使只监听 127.0.0.1，本地端口也可能被暴露。
        if (tunneled)
            return inboundOpen ? "Exposed" : "Potential"

        if (isDirectPublic()) {
            // 直连公网：对外监听（0.0.0.0 / 公网IP / IPv6 全接口） + 入站偏开放 -> 暴露
            if ((bindScope === "Any" || bindScope === "Public") && inboundOpen)
                return "Exposed"
            if (bindScope === "Any" || bindScope === "Public")
                return "Potential"
            return "NotExposed"
        }

        // NAT：默认不暴露，需要端口转发/DMZ 才会“打洞”
        if (forwarded) {
            if (bindScope === "Loopback")
                return "Potential"
            return inboundOpen ? "Exposed" : "Potential"
        }

        return "NotExposed"
    }

    function countByStatus(target) {
        let n = 0
        for (let i = 0; i < Security.ports.length; ++i) {
            if (exposureStatus(Security.ports[i]) === target)
                n++
        }
        return n
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
                title: I18n.tr("已暴露", "Exposed")
                value: String(root.countByStatus("Exposed"))
                tone: value !== "0" ? "danger" : "success"
                Layout.fillWidth: true
                tip: "Exposed: based on your WAN/NAT/tunnel inputs, the port may be reachable from the Internet (demo heuristic)."
            }

            MetricCard {
                icon: Icons.risk
                title: I18n.tr("可能暴露", "Potential")
                value: String(root.countByStatus("Potential"))
                tone: value !== "0" ? "warning" : "success"
                Layout.fillWidth: true
                tip: "Potential: there are conditions that could expose the service; verify firewall/NAT/tunneling."
            }

            MetricCard {
                icon: Icons.network
                title: I18n.tr("未暴露", "Not Exposed")
                value: String(root.countByStatus("NotExposed"))
                tone: "normal"
                Layout.fillWidth: true
                tip: "Not Exposed: no direct Internet reachability detected by the current inputs (demo)."
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("公网（公网暴露判定）", "Public (Exposure)")
            icon: Icons.exposure
            tip: "Provide WAN/public IPs and mark local public IPs to improve exposure assessment."

            Label {
                Layout.fillWidth: true
                text: I18n.tr(
                          "“公网暴露”= 互联网上任何人知道你的公网 IP 和端口后，都可以尝试连接。典型成立条件：公网 IP（或 NAT 映射/内网穿透）+ 端口监听 + 入站策略对 0.0.0.0/0 放行。",
                          "\"Public exposure\" means anyone on the Internet can try to connect if they know your public IP and port. Typical conditions: public IP (or NAT mapping/tunneling) + listening port + inbound policy open to 0.0.0.0/0.")
                color: Theme.textSecondary
                wrapMode: Text.Wrap
            }

            ThemedTextField {
                Layout.fillWidth: true
                placeholderText: I18n.tr("输入你的公网 IP（WAN，可多个，用逗号/空格分隔）", "Enter your public IPs (WAN; multiple allowed, comma/space separated)")
                text: Config.wanIps
                onEditingFinished: Config.wanIps = text.trim()
                tip: "Example: 203.0.113.10, 198.51.100.2 (multiple allowed)."
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: 10

                Label {
                    text: I18n.tr("直连公网：", "Direct public: ")
                    color: Theme.textSecondary
                }

                StatusTag {
                    text: root.isDirectPublic() ? I18n.tr("是", "Yes") : I18n.tr("否（NAT）", "No (NAT)")
                    tone: root.isDirectPublic() ? "warning" : "normal"
                    tip: "Direct public means a WAN IP is assigned to a local NIC; otherwise it is likely behind NAT."
                }

                Label {
                    Layout.fillWidth: true
                    text: root.isDirectPublic()
                        ? I18n.tr("公网 IP 直接分配在本机网卡上", "WAN IP is assigned to a local NIC")
                        : I18n.tr("公网 IP 不在本机网卡上（通常由路由器持有）", "WAN IP not on local NIC (usually held by router)")
                    color: Theme.textSecondary
                    elide: Text.ElideRight
                    HoverHandler { id: directExplainHover }
                }
            }

            Label {
                text: I18n.tr("本机 IP 列表（可勾选哪些你认为是“公网 IP”）", "Local IP list (mark which ones you consider public)")
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
                            checked: Config.isIpMarkedPublic(String(modelData.ip), modelData.guessedPublic === true)
                            onToggled: Config.setIpMarkedPublic(String(modelData.ip), checked)
                        }
                    }
                }
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("NAT / 端口转发 / 内网穿透", "NAT / Port Forwarding / Tunneling")
            icon: Icons.network
            tip: "Configure NAT forwarding/DMZ/tunneling inputs so the exposure heuristic can evaluate risk."

            RowLayout {
                Layout.fillWidth: true
                spacing: 18

                ThemedSwitch {
                    text: I18n.tr("已配置端口转发", "Port forwarding enabled")
                    checked: Config.portForwardEnabled
                    onToggled: Config.portForwardEnabled = checked
                    tip: "If enabled, specify forwarded ports below (unless DMZ is enabled)."
                }

                ThemedSwitch {
                    text: I18n.tr("DMZ（全端口）", "DMZ (all ports)")
                    checked: Config.dmzEnabled
                    onToggled: Config.dmzEnabled = checked
                    tip: "DMZ forwards most inbound traffic to one host; high exposure risk."
                }

                ThemedSwitch {
                    text: I18n.tr("内网穿透（FRP/NPS 等）", "Tunneling (FRP/NPS)")
                    checked: Config.tunnelEnabled
                    onToggled: Config.tunnelEnabled = checked
                    tip: "Tunneling may expose local ports even if bound to 127.0.0.1."
                }
            }

            GridLayout {
                Layout.fillWidth: true
                columns: 2
                columnSpacing: 8
                rowSpacing: 8

                ThemedTextField {
                    Layout.fillWidth: true
                    placeholderText: I18n.tr("转发端口列表（逗号分隔，如 3389,80,443）", "Forwarded ports CSV (e.g. 3389,80,443)")
                    text: Config.forwardedPortsCsv
                    enabled: Config.portForwardEnabled && !Config.dmzEnabled
                    onEditingFinished: Config.forwardedPortsCsv = text.trim()
                    tip: "Comma-separated list, e.g. 3389,80,443"
                }

                ThemedTextField {
                    Layout.fillWidth: true
                    placeholderText: I18n.tr("穿透端口列表（逗号分隔，如 22,3389）", "Tunneled ports CSV (e.g. 22,3389)")
                    text: Config.tunnelPortsCsv
                    enabled: Config.tunnelEnabled
                    onEditingFinished: Config.tunnelPortsCsv = text.trim()
                    tip: "Comma-separated list of locally exposed ports via tunneling."
                }
            }
        }

        SectionCard {
            Layout.fillWidth: true
            title: I18n.tr("公网暴露评估（基于输入）", "Exposure Assessment (based on your inputs)")
            icon: Icons.port
            tip: "This is a heuristic view; confirm with router/firewall configuration and external scanning."

            Repeater {
                model: Security.ports
                delegate: Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: 62
                    radius: 8
                    color: Theme.cardAltBg

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 10
                        spacing: 10

                        Label {
                            id: portLabel
                            text: modelData.protocol + ":" + modelData.port
                            color: Theme.textPrimary
                            font.bold: true
                            Layout.preferredWidth: 120

                            readonly property string tipText: Security.knownPortTip(parseInt(modelData.port), modelData.protocol)
                            HoverHandler { id: portHover }
                        }

                        Label {
                            id: procLabel
                            text: modelData.process + " | " + modelData.localAddress
                            color: Theme.textSecondary
                            Layout.fillWidth: true
                            elide: Text.ElideRight

                            readonly property string tipText: Security.knownProcessTip(modelData.process)
                            HoverHandler { id: procHover }
                        }

                        StatusTag {
                            text: root.exposureStatus(modelData) === "Exposed" ? I18n.tr("已暴露", "Exposed")
                                : root.exposureStatus(modelData) === "Potential" ? I18n.tr("可能暴露", "Potential")
                                : root.exposureStatus(modelData) === "NotExposed" ? I18n.tr("未暴露", "Not Exposed")
                                : I18n.tr("未知", "Unknown")
                            tone: root.exposureStatus(modelData) === "Exposed" ? "danger"
                                : root.exposureStatus(modelData) === "Potential" ? "warning"
                                : root.exposureStatus(modelData) === "NotExposed" ? "success"
                                : "normal"
                            tip: "Exposure is computed from WAN/NAT/tunneling inputs + bind scope + inbound firewall heuristic (demo)."
                        }

                        StatusTag {
                            text: I18n.riskLabel(modelData.risk)
                            tone: modelData.risk === "Critical" ? "danger"
                                : modelData.risk === "High" ? "warning"
                                : modelData.risk === "Low" ? "success" : "normal"
                            tip: "Risk is derived from port type and runtime hints (demo)."
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
        }
    }
}
