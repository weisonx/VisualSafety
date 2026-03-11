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
            title: I18n.tr("端口与高危端口使用情况", "Ports & High-Risk Ports")
            icon: Icons.port
            tip: I18n.tr("悬浮端口/进程查看常见端口与进程说明（示例）。", "Hover port/process for common explanations (demo).")

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

                        Label {
                            id: portLabel
                            text: modelData.protocol + ":" + modelData.port
                            color: Theme.textPrimary
                            font.bold: true
                            Layout.preferredWidth: 120

                            readonly property string tipText: Security.knownPortTip(parseInt(modelData.port), modelData.protocol)
                            HoverHandler { id: portHover }
                            ToolTip.delay: 350
                            ToolTip.timeout: 8000
                            ToolTip.visible: portHover.hovered && portLabel.tipText.length > 0
                            ToolTip.text: portLabel.tipText
                        }

                        Label {
                            id: procLabel
                            text: modelData.process
                            color: Theme.textSecondary
                            Layout.fillWidth: true
                            elide: Text.ElideRight

                            readonly property string tipText: Security.knownProcessTip(modelData.process)
                            HoverHandler { id: procHover }
                            ToolTip.delay: 350
                            ToolTip.timeout: 8000
                            ToolTip.visible: procHover.hovered && procLabel.tipText.length > 0
                            ToolTip.text: procLabel.tipText
                        }

                        StatusTag {
                            text: modelData.bindScope === "Any" ? I18n.tr("对外监听", "All IF")
                                : modelData.bindScope === "Public" ? I18n.tr("绑定公网", "Public bind")
                                : modelData.bindScope === "Private" ? I18n.tr("内网监听", "LAN")
                                : modelData.bindScope === "Loopback" ? I18n.tr("仅本机", "Loopback")
                                : I18n.tr("未知", "Unknown")
                            tone: (modelData.bindScope === "Any" || modelData.bindScope === "Public") ? "warning"
                                : modelData.bindScope === "Private" ? "normal"
                                : modelData.bindScope === "Loopback" ? "success" : "normal"
                            tip: I18n.tr(
                                     "监听绑定范围：对外监听/绑定公网表示可能从外部网络访问；仅本机表示只在本机可访问。",
                                     "Bind scope: All IF/Public suggests reachable from outside; Loopback means local-only.")
                        }

                        StatusTag {
                            text: I18n.riskLabel(modelData.risk)
                            tone: modelData.risk === "Critical" ? "danger"
                                : modelData.risk === "High" ? "warning"
                                : modelData.risk === "Low" ? "success" : "normal"
                            tip: I18n.tr(
                                     "风险分级由端口类型、监听范围、进程特征等综合推导（示例）。",
                                     "Risk is derived from port type, bind scope, process hints, etc. (demo).")
                        }

                        ThemedButton {
                            text: modelData.action === "Block"
                                ? (Icons.block + " " + I18n.tr("阻断", "Block"))
                                : I18n.tr("观察", "Observe")
                            enabled: modelData.action === "Block"
                            onClicked: Security.blockAction(modelData.process, (I18n.tr("端口 ", "Port ") + modelData.port))
                        }
                    }
                }
            }
        }
    }
}

