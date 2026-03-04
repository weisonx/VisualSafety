import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "components"
import "pages"

ApplicationWindow {
    id: root
    width: 1440
    height: 900
    minimumWidth: 1120
    minimumHeight: 720
    visible: true
    title: "VisualSafety Security Console"
    color: Theme.windowBg

    palette.window: Theme.windowBg
    palette.windowText: Theme.textPrimary
    palette.base: Theme.inputBg
    palette.alternateBase: Theme.cardAltBg
    palette.text: Theme.inputText
    palette.button: Theme.controlBg
    palette.buttonText: Theme.controlText
    palette.highlight: Theme.accentColor
    palette.highlightedText: Theme.controlText
    palette.placeholderText: Theme.inputPlaceholder

    property int currentIndex: 0

    readonly property var pages: [
        { title: "总览", icon: Icons.dashboard },
        { title: "权限", icon: Icons.permission },
        { title: "凭证", icon: Icons.credential },
        { title: "端口", icon: Icons.port },
        { title: "网络", icon: Icons.network },
        { title: "告警", icon: Icons.alert },
        { title: "日志", icon: Icons.log },
        { title: "应用", icon: Icons.app },
        { title: "处置", icon: Icons.power }
    ]

    header: Rectangle {
        height: 64
        color: Theme.sidebarBg
        border.width: 0

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 20
            anchors.rightMargin: 20

            Label {
                text: Icons.dashboard + "  VisualSafety"
                color: Theme.textPrimary
                font.pixelSize: 22
                font.bold: true
            }

            Label {
                Layout.leftMargin: 10
                text: "当前动作: " + Security.lastAction
                color: Theme.textSecondary
                font.pixelSize: 13
                Layout.fillWidth: true
                elide: Text.ElideRight
            }

            ThemedButton {
                text: Icons.refresh + " 刷新"
                Layout.alignment: Qt.AlignVCenter
                onClicked: Security.refreshData()
            }

            ThemedSwitch {
                checked: Theme.darkTheme
                text: checked ? (Icons.theme + " 深色") : (Icons.theme + " 浅色")
                Layout.alignment: Qt.AlignVCenter
                onToggled: Theme.darkTheme = checked
            }
        }
    }

    RowLayout {
        anchors.fill: parent
        anchors.topMargin: root.header.height

        Rectangle {
            Layout.preferredWidth: 220
            Layout.fillHeight: true
            color: Theme.sidebarBg
            border.width: 1
            border.color: Theme.borderColor

            ListView {
                anchors.fill: parent
                anchors.margins: 10
                model: root.pages
                spacing: 6
                delegate: ItemDelegate {
                    width: ListView.view.width
                    highlighted: root.currentIndex === index
                    onClicked: root.currentIndex = index

                    contentItem: Label {
                        text: modelData.icon + "  " + modelData.title
                        color: Theme.textPrimary
                        verticalAlignment: Text.AlignVCenter
                        leftPadding: 8
                    }

                    background: Rectangle {
                        radius: 8
                        color: highlighted ? Theme.accentMuted : (parent.hovered ? Theme.controlBg : "transparent")
                        border.width: highlighted ? 1 : 0
                        border.color: highlighted ? Theme.accentColor : "transparent"
                    }
                }
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: Theme.windowBg

            StackLayout {
                anchors.fill: parent
                anchors.margins: 14
                currentIndex: root.currentIndex

                OverviewPage {}
                PermissionsPage {}
                CredentialsPage {}
                PortsPage {}
                NetworkPage {}
                AlertsPage {}
                LogsPage {}
                AppsPage {}
                ActionsPage {}
            }
        }
    }
}
