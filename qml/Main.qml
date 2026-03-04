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
    title: I18n.tr("VisualSafety 安全控制台", "VisualSafety Security Console")
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
        { title: I18n.tr("总览", "Overview"), icon: Icons.dashboard },
        { title: I18n.tr("权限", "Permissions"), icon: Icons.permission },
        { title: I18n.tr("凭证", "Credentials"), icon: Icons.credential },
        { title: I18n.tr("端口", "Ports"), icon: Icons.port },
        { title: I18n.tr("网络", "Network"), icon: Icons.network },
        { title: I18n.tr("告警", "Alerts"), icon: Icons.alert },
        { title: I18n.tr("日志", "Logs"), icon: Icons.log },
        { title: I18n.tr("应用", "Apps"), icon: Icons.app },
        { title: I18n.tr("处置", "Actions"), icon: Icons.power }
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
                text: I18n.tr("当前动作: ", "Action: ") + Security.lastAction
                color: Theme.textSecondary
                font.pixelSize: 13
                Layout.fillWidth: true
                elide: Text.ElideRight
            }

            ThemedButton {
                text: Icons.refresh + " " + I18n.tr("刷新", "Refresh")
                Layout.alignment: Qt.AlignVCenter
                onClicked: Security.refreshData()
            }

            ThemedComboBox {
                id: languageBox
                Layout.alignment: Qt.AlignVCenter
                model: I18n.languages
                textRole: "name"
                valueRole: "code"
                implicitWidth: 120
                Component.onCompleted: currentIndex = I18n.indexOfLanguage(I18n.language)
                Connections {
                    target: I18n
                    function onLanguageChanged() {
                        const idx = I18n.indexOfLanguage(I18n.language)
                        if (languageBox.currentIndex !== idx)
                            languageBox.currentIndex = idx
                    }
                }
                onActivated: I18n.language = currentValue
            }

            ThemedSwitch {
                checked: Theme.darkTheme
                text: checked ? (Icons.theme + " " + I18n.tr("深色", "Dark"))
                              : (Icons.theme + " " + I18n.tr("浅色", "Light"))
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
