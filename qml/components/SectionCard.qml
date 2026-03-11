import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Pane {
    id: root
    property string title: ""
    property string icon: ""
    property string tip: ""
    default property alias sectionContent: contentColumn.data

    background: Rectangle {
        radius: 12
        color: Theme.cardBg
        border.width: 1
        border.color: Theme.borderColor
    }

    contentItem: ColumnLayout {
        spacing: 10
        RowLayout {
            id: headerRow
            Layout.fillWidth: true
            HoverHandler { id: headerHover }

            Label {
                text: root.icon
                font.pixelSize: 18
            }
            Label {
                text: root.title
                color: Theme.textPrimary
                font.pixelSize: 16
                font.bold: true
                Layout.fillWidth: true
            }
            Label {
                visible: root.tip.length > 0
                text: Icons.info
                color: Theme.textSecondary
                font.pixelSize: 14
            }
        }
        Rectangle {
            Layout.fillWidth: true
            height: 1
            color: Theme.borderColor
            opacity: 0.7
        }
        ColumnLayout {
            id: contentColumn
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 8
        }
    }
}
