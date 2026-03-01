import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Pane {
    id: root
    property string title: ""
    property string icon: ""
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
            Layout.fillWidth: true
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
            spacing: 8
        }
    }
}
