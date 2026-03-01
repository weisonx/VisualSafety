import QtQuick
import QtQuick.Controls

Switch {
    id: root

    indicator: Rectangle {
        implicitWidth: 44
        implicitHeight: 24
        radius: 12
        color: root.checked ? Theme.accentColor : Theme.controlBg
        border.width: 1
        border.color: root.checked ? Theme.accentColor : Theme.borderColor

        Rectangle {
            x: root.checked ? parent.width - width - 3 : 3
            y: 3
            width: 16
            height: 16
            radius: 8
            color: Theme.controlText
        }
    }

    contentItem: Label {
        text: root.text
        color: Theme.textPrimary
        verticalAlignment: Text.AlignVCenter
        leftPadding: root.indicator.width + root.spacing
    }
}
