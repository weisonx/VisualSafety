import QtQuick
import QtQuick.Controls

Button {
    id: root

    contentItem: Label {
        text: root.text
        color: Theme.controlText
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        font.pixelSize: 13
        font.bold: true
    }

    background: Rectangle {
        radius: 8
        color: root.down ? Theme.accentColor : (root.hovered ? Theme.controlBgHover : Theme.controlBg)
        border.width: 1
        border.color: root.down ? Theme.accentColor : Theme.borderColor
    }
}
