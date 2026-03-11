import QtQuick
import QtQuick.Controls

Button {
    id: root
    property string tip: ""
    implicitHeight: 34
    leftPadding: 12
    rightPadding: 12
    topPadding: 7
    bottomPadding: 7

    ToolTip.delay: 350
    ToolTip.timeout: 8000
    ToolTip.visible: root.hovered && root.tip.length > 0
    ToolTip.text: root.tip

    contentItem: Label {
        text: root.text
        color: root.down ? Theme.controlText : (Theme.darkTheme ? "#cfd8e3" : Theme.textPrimary)
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        font.pixelSize: 13
        font.bold: true
    }

    background: Rectangle {
        radius: 8
        color: root.down ? Theme.accentColor : Theme.controlBg
        border.width: 1
        border.color: root.down ? Theme.accentColor : (root.hovered ? Theme.accentColor : Theme.borderColor)
    }
}
