import QtQuick
import QtQuick.Controls

Switch {
    id: root
    property string tip: ""
    implicitHeight: 34
    spacing: 10
    hoverEnabled: true

    ToolTip.delay: 350
    ToolTip.timeout: 8000
    ToolTip.visible: root.hovered && root.tip.length > 0
    ToolTip.text: root.tip

    indicator: Rectangle {
        implicitWidth: 44
        implicitHeight: 24
        y: Math.round((root.height - height) / 2)
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
        height: root.implicitHeight
        verticalAlignment: Text.AlignVCenter
        leftPadding: root.indicator.width + root.spacing
    }
}
