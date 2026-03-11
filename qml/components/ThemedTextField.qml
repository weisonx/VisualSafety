import QtQuick
import QtQuick.Controls

TextField {
    id: root
    property string tip: ""
    color: Theme.inputText
    placeholderTextColor: Theme.inputPlaceholder
    selectionColor: Theme.accentColor
    selectedTextColor: Theme.controlText
    hoverEnabled: true

    ToolTip.delay: 350
    ToolTip.timeout: 8000
    ToolTip.visible: root.hovered && root.tip.length > 0
    ToolTip.text: root.tip

    background: Rectangle {
        radius: 8
        color: Theme.inputBg
        border.width: 1
        border.color: root.activeFocus ? Theme.accentColor : Theme.borderColor
    }
}
