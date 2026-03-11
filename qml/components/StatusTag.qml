import QtQuick
import QtQuick.Controls

Rectangle {
    id: root
    property string text: ""
    property string tone: "normal" // normal, success, warning, danger
    property string tip: ""

    HoverHandler { id: tagHover }

    radius: 10
    height: 24
    implicitWidth: badgeLabel.implicitWidth + 14
    color: root.tone === "danger" ? Qt.rgba(1, 0.2, 0.2, 0.18)
          : root.tone === "warning" ? Qt.rgba(1, 0.64, 0, 0.18)
          : root.tone === "success" ? Qt.rgba(0.2, 0.85, 0.45, 0.16)
          : Qt.rgba(0.3, 0.5, 0.9, 0.14)
    border.width: 1
    border.color: root.tone === "danger" ? Theme.dangerColor
                : root.tone === "warning" ? Theme.warningColor
                : root.tone === "success" ? Theme.successColor
                : Theme.accentColor

    Label {
        id: badgeLabel
        anchors.centerIn: parent
        text: root.text
        color: root.tone === "danger" ? Theme.dangerColor
             : root.tone === "warning" ? Theme.warningColor
             : root.tone === "success" ? Theme.successColor
             : Theme.accentColor
        font.pixelSize: 12
        font.bold: true
    }
}

