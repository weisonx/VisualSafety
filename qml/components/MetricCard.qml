import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Pane {
    id: root
    property string icon: ""
    property string title: ""
    property string value: ""
    property string tone: "normal" // normal, warning, danger, success
    property string tip: ""

    HoverHandler { id: cardHover }
    ToolTip.delay: 350
    ToolTip.timeout: 8000
    ToolTip.visible: cardHover.hovered && ((root.tip.length > 0) || (root.title.length > 0))
    ToolTip.text: root.tip.length > 0 ? root.tip : root.title

    background: Rectangle {
        radius: 12
        color: Theme.cardBg
        border.width: 1
        border.color: root.tone === "danger" ? Theme.dangerColor
            : root.tone === "warning" ? Theme.warningColor
            : root.tone === "success" ? Theme.successColor
            : Theme.borderColor
    }

    contentItem: ColumnLayout {
        spacing: 8
        RowLayout {
            Layout.fillWidth: true
            Label {
                text: root.icon
                font.pixelSize: 20
            }
            Label {
                text: root.title
                color: Theme.textSecondary
                font.pixelSize: 14
                Layout.fillWidth: true
            }
        }
        Label {
            text: root.value
            color: Theme.textPrimary
            font.pixelSize: 24
            font.bold: true
        }
    }
}
