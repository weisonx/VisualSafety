import QtQuick
import QtQuick.Controls

ComboBox {
    id: root
    implicitHeight: 34
    leftPadding: 10
    rightPadding: 28
    topPadding: 7
    bottomPadding: 7

    contentItem: Label {
        text: root.displayText
        color: Theme.inputText
        height: root.implicitHeight
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
    }

    background: Rectangle {
        radius: 8
        color: Theme.inputBg
        border.width: 1
        border.color: root.activeFocus ? Theme.accentColor : Theme.borderColor
    }

    indicator: Label {
        text: "▼"
        color: Theme.textSecondary
        anchors.right: parent.right
        anchors.rightMargin: 8
        anchors.verticalCenter: parent.verticalCenter
        font.pixelSize: 10
    }

    popup: Popup {
        y: root.height + 4
        width: root.width
        padding: 4

        background: Rectangle {
            color: Theme.cardBg
            border.width: 1
            border.color: Theme.borderColor
            radius: 8
        }

        contentItem: ListView {
            clip: true
            implicitHeight: contentHeight
            model: root.delegateModel
            currentIndex: root.highlightedIndex

            delegate: ItemDelegate {
                width: ListView.view.width
                highlighted: root.highlightedIndex === index

                contentItem: Label {
                    text: root.textRole && root.textRole.length > 0 ? modelData[root.textRole] : modelData
                    color: Theme.textPrimary
                    verticalAlignment: Text.AlignVCenter
                    leftPadding: 8
                }

                background: Rectangle {
                    color: parent.highlighted ? Theme.accentMuted : "transparent"
                    radius: 6
                }
            }
        }
    }
}
