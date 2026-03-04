import QtQuick
import QtQuick.Controls

ScrollBar {
    id: root

    hoverEnabled: true
    minimumSize: 0.06

    readonly property int thicknessIdle: 8
    readonly property int thicknessHover: 10
    readonly property int thickness: (root.hovered || root.pressed) ? thicknessHover : thicknessIdle

    implicitWidth: root.orientation === Qt.Vertical ? thickness : 0
    implicitHeight: root.orientation === Qt.Horizontal ? thickness : 0

    padding: 2

    background: Rectangle {
        radius: root.thickness / 2
        color: Theme.darkTheme ? "#ffffff" : "#000000"
        opacity: root.hovered || root.pressed ? (Theme.darkTheme ? 0.06 : 0.05) : 0.0
        Behavior on opacity { NumberAnimation { duration: 120 } }
    }

    contentItem: Rectangle {
        radius: root.thickness / 2
        color: Theme.darkTheme ? "#93a4b7" : "#6a7a8b"
        opacity: root.pressed ? (Theme.darkTheme ? 0.92 : 0.80)
            : root.hovered ? (Theme.darkTheme ? 0.72 : 0.58)
            : (Theme.darkTheme ? 0.38 : 0.32)
        Behavior on opacity { NumberAnimation { duration: 120 } }
    }
}

