pragma Singleton

import QtQuick
import Qt.labs.settings

QtObject {
    id: root

    property Settings settings: Settings {
        category: "i18n"
        property string language: "zh_CN"
    }

    property string language: "zh_CN"
    Component.onCompleted: language = settings.language
    onLanguageChanged: settings.language = language

    readonly property var languages: [
        { name: "\u4e2d\u6587", code: "zh_CN" },
        { name: "English", code: "en_US" }
    ]

    function indexOfLanguage(code) {
        for (let i = 0; i < languages.length; ++i) {
            if (languages[i].code === code)
                return i
        }
        return 0
    }

    function tr(zhText, enText) {
        return language.indexOf("en") === 0 ? enText : zhText
    }
}
