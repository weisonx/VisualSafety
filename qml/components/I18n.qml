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

    function riskLabel(value) {
        switch (String(value)) {
        case "Critical": return tr("严重", "Critical")
        case "High": return tr("高", "High")
        case "Medium": return tr("中", "Medium")
        case "Low": return tr("低", "Low")
        default: return String(value)
        }
    }

    function trustLabel(value) {
        switch (String(value)) {
        case "Trusted": return tr("可信", "Trusted")
        case "Untrusted": return tr("不可信", "Untrusted")
        case "Unknown": return tr("未知", "Unknown")
        default: return String(value)
        }
    }

    function severityLabel(value) {
        switch (String(value)) {
        case "Critical": return tr("严重", "Critical")
        case "High": return tr("高", "High")
        case "Medium": return tr("中", "Medium")
        case "Low": return tr("低", "Low")
        default: return String(value)
        }
    }

    function exposureLabel(value) {
        switch (String(value)) {
        case "Masked": return tr("已掩码", "Masked")
        case "Vault Protected": return tr("保险库保护", "Vault Protected")
        case "Safe": return tr("安全", "Safe")
        case "At Risk": return tr("有风险", "At Risk")
        case "Unavailable": return tr("不可用", "Unavailable")
        default: return String(value)
        }
    }

    function logLevelLabel(value) {
        switch (String(value)) {
        case "INFO": return tr("信息", "INFO")
        case "WARN": return tr("警告", "WARN")
        case "ALERT": return tr("告警", "ALERT")
        case "CRITICAL": return tr("严重", "CRITICAL")
        case "ERROR": return tr("错误", "ERROR")
        default: return String(value)
        }
    }

    function statusLabel(value) {
        switch (String(value)) {
        case "Enabled": return tr("已启用", "Enabled")
        case "Disabled": return tr("已禁用", "Disabled")
        case "Elevated": return tr("已提升", "Elevated")
        case "Not elevated": return tr("未提升", "Not elevated")
        case "Unavailable": return tr("不可用", "Unavailable")
        case "Monitored": return tr("监控中", "Monitored")
        case "Guarded": return tr("防护中", "Guarded")
        case "Restricted": return tr("受限", "Restricted")
        case "At Risk": return tr("有风险", "At Risk")
        case "Allowed": return tr("允许", "Allowed")
        case "Denied": return tr("拒绝", "Denied")
        case "Prompt": return tr("提示", "Prompt")
        case "Running": return tr("运行中", "Running")
        default: return String(value)
        }
    }
}
