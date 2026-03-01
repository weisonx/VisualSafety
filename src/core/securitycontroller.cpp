#include "securitycontroller.h"

#include <QDateTime>

namespace {
QVariantMap mapOf(std::initializer_list<std::pair<QString, QVariant>> values)
{
    QVariantMap map;
    for (const auto &pair : values) {
        map.insert(pair.first, pair.second);
    }
    return map;
}
}

SecurityController::SecurityController(QObject *parent)
    : QObject(parent)
{
    refreshData();
    appendLog("INFO", "Security UI initialized.");
}

QVariantList SecurityController::permissions() const { return m_permissions; }
QVariantList SecurityController::appPermissions() const { return m_appPermissions; }
QVariantList SecurityController::highRiskPermissions() const { return m_highRiskPermissions; }
QVariantList SecurityController::credentials() const { return m_credentials; }
QVariantList SecurityController::ports() const { return m_ports; }
QVariantList SecurityController::firewallRules() const { return m_firewallRules; }
QVariantList SecurityController::traffic() const { return m_traffic; }
QVariantList SecurityController::alerts() const { return m_alerts; }
QVariantList SecurityController::logs() const { return m_logs; }
QVariantList SecurityController::appMonitors() const { return m_appMonitors; }
QString SecurityController::lastAction() const { return m_lastAction; }
int SecurityController::criticalAlertCount() const
{
    int count = 0;
    for (const auto &item : m_alerts) {
        const auto severity = item.toMap().value("severity").toString();
        if (severity == "Critical") {
            ++count;
        }
    }
    return count;
}

int SecurityController::runningAppCount() const
{
    int count = 0;
    for (const auto &item : m_appMonitors) {
        if (item.toMap().value("status").toString() == "Running") {
            ++count;
        }
    }
    return count;
}

int SecurityController::blockedActionCount() const { return m_blockedActionCount; }

bool SecurityController::desktopNotify() const { return m_desktopNotify; }
void SecurityController::setDesktopNotify(bool value)
{
    if (m_desktopNotify == value) {
        return;
    }
    m_desktopNotify = value;
    emit notifySettingsChanged();
}

bool SecurityController::emailNotify() const { return m_emailNotify; }
void SecurityController::setEmailNotify(bool value)
{
    if (m_emailNotify == value) {
        return;
    }
    m_emailNotify = value;
    emit notifySettingsChanged();
}

bool SecurityController::smsNotify() const { return m_smsNotify; }
void SecurityController::setSmsNotify(bool value)
{
    if (m_smsNotify == value) {
        return;
    }
    m_smsNotify = value;
    emit notifySettingsChanged();
}

void SecurityController::refreshData()
{
    m_blockedActionCount = 2;
    m_permissions = {
        mapOf({{"name", "File System"}, {"scope", "Read/Write user docs"}, {"level", "High"}, {"status", "Monitored"}}),
        mapOf({{"name", "Shell Execution"}, {"scope", "PowerShell / cmd invocation"}, {"level", "Critical"}, {"status", "Restricted"}}),
        mapOf({{"name", "Registry Access"}, {"scope", "HKCU + HKLM"}, {"level", "High"}, {"status", "Monitored"}}),
        mapOf({{"name", "Process Control"}, {"scope", "Start/Terminate process"}, {"level", "Critical"}, {"status", "Guarded"}}),
    };

    m_appPermissions = {
        mapOf({{"app", "AgentRunner.exe"}, {"permission", "Shell Execution"}, {"status", "Denied"}, {"lastUsed", "2 min ago"}}),
        mapOf({{"app", "BrowserHelper.exe"}, {"permission", "Network"}, {"status", "Allowed"}, {"lastUsed", "just now"}}),
        mapOf({{"app", "DataSync.exe"}, {"permission", "File System"}, {"status", "Allowed"}, {"lastUsed", "1 min ago"}}),
        mapOf({{"app", "PromptLab.exe"}, {"permission", "Process Control"}, {"status", "Prompt"}, {"lastUsed", "4 min ago"}}),
    };

    m_highRiskPermissions = {
        mapOf({{"permission", "Shell Execution"}, {"process", "AgentRunner.exe"}, {"action", "Invoke-Expression"}, {"time", "20:10:44"}, {"risk", "Critical"}}),
        mapOf({{"permission", "Process Control"}, {"process", "PromptLab.exe"}, {"action", "Terminate antivirus"}, {"time", "20:09:18"}, {"risk", "High"}}),
    };

    m_credentials = {
        mapOf({{"type", "API Key"}, {"owner", "LLM Gateway"}, {"expires", "2026-05-10"}, {"exposure", "Masked"}}),
        mapOf({{"type", "OAuth Token"}, {"owner", "Mail Service"}, {"expires", "2026-03-07"}, {"exposure", "Rotating"}}),
        mapOf({{"type", "SSH Key"}, {"owner", "Build Host"}, {"expires", "N/A"}, {"exposure", "Vault Protected"}}),
    };

    m_ports = {
        mapOf({{"port", "22"}, {"protocol", "TCP"}, {"process", "RemoteAgent.exe"}, {"risk", "High"}, {"action", "Watch"}}),
        mapOf({{"port", "3389"}, {"protocol", "TCP"}, {"process", "RDP"}, {"risk", "Critical"}, {"action", "Block"}}),
        mapOf({{"port", "8080"}, {"protocol", "TCP"}, {"process", "LocalProxy.exe"}, {"risk", "Medium"}, {"action", "Watch"}}),
        mapOf({{"port", "5353"}, {"protocol", "UDP"}, {"process", "mDNS"}, {"risk", "Low"}, {"action", "Allow"}}),
    };

    m_firewallRules = {
        mapOf({{"rule", "Block outbound to unknown ASN"}, {"target", "0.0.0.0/0"}, {"decision", "Enabled"}, {"risk", "High"}}),
        mapOf({{"rule", "Allow trusted update endpoints"}, {"target", "*.microsoft.com"}, {"decision", "Enabled"}, {"risk", "Low"}}),
        mapOf({{"rule", "Block TOR relay fingerprints"}, {"target", "threat feed set"}, {"decision", "Enabled"}, {"risk", "Critical"}}),
    };

    m_traffic = {
        mapOf({{"direction", "Outbound"}, {"mbps", "21.7"}, {"unusual", "Yes"}}),
        mapOf({{"direction", "Inbound"}, {"mbps", "4.2"}, {"unusual", "No"}}),
        mapOf({{"direction", "Lateral"}, {"mbps", "1.1"}, {"unusual", "No"}}),
    };

    m_alerts = {
        mapOf({{"time", "20:10:45"}, {"severity", "Critical"}, {"title", "High-risk shell command blocked"}, {"detail", "AgentRunner.exe attempted obfuscated execution."}}),
        mapOf({{"time", "20:09:18"}, {"severity", "High"}, {"title", "Process-kill request intercepted"}, {"detail", "PromptLab.exe targeted security process."}}),
        mapOf({{"time", "20:08:09"}, {"severity", "Medium"}, {"title", "Unusual outbound burst"}, {"detail", "Traffic exceeded baseline by 260% in 15s."}}),
    };

    m_appMonitors = {
        mapOf({{"app", "AgentRunner.exe"}, {"pid", "4412"}, {"trust", "Untrusted"}, {"status", "Running"}, {"hint", "Can perform shell actions"}}),
        mapOf({{"app", "PromptLab.exe"}, {"pid", "5310"}, {"trust", "Unknown"}, {"status", "Running"}, {"hint", "Requests process control"}}),
        mapOf({{"app", "DataSync.exe"}, {"pid", "9028"}, {"trust", "Trusted"}, {"status", "Running"}, {"hint", "Normal file sync"}}),
        mapOf({{"app", "LocalProxy.exe"}, {"pid", "1204"}, {"trust", "Unknown"}, {"status", "Running"}, {"hint", "Binds high port"}}),
    };

    m_lastAction = "Dashboard data refreshed";
    emit dataChanged();
    emit statusChanged();
}

void SecurityController::forceQuitApp(const QString &name)
{
    appendAlert("High", "Force quit requested", name + " was terminated by operator.");
    appendLog("WARN", "Forced termination for " + name);
    m_lastAction = "Forced exit executed: " + name;
    emit statusChanged();
}

void SecurityController::blockAction(const QString &source, const QString &action)
{
    ++m_blockedActionCount;
    appendAlert("Critical", "Dangerous action blocked", source + ": " + action);
    appendLog("ALERT", "Blocked high-risk action from " + source + " => " + action);
    m_lastAction = "Blocked action from " + source;
    emit statusChanged();
    emit dataChanged();
}

void SecurityController::shutdownNow()
{
    appendAlert("Critical", "Emergency shutdown command armed", "Operator triggered immediate shutdown workflow.");
    appendLog("CRITICAL", "Emergency shutdown requested.");
    m_lastAction = "Emergency shutdown requested";
    emit statusChanged();
}

void SecurityController::restartNow()
{
    appendAlert("High", "Emergency restart command armed", "Operator triggered immediate restart workflow.");
    appendLog("CRITICAL", "Emergency restart requested.");
    m_lastAction = "Emergency restart requested";
    emit statusChanged();
}

void SecurityController::addManualLog(const QString &level, const QString &message)
{
    appendLog(level, message);
}

void SecurityController::appendLog(const QString &level, const QString &message)
{
    m_logs.prepend(mapOf({{"time", nowStamp()}, {"level", level}, {"message", message}}));
    while (m_logs.size() > 300) {
        m_logs.removeLast();
    }
    emit logsChanged();
}

void SecurityController::appendAlert(const QString &severity, const QString &title, const QString &detail)
{
    m_alerts.prepend(mapOf({{"time", nowStamp()}, {"severity", severity}, {"title", title}, {"detail", detail}}));
    while (m_alerts.size() > 100) {
        m_alerts.removeLast();
    }
    emit dataChanged();
}

QString SecurityController::nowStamp() const
{
    return QDateTime::currentDateTime().toString("HH:mm:ss");
}
