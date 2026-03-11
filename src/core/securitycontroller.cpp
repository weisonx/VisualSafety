#include "securitycontroller.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QCoreApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QProcess>
#include <QRegularExpression>
#include <QSet>
#include <QStandardPaths>
#include <QTextStream>

namespace {
struct CommandResult {
    bool started = false;
    bool finished = false;
    int exitCode = -1;
    QString out;
    QString err;
};

CommandResult RunProcess(const QString &program, const QStringList &args, int timeoutMs = 8000)
{
    QProcess proc;
    proc.start(program, args);

    CommandResult result;
    result.started = proc.waitForStarted(1500);
    if (!result.started) {
        result.err = QStringLiteral("Failed to start process: %1").arg(program);
        return result;
    }

    result.finished = proc.waitForFinished(timeoutMs);
    if (!result.finished) {
        proc.kill();
        proc.waitForFinished(1000);
        result.err = QStringLiteral("Command timeout: %1").arg(program);
        return result;
    }

    result.exitCode = proc.exitCode();
    result.out = QString::fromLocal8Bit(proc.readAllStandardOutput());
    result.err = QString::fromLocal8Bit(proc.readAllStandardError());
    return result;
}

QString MergedOutput(const CommandResult &result)
{
    return (result.out + "\n" + result.err).trimmed();
}

QVariantMap MapOf(std::initializer_list<std::pair<QString, QVariant>> values)
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
    const QString logDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (!logDir.isEmpty()) {
        QDir().mkpath(logDir);
        m_logFilePath = logDir + "/security.log";
    }

    loadPlugins();
    refreshData();
    appendLog("INFO", "VisualSafety initialized.");
}

QVariantList SecurityController::permissions() const { return m_permissions; }
QVariantList SecurityController::appPermissions() const { return m_appPermissions; }
QVariantList SecurityController::highRiskPermissions() const { return m_highRiskPermissions; }
QVariantList SecurityController::credentials() const { return m_credentials; }
QVariantList SecurityController::ports() const { return m_ports; }
QVariantList SecurityController::publicExposure() const { return m_publicExposure; }
QVariantList SecurityController::ipAddresses() const { return m_ipAddresses; }
QVariantList SecurityController::firewallRules() const { return m_firewallRules; }
QVariantMap SecurityController::controls() const { return m_controls; }
QVariantList SecurityController::traffic() const { return m_traffic; }
QVariantList SecurityController::alerts() const { return m_alerts; }
QVariantList SecurityController::logs() const { return m_logs; }
QVariantList SecurityController::appMonitors() const { return m_appMonitors; }
QString SecurityController::lastAction() const { return m_lastAction; }
int SecurityController::blockedActionCount() const { return m_blockedActionCount; }

int SecurityController::criticalAlertCount() const
{
    int count = 0;
    for (const auto &entry : m_alerts) {
        if (entry.toMap().value("severity").toString() == "Critical") {
            ++count;
        }
    }
    return count;
}

int SecurityController::runningAppCount() const
{
    int count = 0;
    for (const auto &entry : m_appMonitors) {
        if (entry.toMap().value("status").toString() == "Running") {
            ++count;
        }
    }
    return count;
}

bool SecurityController::desktopNotify() const { return m_desktopNotify; }
bool SecurityController::emailNotify() const { return m_emailNotify; }
bool SecurityController::smsNotify() const { return m_smsNotify; }
QString SecurityController::smtpServer() const { return m_smtpServer; }
int SecurityController::smtpPort() const { return m_smtpPort; }
QString SecurityController::smtpSender() const { return m_smtpSender; }
QString SecurityController::smtpRecipient() const { return m_smtpRecipient; }
QString SecurityController::smsWebhookUrl() const { return m_smsWebhookUrl; }
QString SecurityController::smsRecipient() const { return m_smsRecipient; }
bool SecurityController::autoBlockHighRiskPorts() const { return m_autoBlockHighRiskPorts; }
bool SecurityController::autoKillUntrustedShell() const { return m_autoKillUntrustedShell; }
QString SecurityController::processWhitelist() const { return m_processWhitelist; }
QString SecurityController::processBlacklist() const { return m_processBlacklist; }
QVariantList SecurityController::availablePlugins() const { return m_availablePlugins; }
QVariantList SecurityController::installedPlugins() const { return m_installedPlugins; }

void SecurityController::setDesktopNotify(bool value)
{
    if (m_desktopNotify == value) {
        return;
    }
    m_desktopNotify = value;
    emit notifySettingsChanged();
}

void SecurityController::setEmailNotify(bool value)
{
    if (m_emailNotify == value) {
        return;
    }
    m_emailNotify = value;
    emit notifySettingsChanged();
}

void SecurityController::setSmsNotify(bool value)
{
    if (m_smsNotify == value) {
        return;
    }
    m_smsNotify = value;
    emit notifySettingsChanged();
}

void SecurityController::setSmtpServer(const QString &value)
{
    const QString normalized = value.trimmed();
    if (m_smtpServer == normalized) {
        return;
    }
    m_smtpServer = normalized;
    emit notifySettingsChanged();
}

void SecurityController::setSmtpPort(int value)
{
    const int normalized = (value <= 0 || value > 65535) ? 25 : value;
    if (m_smtpPort == normalized) {
        return;
    }
    m_smtpPort = normalized;
    emit notifySettingsChanged();
}

void SecurityController::setSmtpSender(const QString &value)
{
    const QString normalized = value.trimmed();
    if (m_smtpSender == normalized) {
        return;
    }
    m_smtpSender = normalized;
    emit notifySettingsChanged();
}

void SecurityController::setSmtpRecipient(const QString &value)
{
    const QString normalized = value.trimmed();
    if (m_smtpRecipient == normalized) {
        return;
    }
    m_smtpRecipient = normalized;
    emit notifySettingsChanged();
}

void SecurityController::setSmsWebhookUrl(const QString &value)
{
    const QString normalized = value.trimmed();
    if (m_smsWebhookUrl == normalized) {
        return;
    }
    m_smsWebhookUrl = normalized;
    emit notifySettingsChanged();
}

void SecurityController::setSmsRecipient(const QString &value)
{
    const QString normalized = value.trimmed();
    if (m_smsRecipient == normalized) {
        return;
    }
    m_smsRecipient = normalized;
    emit notifySettingsChanged();
}

void SecurityController::setAutoBlockHighRiskPorts(bool value)
{
    if (m_autoBlockHighRiskPorts == value) {
        return;
    }
    m_autoBlockHighRiskPorts = value;
    emit policyChanged();
}

void SecurityController::setAutoKillUntrustedShell(bool value)
{
    if (m_autoKillUntrustedShell == value) {
        return;
    }
    m_autoKillUntrustedShell = value;
    emit policyChanged();
}

void SecurityController::setProcessWhitelist(const QString &value)
{
    const QString normalized = value.trimmed();
    if (m_processWhitelist == normalized) {
        return;
    }
    m_processWhitelist = normalized;
    emit policyChanged();
}

void SecurityController::setProcessBlacklist(const QString &value)
{
    const QString normalized = value.trimmed();
    if (m_processBlacklist == normalized) {
        return;
    }
    m_processBlacklist = normalized;
    emit policyChanged();
}

void SecurityController::refreshData()
{
    const bool admin = isRunningAsAdmin();

    m_appMonitors = scanAppMonitors();
    m_ports = scanPorts(m_appMonitors);
    m_appMonitors = annotateAppMonitors(m_appMonitors, m_ports);
    m_credentials = scanCredentials();
    m_firewallRules = scanFirewallRules();
    m_controls = scanControls(m_firewallRules, admin);
    m_ipAddresses = scanIpAddresses();
    m_publicExposure = scanPublicExposure(m_ports, m_firewallRules, m_ipAddresses);
    m_traffic = scanTraffic();

    m_appPermissions = deriveAppPermissions(m_appMonitors, m_ports);
    m_highRiskPermissions = deriveHighRiskPermissions(m_appMonitors, m_ports);
    m_permissions = scanPrivileges(admin);
    if (m_permissions.isEmpty()) {
        m_permissions = derivePermissions(m_firewallRules, admin);
    }

    runPolicyEngine();

    QVariantList runtimeAlerts;
    for (const auto &item : m_alerts) {
        if (item.toMap().value("origin").toString() == "runtime") {
            runtimeAlerts.append(item);
        }
    }

    const QVariantList eventAlerts = scanEventAlerts();
    const QVariantList scanAlerts = deriveAlerts(m_highRiskPermissions, m_traffic);

    QVariantList mergedAlerts;
    QSet<QString> seen;

    auto appendUnique = [&](const QVariantList &source) {
        for (const auto &item : source) {
            const QVariantMap row = item.toMap();
            const QString key = row.value("title").toString() + "|" + row.value("detail").toString();
            if (key.trimmed().isEmpty() || seen.contains(key)) {
                continue;
            }
            seen.insert(key);
            mergedAlerts.append(item);
            if (mergedAlerts.size() >= 100) {
                break;
            }
        }
    };

    appendUnique(runtimeAlerts);
    appendUnique(eventAlerts);
    appendUnique(scanAlerts);

    while (mergedAlerts.size() > 100) {
        mergedAlerts.removeLast();
    }
    m_alerts = mergedAlerts;

    m_lastAction = "System scan completed";
    appendLog("INFO", QString("System scan completed. processes=%1 ports=%2 alerts=%3")
        .arg(m_appMonitors.size())
        .arg(m_ports.size())
        .arg(m_alerts.size()));

    emit dataChanged();
    emit statusChanged();
}

QString SecurityController::pluginConfigPath() const
{
    const QString dirPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (dirPath.isEmpty()) {
        return QString();
    }
    return dirPath + "/plugins.json";
}

void SecurityController::loadPlugins()
{
    // Built-in catalog (published with this project).
    m_availablePlugins.clear();
    m_availablePlugins.append(MapOf({
        {"id", "port_exposure_report"},
        {"title", "Port Exposure Report"},
        {"description", "Summarize potentially exposed listening ports and give quick hardening hints."},
        {"version", "0.1.0"},
        {"author", "VisualSafety"},
        {"icon", QString::fromUtf8("\xF0\x9F\x94\x8C")}, // 🔌
        {"inputs", "Security.ports / Security.firewallRules / Security.ipAddresses"},
        {"params", "none"},
        {"outputs", "summary text + counts"}
    }));
    m_availablePlugins.append(MapOf({
        {"id", "rdp_hardening_check"},
        {"title", "RDP Hardening Check"},
        {"description", "Inspect local RDP related state and recommend hardening actions (policy-only demo)."},
        {"version", "0.1.0"},
        {"author", "VisualSafety"},
        {"icon", QString::fromUtf8("\xF0\x9F\x96\xA5\xEF\xB8\x8F")}, // 🖥️
        {"inputs", "Security.controls / Security.firewallRules"},
        {"params", "none"},
        {"outputs", "recommendations list"}
    }));
    m_availablePlugins.append(MapOf({
        {"id", "credential_hygiene"},
        {"title", "Credential Hygiene"},
        {"description", "Review credential entries and highlight missing rotation/masking (demo)."},
        {"version", "0.1.0"},
        {"author", "VisualSafety"},
        {"icon", QString::fromUtf8("\xF0\x9F\x97\x9D\xEF\xB8\x8F")}, // 🗝️
        {"inputs", "Security.credentials"},
        {"params", "minRisk=Medium"},
        {"outputs", "flagged items list"}
    }));

    // Load installed state.
    m_installedPluginIds.clear();
    const QString path = pluginConfigPath();
    if (!path.isEmpty()) {
        QFile file(path);
        if (file.open(QIODevice::ReadOnly)) {
            const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
            const QJsonObject root = doc.isObject() ? doc.object() : QJsonObject{};
            const QJsonArray installed = root.value("installed").toArray();
            for (const auto &entry : installed) {
                const QString id = entry.toString().trimmed();
                if (!id.isEmpty()) {
                    m_installedPluginIds.insert(id);
                }
            }
        }
    }

    rebuildInstalledPlugins();
    emit pluginsChanged();
}

void SecurityController::savePlugins() const
{
    const QString path = pluginConfigPath();
    if (path.isEmpty()) {
        return;
    }

    QJsonArray installed;
    for (const auto &id : m_installedPluginIds) {
        installed.append(id);
    }

    QJsonObject root;
    root.insert("installed", installed);

    const QFileInfo info(path);
    QDir().mkpath(info.dir().absolutePath());

    const QString tmpPath = path + ".tmp";
    QFile file(tmpPath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return;
    }

    const QJsonDocument doc(root);
    file.write(doc.toJson(QJsonDocument::Indented));
    file.close();

    QFile::remove(path);
    QFile::rename(tmpPath, path);
}

QVariantMap SecurityController::findPluginById(const QString &id) const
{
    const QString key = id.trimmed();
    for (const auto &entry : m_availablePlugins) {
        const QVariantMap row = entry.toMap();
        if (row.value("id").toString() == key) {
            return row;
        }
    }
    return QVariantMap{};
}

void SecurityController::rebuildInstalledPlugins()
{
    m_installedPlugins.clear();
    for (const auto &id : m_installedPluginIds) {
        QVariantMap meta = findPluginById(id);
        if (meta.isEmpty()) {
            meta = MapOf({
                {"id", id},
                {"title", id},
                {"description", "Unknown plugin (metadata missing)."},
                {"version", "0.0.0"},
                {"author", "Unknown"},
                {"icon", QString::fromUtf8("\xF0\x9F\xA7\xB0")} // 🧰
            });
        }
        m_installedPlugins.append(meta);
    }
}

bool SecurityController::installPlugin(const QString &id)
{
    const QString key = id.trimmed();
    if (key.isEmpty()) {
        return false;
    }
    if (m_installedPluginIds.contains(key)) {
        return true;
    }
    if (findPluginById(key).isEmpty()) {
        appendLog("WARN", "Plugin install rejected (unknown id): " + key);
        return false;
    }

    m_installedPluginIds.insert(key);
    rebuildInstalledPlugins();
    savePlugins();
    emit pluginsChanged();
    appendLog("INFO", "Plugin installed: " + key);
    return true;
}

bool SecurityController::uninstallPlugin(const QString &id)
{
    const QString key = id.trimmed();
    if (key.isEmpty()) {
        return false;
    }
    if (!m_installedPluginIds.contains(key)) {
        return true;
    }

    m_installedPluginIds.remove(key);
    rebuildInstalledPlugins();
    savePlugins();
    emit pluginsChanged();
    appendLog("INFO", "Plugin uninstalled: " + key);
    return true;
}

QVariantMap SecurityController::runPlugin(const QString &id, const QVariantMap &params)
{
    const QString key = id.trimmed();
    const QVariantMap meta = findPluginById(key);
    if (key.isEmpty() || meta.isEmpty()) {
        return MapOf({{"ok", false}, {"message", "Unknown plugin id"}});
    }

    Q_UNUSED(params);

    if (key == "port_exposure_report") {
        int highRisk = 0;
        int exposed = 0;
        for (const auto &entry : m_ports) {
            const QVariantMap row = entry.toMap();
            const QString risk = row.value("risk").toString();
            if (risk == "Critical" || risk == "High") {
                ++highRisk;
            }
            const QString scope = row.value("bindScope").toString();
            if (scope == "Any" || scope == "Public") {
                ++exposed;
            }
        }
        const QString msg = QString("ports=%1 exposedCandidates=%2 highRisk=%3")
                                .arg(m_ports.size())
                                .arg(exposed)
                                .arg(highRisk);
        appendLog("INFO", "Plugin run: " + key + " -> " + msg);
        return MapOf({{"ok", true}, {"message", msg}, {"ports", m_ports.size()}, {"exposed", exposed}, {"highRisk", highRisk}});
    }

    if (key == "rdp_hardening_check") {
        const QVariantMap controls = m_controls;
        const bool rdpEnabled = controls.value("remoteDesktop").toString() == "Enabled";
        QVariantList recs;
        if (rdpEnabled) {
            recs.append("Consider restricting RDP to trusted IPs and enabling NLA.");
        } else {
            recs.append("RDP appears disabled.");
        }
        appendLog("INFO", "Plugin run: " + key);
        return MapOf({{"ok", true}, {"message", "RDP check completed"}, {"recommendations", recs}});
    }

    if (key == "credential_hygiene") {
        int exposed = 0;
        for (const auto &entry : m_credentials) {
            const QVariantMap row = entry.toMap();
            const QString exposureFlag = row.value("exposure").toString();
            if (exposureFlag.contains("Exposed", Qt::CaseInsensitive)) {
                ++exposed;
            }
        }
        const QString msg = QString("credentialEntries=%1 exposedFlags=%2").arg(m_credentials.size()).arg(exposed);
        appendLog("INFO", "Plugin run: " + key + " -> " + msg);
        return MapOf({{"ok", true}, {"message", msg}, {"credentialEntries", m_credentials.size()}, {"exposedFlags", exposed}});
    }

    appendLog("INFO", "Plugin run (no-op): " + key);
    return MapOf({{"ok", true}, {"message", "Plugin executed (no-op demo)."}});
}

QString SecurityController::knownPortTip(int port, const QString &protocol) const
{
    if (port <= 0 || port > 65535) {
        return QString();
    }

    const QString proto = protocol.trimmed().isEmpty() ? "tcp/udp" : protocol.trimmed().toLower();

    switch (port) {
    case 22:
        return QString("Port 22 (%1): SSH remote login. Exposing to Internet is high risk; prefer allowlist/VPN.").arg(proto);
    case 80:
        return QString("Port 80 (%1): HTTP. Prefer 443 + redirect; ensure WAF / patching.").arg(proto);
    case 443:
        return QString("Port 443 (%1): HTTPS. Ensure TLS config, certificates, and patching.").arg(proto);
    case 445:
        return QString("Port 445 (%1): SMB. Internet exposure is critical risk (wormable). Block on WAN.").arg(proto);
    case 3389:
        return QString("Port 3389 (%1): RDP. Internet exposure is high risk; restrict by IP + NLA + MFA/VPN.").arg(proto);
    case 3306:
        return QString("Port 3306 (%1): MySQL. Do not expose to Internet; bind to localhost/VPC only.").arg(proto);
    case 5432:
        return QString("Port 5432 (%1): PostgreSQL. Do not expose to Internet; restrict network and auth.").arg(proto);
    case 6379:
        return QString("Port 6379 (%1): Redis. Internet exposure is critical unless secured; prefer bind localhost.").arg(proto);
    case 27017:
        return QString("Port 27017 (%1): MongoDB. Avoid Internet exposure; enforce auth + network ACL.").arg(proto);
    case 5985:
        return QString("Port 5985 (%1): WinRM (HTTP). Avoid Internet exposure; prefer 5986 + allowlist.").arg(proto);
    case 5986:
        return QString("Port 5986 (%1): WinRM (HTTPS). Avoid Internet exposure; allowlist/VPN only.").arg(proto);
    case 5900:
        return QString("Port 5900 (%1): VNC. Avoid Internet exposure; tunnel/VPN only.").arg(proto);
    default:
        return QString();
    }
}

QString SecurityController::knownProcessTip(const QString &processName) const
{
    const QString key = processName.trimmed().toLower();
    if (key.isEmpty()) {
        return QString();
    }

    if (key == "svchost.exe") {
        return "svchost.exe: Windows service host. Multiple instances are normal; investigate unusual paths or network listeners.";
    }
    if (key == "lsass.exe") {
        return "lsass.exe: Local Security Authority. Credential dumping target; high-value process (do not kill).";
    }
    if (key == "explorer.exe") {
        return "explorer.exe: Windows shell. Usually trusted; unexpected child processes may be suspicious.";
    }
    if (key == "services.exe") {
        return "services.exe: Service Control Manager. Core Windows process (do not kill).";
    }
    if (key == "wininit.exe" || key == "csrss.exe") {
        return "Core Windows process. Termination will crash the session; treat as protected.";
    }
    if (key == "powershell.exe" || key == "pwsh.exe") {
        return "PowerShell: Powerful scripting shell. High-risk when invoked by untrusted apps or with encoded commands.";
    }
    if (key == "cmd.exe" || key == "wscript.exe" || key == "cscript.exe" || key == "mshta.exe") {
        return "Scripting/command runtime. Frequently abused by malware; verify parent process and command line.";
    }

    return QString();
}

void SecurityController::hardenFirewall()
{
    if (!isRunningAsAdmin()) {
        appendAlert("High", "Admin required", "Firewall hardening requires administrator privileges.");
        return;
    }

    const QString script =
        "try { "
        "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow | Out-Null; "
        "Write-Output 'ok' "
        "} catch { Write-Output $_.Exception.Message }";

    const CommandResult result = RunProcess("powershell", {"-NoProfile", "-Command", script}, 15000);
    const QString output = MergedOutput(result);
    appendLog(result.exitCode == 0 ? "INFO" : "ERROR", "Firewall harden result: " + output);
    m_lastAction = "Firewall hardening applied";
    emit statusChanged();
    refreshData();
}

void SecurityController::setRemoteDesktopEnabled(bool enabled)
{
    if (!isRunningAsAdmin()) {
        appendAlert("High", "Admin required", "Remote Desktop control requires administrator privileges.");
        return;
    }

    const QString denyValue = enabled ? "0" : "1";
    const QString firewallCmd = enabled
        ? "Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' | Out-Null;"
        : "Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' | Out-Null;";

    const QString script =
        "try { "
        "Set-ItemProperty -Path 'HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Terminal Server' -Name 'fDenyTSConnections' -Value " + denyValue + "; "
        + firewallCmd +
        "Write-Output 'ok' "
        "} catch { Write-Output $_.Exception.Message }";

    const CommandResult result = RunProcess("powershell", {"-NoProfile", "-Command", script}, 15000);
    appendLog(result.exitCode == 0 ? "INFO" : "ERROR", "Remote Desktop set result: " + MergedOutput(result));
    m_lastAction = enabled ? "Remote Desktop enabled" : "Remote Desktop disabled";
    emit statusChanged();
    refreshData();
}

void SecurityController::setFileSharingEnabled(bool enabled)
{
    if (!isRunningAsAdmin()) {
        appendAlert("High", "Admin required", "File sharing control requires administrator privileges.");
        return;
    }

    const QString firewallCmd = enabled
        ? "Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing' | Out-Null;"
        : "Disable-NetFirewallRule -DisplayGroup 'File and Printer Sharing' | Out-Null;";

    const QString script =
        "try { " + firewallCmd + " Write-Output 'ok' } catch { Write-Output $_.Exception.Message }";

    const CommandResult result = RunProcess("powershell", {"-NoProfile", "-Command", script}, 15000);
    appendLog(result.exitCode == 0 ? "INFO" : "ERROR", "File sharing set result: " + MergedOutput(result));
    m_lastAction = enabled ? "File sharing allowed" : "File sharing blocked";
    emit statusChanged();
    refreshData();
}

void SecurityController::disableSmb1()
{
    if (!isRunningAsAdmin()) {
        appendAlert("High", "Admin required", "Disabling SMBv1 requires administrator privileges.");
        return;
    }

    const QString script =
        "try { "
        "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force | Out-Null; "
        "Write-Output 'ok' "
        "} catch { Write-Output $_.Exception.Message }";

    const CommandResult result = RunProcess("powershell", {"-NoProfile", "-Command", script}, 15000);
    appendLog(result.exitCode == 0 ? "INFO" : "ERROR", "Disable SMBv1 result: " + MergedOutput(result));
    m_lastAction = "SMBv1 disable attempted";
    emit statusChanged();
    refreshData();
}

void SecurityController::restartAsAdmin()
{
    if (isRunningAsAdmin()) {
        appendLog("INFO", "Restart as admin ignored: already elevated.");
        m_lastAction = "Already running as admin";
        emit statusChanged();
        return;
    }

    const QString exePath = QCoreApplication::applicationFilePath();
    if (exePath.trimmed().isEmpty()) {
        appendAlert("High", "Restart failed", "Unable to determine application path.");
        return;
    }

    const QString script = "Start-Process -FilePath '" + psQuote(exePath) + "' -Verb RunAs";
    const bool started = QProcess::startDetached("powershell", {"-NoProfile", "-Command", script});
    if (!started) {
        appendAlert("High", "Restart failed", "Unable to launch elevated process (UAC).");
        appendLog("ERROR", "Restart as admin failed: startDetached returned false.");
        return;
    }

    appendLog("INFO", "Restarting as admin requested (UAC prompt should appear).");
    m_lastAction = "Restarting as admin";
    emit statusChanged();
    QCoreApplication::quit();
}

void SecurityController::forceQuitApp(const QString &name)
{
    if (name.trimmed().isEmpty()) {
        appendLog("WARN", "Force quit ignored: empty app name.");
        return;
    }

    QString detail;
    const bool ok = terminateProcess(name, &detail);
    if (ok) {
        appendAlert("High", "Process terminated", name + " terminated by operator.");
        appendLog("WARN", "Forced termination executed for " + name);
        m_lastAction = "Forced exit executed: " + name;
    } else {
        appendLog("ERROR", "Force quit failed for " + name + " -> " + detail);
        m_lastAction = "Force exit failed: " + name;
    }

    emit statusChanged();
    refreshData();
}

void SecurityController::blockAction(const QString &source, const QString &action)
{
    ++m_blockedActionCount;

    bool blocked = false;
    QString outcome;

    const QRegularExpression portExpr("(\\d{1,5})");
    const QRegularExpressionMatch portMatch = portExpr.match(action);
    if (action.contains("Port", Qt::CaseInsensitive) && portMatch.hasMatch()) {
        blocked = blockPort(portMatch.captured(1).toInt(), &outcome);
    }

    if (!blocked && source.contains(".exe", Qt::CaseInsensitive)) {
        blocked = terminateProcess(source, &outcome);
    }

    appendAlert("Critical", "Dangerous action blocked", source + ": " + action + " | " + outcome);
    appendLog(blocked ? "ALERT" : "ERROR", "Block action request -> " + source + " / " + action + " / " + outcome);
    m_lastAction = blocked ? ("Blocked action from " + source) : ("Block failed for " + source);

    emit statusChanged();
    refreshData();
}

void SecurityController::shutdownNow()
{
    const CommandResult result = RunProcess("shutdown", {"/s", "/t", "5", "/f"});
    if (result.finished && result.exitCode == 0) {
        appendAlert("Critical", "Emergency shutdown armed", "System will shutdown in 5 seconds.");
        appendLog("CRITICAL", "Emergency shutdown requested by operator.");
        m_lastAction = "Emergency shutdown requested";
    } else {
        appendLog("ERROR", "Shutdown request failed -> " + MergedOutput(result));
        m_lastAction = "Emergency shutdown failed";
    }
    emit statusChanged();
}

void SecurityController::restartNow()
{
    const CommandResult result = RunProcess("shutdown", {"/r", "/t", "5", "/f"});
    if (result.finished && result.exitCode == 0) {
        appendAlert("High", "Emergency restart armed", "System will restart in 5 seconds.");
        appendLog("CRITICAL", "Emergency restart requested by operator.");
        m_lastAction = "Emergency restart requested";
    } else {
        appendLog("ERROR", "Restart request failed -> " + MergedOutput(result));
        m_lastAction = "Emergency restart failed";
    }
    emit statusChanged();
}

void SecurityController::addManualLog(const QString &level, const QString &message)
{
    appendLog(level.trimmed().isEmpty() ? "INFO" : level.trimmed().toUpper(), message);
}

void SecurityController::testNotifications()
{
    const QString title = "VisualSafety notification test";
    const QString detail = "Channel checks requested by operator.";

    if (m_desktopNotify) {
        sendDesktopNotification(title, detail);
    }
    if (m_emailNotify) {
        sendEmailNotification(title, detail);
    }
    if (m_smsNotify) {
        sendSmsNotification(title, detail);
    }

    appendLog("INFO", "Notification test finished.");
}

void SecurityController::applyPolicyNow()
{
    runPolicyEngine();
    appendLog("INFO", "Policy engine executed manually.");
    emit dataChanged();
}

bool SecurityController::exportLogs(const QString &filePath)
{
    const QString path = filePath.trimmed();
    if (path.isEmpty()) {
        appendLog("ERROR", "Export logs failed: empty path.");
        return false;
    }

    const QFileInfo fileInfo(path);
    QDir().mkpath(fileInfo.absolutePath());

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        appendLog("ERROR", "Export logs failed: cannot open " + path);
        return false;
    }

    QTextStream stream(&file);
    for (int i = m_logs.size() - 1; i >= 0; --i) {
        const QVariantMap row = m_logs.at(i).toMap();
        stream << "[" << row.value("time").toString() << "] "
               << row.value("level").toString() << " "
               << row.value("message").toString() << "\n";
    }

    appendLog("INFO", "Logs exported to " + path);
    return true;
}

bool SecurityController::isRunningAsAdmin() const
{
    const CommandResult result = RunProcess("net", {"session"}, 3000);
    return result.finished && result.exitCode == 0;
}

QString SecurityController::nowStamp() const
{
    return QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
}

QString SecurityController::sanitizeRuleName(const QString &value) const
{
    QString out = value;
    out.replace(QRegularExpression("[^A-Za-z0-9_\\-]"), "_");
    return out.left(48);
}

QString SecurityController::psQuote(const QString &value) const
{
    QString out = value;
    out.replace("'", "''");
    return out;
}

QStringList SecurityController::splitCsvValues(const QString &value) const
{
    QStringList out;
    const QStringList items = value.split(',', Qt::SkipEmptyParts);
    for (const QString &item : items) {
        const QString normalized = item.trimmed().toLower();
        if (!normalized.isEmpty()) {
            out.append(normalized);
        }
    }
    return out;
}

bool SecurityController::containsInCsv(const QString &csv, const QString &name) const
{
    return splitCsvValues(csv).contains(name.trimmed().toLower());
}

bool SecurityController::isSensitiveShellProcess(const QString &name) const
{
    const QString lowered = name.trimmed().toLower();
    return lowered == "powershell.exe" || lowered == "pwsh.exe" || lowered == "cmd.exe"
        || lowered == "wscript.exe" || lowered == "cscript.exe" || lowered == "mshta.exe"
        || lowered == "python.exe" || lowered == "node.exe";
}

bool SecurityController::isBlacklisted(const QString &name) const
{
    return containsInCsv(m_processBlacklist, name);
}

bool SecurityController::isWhitelisted(const QString &name) const
{
    return containsInCsv(m_processWhitelist, name);
}

bool SecurityController::blockPort(int port, QString *detail)
{
    if (port <= 0 || port > 65535) {
        if (detail) {
            *detail = "Invalid port";
        }
        return false;
    }

    const QString ruleName = sanitizeRuleName(QString("VisualSafety_Block_%1").arg(port));
    const CommandResult inRule = RunProcess(
        "netsh",
        {"advfirewall", "firewall", "add", "rule", "name=" + ruleName + "_IN", "dir=in", "action=block", "protocol=TCP", "localport=" + QString::number(port)}
    );
    const CommandResult outRule = RunProcess(
        "netsh",
        {"advfirewall", "firewall", "add", "rule", "name=" + ruleName + "_OUT", "dir=out", "action=block", "protocol=TCP", "localport=" + QString::number(port)}
    );

    const bool ok = inRule.finished && outRule.finished && inRule.exitCode == 0 && outRule.exitCode == 0;
    if (detail) {
        *detail = ok ? QString("Firewall rules created for port %1").arg(port)
                     : QString("Firewall block failed: %1 | %2").arg(MergedOutput(inRule), MergedOutput(outRule));
    }
    return ok;
}

bool SecurityController::terminateProcess(const QString &name, QString *detail)
{
    const CommandResult kill = RunProcess("taskkill", {"/F", "/IM", name});
    const bool ok = kill.finished && kill.exitCode == 0;
    if (detail) {
        *detail = ok ? QString("Process %1 terminated").arg(name)
                     : QString("Process termination failed: %1").arg(MergedOutput(kill));
    }
    return ok;
}

void SecurityController::sendDesktopNotification(const QString &title, const QString &detail)
{
    const QString script =
        "$t='" + psQuote(title.left(80)) + "';"
        "$m='" + psQuote(detail.left(200)) + "';"
        "try {"
        "[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime] > $null;"
        "[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime] > $null;"
        "$x=New-Object Windows.Data.Xml.Dom.XmlDocument;"
        "$x.LoadXml(\"<toast><visual><binding template='ToastGeneric'><text>$t</text><text>$m</text></binding></visual></toast>\");"
        "$toast=[Windows.UI.Notifications.ToastNotification]::new($x);"
        "$notifier=[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('VisualSafety');"
        "$notifier.Show($toast);"
        "Write-Output 'ok';"
        "} catch { Write-Output $_.Exception.Message }";

    const CommandResult result = RunProcess("powershell", {"-NoProfile", "-Command", script}, 6000);
    appendLog("INFO", "Desktop notification result: " + MergedOutput(result));
}

void SecurityController::sendEmailNotification(const QString &title, const QString &detail)
{
    if (m_smtpServer.isEmpty() || m_smtpRecipient.isEmpty() || m_smtpSender.isEmpty()) {
        appendLog("WARN", "Email notification skipped: SMTP config incomplete.");
        return;
    }

    const QString script =
        "$sub='" + psQuote("[VisualSafety] " + title.left(100)) + "';"
        "$body='" + psQuote(detail.left(400)) + "';"
        "$srv='" + psQuote(m_smtpServer) + "';"
        "$from='" + psQuote(m_smtpSender) + "';"
        "$to='" + psQuote(m_smtpRecipient) + "';"
        "try {"
        "Send-MailMessage -To $to -From $from -Subject $sub -Body $body -SmtpServer $srv -Port " + QString::number(m_smtpPort) + ";"
        "Write-Output 'ok';"
        "} catch { Write-Output $_.Exception.Message }";

    const CommandResult result = RunProcess("powershell", {"-NoProfile", "-Command", script}, 10000);
    appendLog("INFO", "Email notification result: " + MergedOutput(result));
}

void SecurityController::sendSmsNotification(const QString &title, const QString &detail)
{
    if (m_smsWebhookUrl.isEmpty()) {
        appendLog("WARN", "SMS notification skipped: webhook URL empty.");
        return;
    }

    const QString message = QString("%1 | %2").arg(title.left(80), detail.left(220));
    const QString script =
        "$url='" + psQuote(m_smsWebhookUrl) + "';"
        "$msg='" + psQuote(message) + "';"
        "$rcpt='" + psQuote(m_smsRecipient) + "';"
        "$payload=@{recipient=$rcpt; message=$msg} | ConvertTo-Json -Compress;"
        "try {"
        "Invoke-RestMethod -Method Post -Uri $url -Body $payload -ContentType 'application/json' | Out-Null;"
        "Write-Output 'ok';"
        "} catch { Write-Output $_.Exception.Message }";

    const CommandResult result = RunProcess("powershell", {"-NoProfile", "-Command", script}, 10000);
    appendLog("INFO", "SMS notification result: " + MergedOutput(result));
}

void SecurityController::runPolicyEngine()
{
    for (const auto &entry : m_ports) {
        const QVariantMap row = entry.toMap();
        const QString risk = row.value("risk").toString();
        if (!m_autoBlockHighRiskPorts || (risk != "Critical" && risk != "High")) {
            continue;
        }

        const int port = row.value("port").toString().toInt();
        const QString process = row.value("process").toString();
        if (port <= 0 || m_policyBlockedPorts.contains(port) || isWhitelisted(process)) {
            continue;
        }

        QString detail;
        if (blockPort(port, &detail)) {
            m_policyBlockedPorts.insert(port);
            ++m_blockedActionCount;
            appendAlert("Critical", "Policy blocked high-risk port", process + " -> Port " + QString::number(port));
        } else {
            appendLog("ERROR", "Policy port block failed for " + QString::number(port) + " -> " + detail);
        }
    }

    if (!m_autoKillUntrustedShell) {
        return;
    }

    for (const auto &entry : m_appMonitors) {
        const QVariantMap row = entry.toMap();
        const QString app = row.value("app").toString();
        if (app.isEmpty() || isWhitelisted(app)) {
            continue;
        }

        const QString key = app.toLower();
        if (m_policyTerminatedApps.contains(key)) {
            continue;
        }

        const bool blacklisted = isBlacklisted(app);
        const bool untrustedShell = row.value("trust").toString() == "Untrusted" && isSensitiveShellProcess(app);
        if (!blacklisted && !untrustedShell) {
            continue;
        }

        QString detail;
        if (terminateProcess(app, &detail)) {
            m_policyTerminatedApps.insert(key);
            ++m_blockedActionCount;
            appendAlert(blacklisted ? "Critical" : "High",
                        blacklisted ? "Policy terminated blacklisted process" : "Policy terminated untrusted shell process",
                        app);
        } else {
            appendLog("ERROR", "Policy process termination failed for " + app + " -> " + detail);
        }
    }
}

void SecurityController::appendLog(const QString &level, const QString &message)
{
    const QString line = QString("[%1] %2 %3").arg(nowStamp(), level, message);
    m_logs.prepend(MapOf({{"time", nowStamp()}, {"level", level}, {"message", message}}));

    while (m_logs.size() > 500) {
        m_logs.removeLast();
    }

    if (!m_logFilePath.isEmpty()) {
        QFile file(m_logFilePath);
        if (file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
            QTextStream stream(&file);
            stream << line << '\n';
        }
    }

    emit logsChanged();
}

void SecurityController::appendAlert(const QString &severity, const QString &title, const QString &detail)
{
    m_alerts.prepend(MapOf({
        {"time", nowStamp()},
        {"severity", severity},
        {"title", title},
        {"detail", detail},
        {"origin", "runtime"}
    }));

    while (m_alerts.size() > 100) {
        m_alerts.removeLast();
    }

    if (m_desktopNotify) {
        sendDesktopNotification(title, detail);
    }
    if (m_emailNotify) {
        sendEmailNotification(title, detail);
    }
    if (m_smsNotify) {
        sendSmsNotification(title, detail);
    }

    emit dataChanged();
}
