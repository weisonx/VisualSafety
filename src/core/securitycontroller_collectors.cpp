#include "securitycontroller.h"

#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QProcess>
#include <QRegularExpression>
#include <QSet>

#include <algorithm>

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

QStringList ParseCsvLine(const QString &line)
{
    QStringList fields;
    QString field;
    bool inQuotes = false;
    for (int i = 0; i < line.size(); ++i) {
        const QChar ch = line.at(i);
        if (ch == '"') {
            if (inQuotes && i + 1 < line.size() && line.at(i + 1) == '"') {
                field.append('"');
                ++i;
            } else {
                inQuotes = !inQuotes;
            }
        } else if (ch == ',' && !inQuotes) {
            fields.append(field.trimmed());
            field.clear();
        } else {
            field.append(ch);
        }
    }
    fields.append(field.trimmed());
    return fields;
}

QString StripCsvQuotes(const QString &value)
{
    QString out = value;
    out.remove('"');
    return out.trimmed();
}

int ParsePortFromAddress(const QString &address)
{
    if (address.isEmpty() || address == "*:*" || address == "*") {
        return -1;
    }
    const int lastColon = address.lastIndexOf(':');
    if (lastColon < 0 || lastColon + 1 >= address.size()) {
        return -1;
    }
    bool ok = false;
    const int port = address.mid(lastColon + 1).toInt(&ok);
    return ok ? port : -1;
}

QString Normalize(const QString &name)
{
    return name.trimmed().toLower();
}

QString ClassifyTrust(const QString &appName)
{
    static const QSet<QString> trusted = {
        "system", "system idle process", "svchost.exe", "explorer.exe", "dwm.exe", "winlogon.exe",
        "csrss.exe", "services.exe", "lsass.exe", "smss.exe", "msmpeng.exe", "securityhealthservice.exe"
    };
    static const QSet<QString> risky = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "rundll32.exe", "python.exe", "pythonw.exe", "node.exe", "nmap.exe"
    };

    const QString key = Normalize(appName);
    if (trusted.contains(key)) {
        return "Trusted";
    }
    if (risky.contains(key)) {
        return "Untrusted";
    }
    return "Unknown";
}

QString ProcessHint(const QString &appName)
{
    const QString key = Normalize(appName);
    if (key.contains("powershell") || key == "cmd.exe") {
        return "Can execute shell commands";
    }
    if (key.contains("python") || key.contains("node")) {
        return "Script runtime with automation capability";
    }
    if (key.contains("remote") || key.contains("rdp")) {
        return "Remote access related process";
    }
    if (key.contains("browser") || key.contains("chrome") || key.contains("edge")) {
        return "Browser process with network access";
    }
    return "General process activity";
}

QString RiskForPort(int port)
{
    static const QSet<int> critical = {23, 445, 3389, 5900};
    static const QSet<int> high = {21, 22, 135, 137, 138, 139, 1433, 3306, 5432};

    if (critical.contains(port)) {
        return "Critical";
    }
    if (high.contains(port)) {
        return "High";
    }
    return port > 0 ? "Low" : "Medium";
}

QString RiskForPrivilege(const QString &name)
{
    static const QSet<QString> critical = {
        "sedebugprivilege",
        "secreatetokenprivilege",
        "seassignprimarytokenprivilege",
        "setcbprivilege",
        "seimpersonateprivilege",
        "seloaddriverprivilege",
        "setakeownershipprivilege",
        "serestoreprivilege",
        "sebackupprivilege",
        "sesecurityprivilege"
    };
    static const QSet<QString> high = {
        "seincreasequotaprivilege",
        "seremoteshutdownprivilege",
        "seshutdownprivilege",
        "semanagevolumeprivilege",
        "serelabelprivilege"
    };

    const QString key = Normalize(name);
    if (critical.contains(key)) {
        return "Critical";
    }
    if (high.contains(key)) {
        return "High";
    }
    return "Medium";
}
}

QVariantList SecurityController::scanAppMonitors() const
{
    QVariantList out;
    const CommandResult result = RunProcess("tasklist", {"/FO", "CSV", "/NH"});
    if (!result.finished || result.exitCode != 0) {
        out.append(MapOf({
            {"app", "tasklist unavailable"},
            {"pid", "-"},
            {"trust", "Unknown"},
            {"status", "Unavailable"},
            {"hint", MergedOutput(result)}
        }));
        return out;
    }

    const QStringList lines = result.out.split('\n', Qt::SkipEmptyParts);
    for (const QString &rawLine : lines) {
        const QString line = rawLine.trimmed();
        if (line.isEmpty()) {
            continue;
        }

        const QStringList fields = ParseCsvLine(line);
        if (fields.size() < 2) {
            continue;
        }

        const QString app = StripCsvQuotes(fields.at(0));
        const QString pid = StripCsvQuotes(fields.at(1));
        if (app.isEmpty() || pid.isEmpty()) {
            continue;
        }

        out.append(MapOf({
            {"app", app},
            {"pid", pid},
            {"trust", ClassifyTrust(app)},
            {"status", "Running"},
            {"hint", ProcessHint(app)}
        }));
    }

    if (out.isEmpty()) {
        out.append(MapOf({
            {"app", "No process parsed"},
            {"pid", "-"},
            {"trust", "Unknown"},
            {"status", "Unavailable"},
            {"hint", "tasklist returned no parsable process rows"}
        }));
    }

    return out;
}

QVariantList SecurityController::scanPrivileges(bool isAdmin) const
{
    QVariantList out;

    const CommandResult result = RunProcess("whoami", {"/priv", "/fo", "csv", "/nh"}, 8000);
    if (!result.finished || result.exitCode != 0) {
        out.append(MapOf({
            {"name", "Token Privileges"},
            {"scope", "whoami /priv unavailable"},
            {"level", isAdmin ? "High" : "Medium"},
            {"status", "Unavailable"}
        }));
        return out;
    }

    const QStringList lines = result.out.split('\n', Qt::SkipEmptyParts);
    QVariantList parsed;
    for (const QString &rawLine : lines) {
        const QString line = rawLine.trimmed();
        if (line.isEmpty()) {
            continue;
        }

        const QStringList fields = ParseCsvLine(line);
        if (fields.size() < 3) {
            continue;
        }

        const QString privName = StripCsvQuotes(fields.at(0));
        const QString description = StripCsvQuotes(fields.at(1));
        const QString state = StripCsvQuotes(fields.at(2));
        if (privName.isEmpty()) {
            continue;
        }

        const QString level = RiskForPrivilege(privName);
        parsed.append(MapOf({
            {"name", privName},
            {"scope", description},
            {"level", level},
            {"status", state}
        }));
    }

    if (parsed.isEmpty()) {
        out.append(MapOf({
            {"name", "Token Privileges"},
            {"scope", "No privileges parsed from whoami /priv"},
            {"level", isAdmin ? "High" : "Medium"},
            {"status", "Unavailable"}
        }));
        return out;
    }

    std::stable_sort(parsed.begin(), parsed.end(), [](const QVariant &a, const QVariant &b) {
        const QVariantMap ma = a.toMap();
        const QVariantMap mb = b.toMap();

        const auto score = [](const QString &level) {
            if (level == "Critical") return 0;
            if (level == "High") return 1;
            return 2;
        };

        const int sa = score(ma.value("level").toString());
        const int sb = score(mb.value("level").toString());
        if (sa != sb) {
            return sa < sb;
        }
        return ma.value("name").toString().compare(mb.value("name").toString(), Qt::CaseInsensitive) < 0;
    });

    out.append(MapOf({
        {"name", "Admin Token"},
        {"scope", "Current user elevation status"},
        {"level", isAdmin ? "High" : "Medium"},
        {"status", isAdmin ? "Elevated" : "Not elevated"}
    }));

    const int limit = 60;
    for (int i = 0; i < parsed.size() && i < limit; ++i) {
        out.append(parsed.at(i));
    }
    return out;
}

QVariantList SecurityController::scanPorts(const QVariantList &apps) const
{
    QVariantMap pidToName;
    for (const auto &entry : apps) {
        const QVariantMap row = entry.toMap();
        pidToName.insert(row.value("pid").toString(), row.value("app").toString());
    }

    QVariantList out;
    const CommandResult result = RunProcess("netstat", {"-ano"});
    if (!result.finished || result.exitCode != 0) {
        out.append(MapOf({
            {"port", "-"},
            {"protocol", "N/A"},
            {"process", "netstat unavailable"},
            {"risk", "Medium"},
            {"action", "Watch"}
        }));
        return out;
    }

    const QStringList lines = MergedOutput(result).split('\n', Qt::SkipEmptyParts);
    QSet<QString> seen;
    for (const QString &rawLine : lines) {
        const QString line = rawLine.trimmed();
        if (!(line.startsWith("TCP") || line.startsWith("UDP"))) {
            continue;
        }

        const QStringList parts = line.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
        if (parts.size() < 4) {
            continue;
        }

        const QString protocol = parts.at(0);
        QString localAddress;
        QString state;
        QString pid;

        if (protocol == "TCP" && parts.size() >= 5) {
            localAddress = parts.at(1);
            state = parts.at(3);
            pid = parts.at(4);
        } else if (protocol == "UDP") {
            localAddress = parts.at(1);
            state = "LISTENING";
            pid = parts.last();
        } else {
            continue;
        }

        const int port = ParsePortFromAddress(localAddress);
        if (port <= 0) {
            continue;
        }

        const QString key = protocol + "|" + QString::number(port) + "|" + pid + "|" + state;
        if (seen.contains(key)) {
            continue;
        }
        seen.insert(key);

        const QString risk = RiskForPort(port);
        QString action = "Allow";
        if (risk == "Critical" || risk == "High") {
            action = "Block";
        } else if (risk == "Medium") {
            action = "Watch";
        }

        out.append(MapOf({
            {"port", QString::number(port)},
            {"protocol", protocol},
            {"process", pidToName.value(pid, "PID " + pid)},
            {"risk", risk},
            {"action", action}
        }));

        if (out.size() >= 100) {
            break;
        }
    }

    if (out.isEmpty()) {
        out.append(MapOf({
            {"port", "-"},
            {"protocol", "N/A"},
            {"process", "No listening ports parsed"},
            {"risk", "Low"},
            {"action", "Allow"}
        }));
    }

    return out;
}

QVariantList SecurityController::scanCredentials() const
{
    QVariantList out;
    const CommandResult result = RunProcess("cmdkey", {"/list"});
    if (!result.finished || result.exitCode != 0) {
        out.append(MapOf({
            {"type", "Credential Manager"},
            {"owner", "Unavailable"},
            {"expires", "N/A"},
            {"exposure", "Access denied or unavailable"}
        }));
        return out;
    }

    const QRegularExpression targetExpr(
        "^\\s*(Target|目标)\\s*[:：]\\s*(.+)$",
        QRegularExpression::CaseInsensitiveOption);
    const QStringList lines = result.out.split('\n', Qt::SkipEmptyParts);
    for (const QString &rawLine : lines) {
        const QString line = rawLine.trimmed();
        const QRegularExpressionMatch match = targetExpr.match(line);
        if (!match.hasMatch()) {
            continue;
        }

        const QString target = match.captured(2).trimmed();
        QString type = "Stored Credential";
        if (target.contains("TERMSRV", Qt::CaseInsensitive)) {
            type = "RDP Credential";
        } else if (target.contains("LegacyGeneric", Qt::CaseInsensitive)) {
            type = "Generic Credential";
        }

        out.append(MapOf({
            {"type", type},
            {"owner", target},
            {"expires", "N/A"},
            {"exposure", "Masked"}
        }));

        if (out.size() >= 30) {
            break;
        }
    }

    if (out.isEmpty()) {
        out.append(MapOf({
            {"type", "Credential Manager"},
            {"owner", "No stored credentials detected"},
            {"expires", "N/A"},
            {"exposure", "Safe"}
        }));
    }

    return out;
}

QVariantList SecurityController::scanFirewallRules() const
{
    QVariantList out;
    const QString psScript = "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Csv -NoTypeInformation";
    const CommandResult result = RunProcess("powershell", {"-NoProfile", "-Command", psScript}, 12000);

    if (result.finished && result.exitCode == 0) {
        const QStringList lines = result.out.split('\n', Qt::SkipEmptyParts);
        for (int i = 1; i < lines.size(); ++i) {
            const QStringList fields = ParseCsvLine(lines.at(i).trimmed());
            if (fields.size() < 4) {
                continue;
            }

            const QString profileName = StripCsvQuotes(fields.at(0));
            const QString enabled = StripCsvQuotes(fields.at(1));
            const QString inbound = StripCsvQuotes(fields.at(2));
            const QString outbound = StripCsvQuotes(fields.at(3));

            const bool profileEnabled = enabled.compare("True", Qt::CaseInsensitive) == 0;
            const QString risk = (!profileEnabled || inbound.compare("Allow", Qt::CaseInsensitive) == 0) ? "High" : "Low";

            out.append(MapOf({
                {"rule", profileName + " profile"},
                {"target", "Inbound=" + inbound + ", Outbound=" + outbound},
                {"decision", profileEnabled ? "Enabled" : "Disabled"},
                {"risk", risk}
            }));
        }
    }

    if (out.isEmpty()) {
        const CommandResult fallback = RunProcess("netsh", {"advfirewall", "show", "allprofiles"}, 10000);
        out.append(MapOf({
            {"rule", "Firewall status"},
            {"target", fallback.finished ? "netsh profile summary" : "Unavailable"},
            {"decision", fallback.finished ? "Collected" : "Unavailable"},
            {"risk", fallback.finished ? "Medium" : "High"}
        }));
    }

    return out;
}

QVariantList SecurityController::scanTraffic() const
{
    QVariantList out;

    const QString psScript = "Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes | ConvertTo-Csv -NoTypeInformation";
    const CommandResult result = RunProcess("powershell", {"-NoProfile", "-Command", psScript}, 12000);

    double totalRx = 0.0;
    double totalTx = 0.0;

    if (result.finished && result.exitCode == 0) {
        const QStringList lines = result.out.split('\n', Qt::SkipEmptyParts);
        for (int i = 1; i < lines.size(); ++i) {
            const QStringList fields = ParseCsvLine(lines.at(i).trimmed());
            if (fields.size() < 3) {
                continue;
            }

            bool okRx = false;
            bool okTx = false;
            const double rx = StripCsvQuotes(fields.at(1)).toDouble(&okRx);
            const double tx = StripCsvQuotes(fields.at(2)).toDouble(&okTx);
            if (okRx) {
                totalRx += rx;
            }
            if (okTx) {
                totalTx += tx;
            }
        }
    }

    static double lastTotalRx = 0.0;
    static double lastTotalTx = 0.0;
    static qint64 lastSampleMs = 0;

    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    const double deltaSeconds =
        lastSampleMs > 0 ? (static_cast<double>(nowMs - lastSampleMs) / 1000.0) : 0.0;

    double rxMbps = 0.0;
    double txMbps = 0.0;
    bool rateValid = false;

    if (deltaSeconds >= 0.2 && totalRx >= lastTotalRx && totalTx >= lastTotalTx) {
        const double rxBps = (totalRx - lastTotalRx) / deltaSeconds;
        const double txBps = (totalTx - lastTotalTx) / deltaSeconds;
        rxMbps = (rxBps * 8.0) / 1000.0 / 1000.0;
        txMbps = (txBps * 8.0) / 1000.0 / 1000.0;
        rateValid = true;
    }

    lastTotalRx = totalRx;
    lastTotalTx = totalTx;
    lastSampleMs = nowMs;

    const QString rxText = rateValid ? QString::number(rxMbps, 'f', 1) : "N/A";
    const QString txText = rateValid ? QString::number(txMbps, 'f', 1) : "N/A";
    const QString totalText = rateValid ? QString::number(rxMbps + txMbps, 'f', 1) : "N/A";

    const bool unusual = rateValid && (txMbps > rxMbps * 1.8) && (txMbps > 50.0);

    out.append(MapOf({{"direction", "Inbound"}, {"mbps", rxText}, {"unusual", "No"}}));
    out.append(MapOf({{"direction", "Outbound"}, {"mbps", txText}, {"unusual", unusual ? "Yes" : "No"}}));
    out.append(MapOf({{"direction", "Total"}, {"mbps", totalText}, {"unusual", "No"}}));
    return out;
}

QVariantList SecurityController::scanEventAlerts() const
{
    QVariantList out;

    const QString psScript =
        "$start=(Get-Date).AddHours(-6);"
        "$logs=@("
        "'Microsoft-Windows-Windows Defender/Operational',"
        "'Microsoft-Windows-PowerShell/Operational',"
        "'Security',"
        "'System'"
        ");"
        "$ev=@();"
        "foreach($l in $logs){"
        "  try {"
        "    $ev += Get-WinEvent -FilterHashtable @{LogName=$l; StartTime=$start} -MaxEvents 30 | "
        "      Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,LogName,Message;"
        "  } catch { }"
        "};"
        "$ev | ForEach-Object {"
        "  $msg=$_.Message;"
        "  if($null -ne $msg -and $msg.Length -gt 260){ $msg=$msg.Substring(0,260) + '...'; }"
        "  [PSCustomObject]@{"
        "    time=$_.TimeCreated;"
        "    id=$_.Id;"
        "    level=$_.LevelDisplayName;"
        "    provider=$_.ProviderName;"
        "    log=$_.LogName;"
        "    message=$msg"
        "  }"
        "} | ConvertTo-Json -Compress";

    const CommandResult result = RunProcess("powershell", {"-NoProfile", "-Command", psScript}, 12000);
    if (!result.finished || result.exitCode != 0) {
        return out;
    }

    const QByteArray jsonBytes = result.out.toUtf8().trimmed();
    if (jsonBytes.isEmpty() || jsonBytes == "null") {
        return out;
    }

    QJsonParseError error{};
    const QJsonDocument doc = QJsonDocument::fromJson(jsonBytes, &error);
    if (error.error != QJsonParseError::NoError) {
        return out;
    }

    const auto mapSeverity = [](const QString &level) {
        const QString key = level.trimmed().toLower();
        if (key == "critical") return QString("Critical");
        if (key == "error") return QString("High");
        if (key == "warning") return QString("Medium");
        return QString("Low");
    };

    const auto appendOne = [&](const QJsonObject &obj) {
        const QString level = obj.value("level").toString();
        const QString provider = obj.value("provider").toString();
        const QString log = obj.value("log").toString();
        const int id = obj.value("id").toInt();

        const QString title = QString("%1 (%2/%3)").arg(
            provider.isEmpty() ? "Event" : provider,
            log.isEmpty() ? "Log" : log,
            QString::number(id));

        out.append(MapOf({
            {"time", obj.value("time").toString()},
            {"severity", mapSeverity(level)},
            {"title", title},
            {"detail", obj.value("message").toString()},
            {"origin", "eventlog"}
        }));
    };

    if (doc.isArray()) {
        const QJsonArray arr = doc.array();
        for (const auto &value : arr) {
            if (!value.isObject()) {
                continue;
            }
            appendOne(value.toObject());
            if (out.size() >= 60) {
                break;
            }
        }
    } else if (doc.isObject()) {
        appendOne(doc.object());
    }

    return out;
}

QVariantList SecurityController::deriveAppPermissions(const QVariantList &apps, const QVariantList &ports) const
{
    QVariantList out;

    QSet<QString> processesWithPorts;
    for (const auto &entry : ports) {
        const QString process = entry.toMap().value("process").toString();
        if (!process.isEmpty()) {
            processesWithPorts.insert(process);
        }
    }

    for (const auto &entry : apps) {
        const QVariantMap row = entry.toMap();
        const QString app = row.value("app").toString();
        if (app.isEmpty()) {
            continue;
        }

        QString permission = "File System";
        QString status = "Allowed";
        if (app.contains("powershell", Qt::CaseInsensitive) || app.compare("cmd.exe", Qt::CaseInsensitive) == 0) {
            permission = "Shell Execution";
            status = "Prompt";
        } else if (processesWithPorts.contains(app)) {
            permission = "Network";
            status = "Allowed";
        } else if (row.value("trust").toString() == "Untrusted") {
            permission = "Process Control";
            status = "Denied";
        }

        out.append(MapOf({{"app", app}, {"permission", permission}, {"status", status}, {"lastUsed", nowStamp()}}));
        if (out.size() >= 30) {
            break;
        }
    }

    return out;
}

QVariantList SecurityController::deriveHighRiskPermissions(const QVariantList &apps, const QVariantList &ports) const
{
    QVariantList out;

    for (const auto &entry : apps) {
        const QVariantMap row = entry.toMap();
        if (row.value("trust").toString() != "Untrusted") {
            continue;
        }

        const QString app = row.value("app").toString();
        QString action = "Sensitive runtime detected";
        if (app.contains("powershell", Qt::CaseInsensitive) || app.compare("cmd.exe", Qt::CaseInsensitive) == 0) {
            action = "Potential command execution capability";
        }

        out.append(MapOf({
            {"permission", "Process Control"},
            {"process", app},
            {"action", action},
            {"time", nowStamp()},
            {"risk", "High"}
        }));
        if (out.size() >= 12) {
            break;
        }
    }

    for (const auto &entry : ports) {
        const QVariantMap row = entry.toMap();
        const QString risk = row.value("risk").toString();
        if (risk != "Critical" && risk != "High") {
            continue;
        }

        out.append(MapOf({
            {"permission", "Network Exposure"},
            {"process", row.value("process").toString()},
            {"action", "High-risk port " + row.value("port").toString() + " active"},
            {"time", nowStamp()},
            {"risk", risk}
        }));

        if (out.size() >= 20) {
            break;
        }
    }

    if (out.isEmpty()) {
        out.append(MapOf({
            {"permission", "System"},
            {"process", "No immediate risk"},
            {"action", "No high-risk action detected in current scan"},
            {"time", nowStamp()},
            {"risk", "Low"}
        }));
    }

    return out;
}

QVariantList SecurityController::derivePermissions(const QVariantList &firewallRules, bool isAdmin) const
{
    bool firewallEnabled = true;
    for (const auto &entry : firewallRules) {
        if (entry.toMap().value("decision").toString() == "Disabled") {
            firewallEnabled = false;
            break;
        }
    }

    QVariantList out;
    out.append(MapOf({{"name", "File System"}, {"scope", "User profile + common writable paths"}, {"level", "High"}, {"status", "Monitored"}}));
    out.append(MapOf({{"name", "Shell Execution"}, {"scope", "PowerShell / cmd runtime"}, {"level", "Critical"}, {"status", isAdmin ? "Guarded" : "Restricted"}}));
    out.append(MapOf({{"name", "Process Control"}, {"scope", "Terminate / inject / spawn process"}, {"level", "Critical"}, {"status", "Guarded"}}));
    out.append(MapOf({{"name", "Network & Firewall"}, {"scope", "Inbound/outbound filtering + port exposure"}, {"level", firewallEnabled ? "High" : "Critical"}, {"status", firewallEnabled ? "Monitored" : "At Risk"}}));
    return out;
}

QVariantList SecurityController::deriveAlerts(const QVariantList &highRiskPermissions, const QVariantList &traffic) const
{
    QVariantList out;
    for (const auto &entry : highRiskPermissions) {
        const QVariantMap row = entry.toMap();
        const QString risk = row.value("risk").toString();
        if (risk == "Low") {
            continue;
        }

        out.append(MapOf({
            {"time", nowStamp()},
            {"severity", risk == "Critical" ? "Critical" : "High"},
            {"title", "High-risk behavior detected"},
            {"detail", row.value("process").toString() + " -> " + row.value("action").toString()},
            {"origin", "scan"}
        }));

        if (out.size() >= 20) {
            break;
        }
    }

    for (const auto &entry : traffic) {
        const QVariantMap row = entry.toMap();
        if (row.value("direction").toString() == "Outbound" && row.value("unusual").toString() == "Yes") {
            out.prepend(MapOf({
                {"time", nowStamp()},
                {"severity", "Medium"},
                {"title", "Unusual outbound traffic"},
                {"detail", "Outbound traffic deviates from baseline."},
                {"origin", "scan"}
            }));
            break;
        }
    }

    if (out.isEmpty()) {
        out.append(MapOf({
            {"time", nowStamp()},
            {"severity", "Low"},
            {"title", "No active threat pattern"},
            {"detail", "Current scan did not detect high-risk behavior."},
            {"origin", "scan"}
        }));
    }

    return out;
}
