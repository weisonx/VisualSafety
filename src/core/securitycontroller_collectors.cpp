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

bool IsPrivateOrSpecialIPv4(const QString &ip)
{
    const QStringList parts = ip.split('.', Qt::SkipEmptyParts);
    if (parts.size() != 4) {
        return true;
    }
    bool ok0 = false;
    bool ok1 = false;
    bool ok2 = false;
    bool ok3 = false;
    const int a = parts.at(0).toInt(&ok0);
    const int b = parts.at(1).toInt(&ok1);
    const int c = parts.at(2).toInt(&ok2);
    const int d = parts.at(3).toInt(&ok3);
    if (!ok0 || !ok1 || !ok2 || !ok3) {
        return true;
    }
    if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255) {
        return true;
    }

    if (a == 0 || a == 10 || a == 127) {
        return true;
    }
    if (a == 169 && b == 254) {
        return true;
    }
    if (a == 172 && b >= 16 && b <= 31) {
        return true;
    }
    if (a == 192 && b == 168) {
        return true;
    }
    // Carrier-grade NAT range.
    if (a == 100 && b >= 64 && b <= 127) {
        return true;
    }
    return false;
}

QString BindScopeForLocalAddress(const QString &localAddress)
{
    const QString addr = localAddress.trimmed();
    if (addr.startsWith("0.0.0.0:", Qt::CaseInsensitive) || addr.startsWith("[::]:", Qt::CaseInsensitive) ||
        addr.startsWith(":::", Qt::CaseInsensitive)) {
        return "Any";
    }
    if (addr.startsWith("127.0.0.1:", Qt::CaseInsensitive) || addr.startsWith("[::1]:", Qt::CaseInsensitive)) {
        return "Loopback";
    }

    const int colon = addr.lastIndexOf(':');
    if (colon <= 0) {
        return "Unknown";
    }

    QString host = addr.left(colon);
    host.remove('[');
    host.remove(']');
    if (host.contains(':')) {
        // IPv6. Conservatively treat non-loopback as potentially reachable.
        return host == "::1" ? "Loopback" : "Any";
    }

    return IsPrivateOrSpecialIPv4(host) ? "Private" : "Public";
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

int RiskScore(const QString &value)
{
    const QString key = Normalize(value);
    if (key == "critical") {
        return 4;
    }
    if (key == "high") {
        return 3;
    }
    if (key == "medium") {
        return 2;
    }
    if (key == "low") {
        return 1;
    }
    return 0;
}

QString ToneForRiskScore(int score)
{
    if (score >= 4) {
        return "danger";
    }
    if (score >= 3) {
        return "warning";
    }
    if (score >= 1) {
        return "normal";
    }
    return "success";
}

bool LooksLikeShell(const QString &name)
{
    const QString key = Normalize(name);
    return key.contains("powershell") || key == "cmd.exe" || key == "pwsh.exe";
}

bool LooksLikeScriptingRuntime(const QString &name)
{
    const QString key = Normalize(name);
    return key.contains("python") || key.contains("node") || key.contains("ruby") || key.contains("perl");
}

bool LooksLikeBrowser(const QString &name)
{
    const QString key = Normalize(name);
    return key.contains("chrome") || key.contains("msedge") || key.contains("firefox") || key.contains("browser") ||
        key.contains("wechat") || key.contains("qqbrowser");
}

bool LooksLikeRemoteAccess(const QString &name)
{
    const QString key = Normalize(name);
    return key.contains("mstsc") || key.contains("rdp") || key.contains("remote") || key.contains("teamviewer") ||
        key.contains("anydesk") || key.contains("vnc");
}

bool LooksLikeTunnelOrVpn(const QString &name)
{
    const QString key = Normalize(name);
    return key.contains("frp") || key.contains("frpc") || key.contains("frps") || key.contains("nps") ||
        key.contains("ngrok") || key.contains("tailscale") || key.contains("wireguard") || key.contains("openvpn") ||
        key.contains("zerotier") || key.contains("clash") || key.contains("v2ray") || key.contains("xray");
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

QVariantList SecurityController::annotateAppMonitors(const QVariantList &apps, const QVariantList &ports) const
{
    struct PortAgg {
        bool listening = false;
        bool publicListening = false;
        int maxRisk = 0;
        int maxPublicRisk = 0;
    };

    QHash<QString, PortAgg> portAgg;
    for (const auto &entry : ports) {
        const QVariantMap row = entry.toMap();
        const QString process = row.value("process").toString();
        if (process.isEmpty()) {
            continue;
        }

        const QString key = Normalize(process);
        PortAgg agg = portAgg.value(key);
        agg.listening = true;

        const int score = RiskScore(row.value("risk").toString());
        agg.maxRisk = std::max(agg.maxRisk, score);

        const QString bindScope = row.value("bindScope").toString();
        if (bindScope == "Any" || bindScope == "Public") {
            agg.publicListening = true;
            agg.maxPublicRisk = std::max(agg.maxPublicRisk, score);
        }

        portAgg.insert(key, agg);
    }

    QVariantList out;
    out.reserve(apps.size());

    for (const auto &entry : apps) {
        QVariantMap row = entry.toMap();
        const QString app = row.value("app").toString();
        const QString trust = row.value("trust").toString();

        QVariantList tags;

        const QString appKey = Normalize(app);
        if (LooksLikeShell(app)) {
            tags.append(MapOf({{"zh", "命令行"}, {"en", "Shell"}, {"tone", trust == "Untrusted" ? "danger" : "warning"}}));
        } else if (LooksLikeScriptingRuntime(app)) {
            tags.append(MapOf({{"zh", "脚本运行时"}, {"en", "Script runtime"}, {"tone", trust == "Untrusted" ? "warning" : "normal"}}));
        }

        if (LooksLikeTunnelOrVpn(app)) {
            tags.append(MapOf({{"zh", "内网穿透/VPN"}, {"en", "Tunnel/VPN"}, {"tone", "warning"}}));
        }

        if (LooksLikeRemoteAccess(app)) {
            tags.append(MapOf({{"zh", "远程访问"}, {"en", "Remote access"}, {"tone", "warning"}}));
        }

        if (LooksLikeBrowser(app)) {
            tags.append(MapOf({{"zh", "浏览器"}, {"en", "Browser"}, {"tone", "normal"}}));
        }

        if (portAgg.contains(appKey)) {
            const PortAgg agg = portAgg.value(appKey);
            if (agg.listening) {
                tags.append(MapOf({{"zh", "监听端口"}, {"en", "Listening"}, {"tone", "normal"}}));
            }
            if (agg.publicListening) {
                const QString tone = ToneForRiskScore(std::max(agg.maxPublicRisk, 3));
                tags.append(MapOf({{"zh", "对外监听"}, {"en", "Public listener"}, {"tone", tone}}));
            }
            if (agg.maxRisk >= 4) {
                tags.append(MapOf({{"zh", "严重端口"}, {"en", "Critical port"}, {"tone", "danger"}}));
            } else if (agg.maxRisk >= 3) {
                tags.append(MapOf({{"zh", "高危端口"}, {"en", "High-risk port"}, {"tone", "warning"}}));
            }
        }

        while (tags.size() > 5) {
            tags.removeLast();
        }

        row.insert("tags", tags);
        out.append(row);
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

        const QString bindScope = BindScopeForLocalAddress(localAddress);
        const bool exposed = (bindScope == "Any" || bindScope == "Public");

        out.append(MapOf({
            {"port", QString::number(port)},
            {"protocol", protocol},
            {"process", pidToName.value(pid, "PID " + pid)},
            {"localAddress", localAddress},
            {"state", state},
            {"bindScope", bindScope},
            {"exposed", exposed},
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

QVariantList SecurityController::scanIpAddresses() const
{
    QVariantList out;

    const QString psScript =
        "Get-NetIPAddress -AddressFamily IPv4 | "
        "Where-Object { $_.IPAddress -and $_.IPAddress -ne '127.0.0.1' } | "
        "Select-Object IPAddress,InterfaceAlias,AddressState | ConvertTo-Csv -NoTypeInformation";
    const CommandResult result = RunProcess("powershell", {"-NoProfile", "-Command", psScript}, 12000);
    if (!result.finished || result.exitCode != 0) {
        out.append(MapOf({
            {"ip", "Unavailable"},
            {"iface", "N/A"},
            {"state", "Unavailable"},
            {"guessedPublic", false},
            {"detail", MergedOutput(result)}
        }));
        return out;
    }

    const QStringList lines = result.out.split('\n', Qt::SkipEmptyParts);
    for (int i = 1; i < lines.size(); ++i) {
        const QStringList fields = ParseCsvLine(lines.at(i).trimmed());
        if (fields.size() < 3) {
            continue;
        }

        const QString ip = StripCsvQuotes(fields.at(0));
        const QString iface = StripCsvQuotes(fields.at(1));
        const QString state = StripCsvQuotes(fields.at(2));
        if (ip.isEmpty()) {
            continue;
        }

        out.append(MapOf({
            {"ip", ip},
            {"iface", iface},
            {"state", state},
            {"guessedPublic", !IsPrivateOrSpecialIPv4(ip)}
        }));

        if (out.size() >= 40) {
            break;
        }
    }

    if (out.isEmpty()) {
        out.append(MapOf({
            {"ip", "N/A"},
            {"iface", "N/A"},
            {"state", "Unavailable"},
            {"guessedPublic", false}
        }));
    }

    return out;
}

QVariantList SecurityController::scanPublicExposure(const QVariantList &ports, const QVariantList &firewallRules, const QVariantList &ipAddresses) const
{
    QVariantList out;

    bool firewallDisabled = false;
    bool inboundAllowByDefault = false;
    for (const auto &entry : firewallRules) {
        const QVariantMap row = entry.toMap();
        if (row.value("decision").toString() == "Disabled") {
            firewallDisabled = true;
        }
        const QString target = row.value("target").toString();
        if (target.contains("Inbound=Allow", Qt::CaseInsensitive)) {
            inboundAllowByDefault = true;
        }
    }

    QStringList publicInterfaces;
    QStringList privateInterfaces;

    for (const auto &entry : ipAddresses) {
        const QVariantMap row = entry.toMap();
        const QString ip = row.value("ip").toString();
        const QString alias = row.value("iface").toString();
        const QString state = row.value("state").toString();
        if (ip.isEmpty() || ip == "Unavailable" || ip == "N/A") {
            continue;
        }
        if (!state.isEmpty() && state.compare("Preferred", Qt::CaseInsensitive) != 0) {
            continue;
        }

        const QString label = alias.isEmpty() ? ip : (alias + " (" + ip + ")");
        if (row.value("guessedPublic").toBool()) {
            publicInterfaces.append(label);
        } else {
            privateInterfaces.append(label);
        }
    }

    const bool hasPublicInterface = !publicInterfaces.isEmpty();
    const bool firewallAtRisk = firewallDisabled || inboundAllowByDefault;

    out.append(MapOf({
        {"type", "Interface"},
        {"severity", hasPublicInterface ? "Medium" : "Low"},
        {"title", hasPublicInterface ? "Possible public IPv4 assigned (heuristic)" : "No public IPv4 detected (heuristic)"},
        {"detail", hasPublicInterface
            ? ("Public: " + publicInterfaces.join(", ") + (privateInterfaces.isEmpty() ? "" : (" | Private: " + privateInterfaces.join(", "))))
            : (privateInterfaces.isEmpty() ? "No active IPv4 address collected." : ("Private: " + privateInterfaces.join(", ")))},
        {"recommendation", "Confirm WAN IP manually (NAT/port-forwarding may affect reachability)."}
    }));

    out.append(MapOf({
        {"type", "Firewall"},
        {"severity", firewallAtRisk ? "High" : "Low"},
        {"title", "Firewall inbound posture"},
        {"detail", firewallDisabled ? "Firewall profile disabled on at least one profile"
                                   : (inboundAllowByDefault ? "Default inbound action is Allow on at least one profile"
                                                           : "Firewall profiles enabled with restrictive inbound defaults")},
        {"recommendation", firewallAtRisk ? "Enable firewall and set default inbound action to Block" : "No action required"}
    }));

    QSet<QString> seen;
    for (const auto &entry : ports) {
        const QVariantMap row = entry.toMap();
        const QString bindScope = row.value("bindScope").toString();
        if (bindScope != "Any" && bindScope != "Public") {
            continue;
        }

        const QString risk = row.value("risk").toString();
        const QString portStr = row.value("port").toString();
        const QString protocol = row.value("protocol").toString();
        const QString process = row.value("process").toString();

        if (portStr.isEmpty()) {
            continue;
        }

        QString severity = "Medium";
        if (risk == "Critical") {
            severity = "Critical";
        } else if (risk == "High") {
            severity = "High";
        } else if (risk == "Low") {
            severity = hasPublicInterface ? "Medium" : "Low";
        }

        if (hasPublicInterface && firewallAtRisk && (risk == "Critical" || risk == "High")) {
            severity = "Critical";
        } else if (hasPublicInterface && (risk == "Critical" || risk == "High")) {
            severity = "High";
        }

        const QString key = protocol + "|" + portStr + "|" + process;
        if (seen.contains(key)) {
            continue;
        }
        seen.insert(key);

        out.append(MapOf({
            {"type", "Port"},
            {"severity", severity},
            {"title", QString("Listening on %1:%2 (%3)").arg(protocol, portStr, bindScope)},
            {"detail", process + " | " + row.value("localAddress").toString()},
            {"recommendation", (risk == "Critical" || risk == "High") ? "Block the port or restrict binding" : "Review service necessity"},
            {"canBlock", (risk == "Critical" || risk == "High")},
            {"process", process},
            {"port", portStr}
        }));

        if (out.size() >= 60) {
            break;
        }
    }

    if (out.size() <= 2) {
        out.append(MapOf({
            {"type", "Port"},
            {"severity", "Low"},
            {"title", "No internet-facing high-risk ports detected"},
            {"detail", "No ports bound to all interfaces were flagged as High/Critical in current scan."},
            {"recommendation", "Keep system patched and firewall enabled"},
            {"canBlock", false}
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

QVariantMap SecurityController::scanControls(const QVariantList &firewallRules, bool isAdmin) const
{
    bool firewallAnyDisabled = false;
    bool firewallInboundAllowDefault = false;
    for (const auto &entry : firewallRules) {
        const QVariantMap row = entry.toMap();
        if (row.value("decision").toString() == "Disabled") {
            firewallAnyDisabled = true;
        }
        const QString target = row.value("target").toString();
        if (target.contains("Inbound=Allow", Qt::CaseInsensitive)) {
            firewallInboundAllowDefault = true;
        }
    }

    auto readPsBool = [&](const QString &script, bool *known) -> bool {
        const CommandResult result = RunProcess("powershell", {"-NoProfile", "-Command", script}, 12000);
        if (!result.finished || result.exitCode != 0) {
            *known = false;
            return false;
        }
        const QString out = result.out.trimmed();
        if (out.compare("True", Qt::CaseInsensitive) == 0) {
            *known = true;
            return true;
        }
        if (out.compare("False", Qt::CaseInsensitive) == 0) {
            *known = true;
            return false;
        }
        *known = false;
        return false;
    };

    auto readPsInt = [&](const QString &script, bool *known) -> int {
        const CommandResult result = RunProcess("powershell", {"-NoProfile", "-Command", script}, 12000);
        if (!result.finished || result.exitCode != 0) {
            *known = false;
            return 0;
        }
        bool ok = false;
        const int value = result.out.trimmed().toInt(&ok);
        *known = ok;
        return ok ? value : 0;
    };

    bool rdpKnown = false;
    const int denyRdp = readPsInt(
        "(Get-ItemProperty 'HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections",
        &rdpKnown);
    const bool remoteDesktopEnabled = rdpKnown ? (denyRdp == 0) : false;

    bool rdpFwKnown = false;
    const int rdpFwEnabledCount = readPsInt(
        "@(Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' }).Count",
        &rdpFwKnown);
    const bool remoteDesktopFirewallEnabled = rdpFwKnown ? (rdpFwEnabledCount > 0) : false;

    bool shareFwKnown = false;
    const int shareEnabledCount = readPsInt(
        "@(Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' }).Count",
        &shareFwKnown);
    const bool fileSharingEnabled = shareFwKnown ? (shareEnabledCount > 0) : false;

    bool smb1Known = false;
    const bool smb1Enabled = readPsBool(
        "try { (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { 'Unknown' }",
        &smb1Known);

    return MapOf({
        {"isAdmin", isAdmin},
        {"firewallAnyDisabled", firewallAnyDisabled},
        {"firewallInboundAllowDefault", firewallInboundAllowDefault},
        {"remoteDesktopKnown", rdpKnown},
        {"remoteDesktopEnabled", remoteDesktopEnabled},
        {"remoteDesktopFirewallKnown", rdpFwKnown},
        {"remoteDesktopFirewallEnabled", remoteDesktopFirewallEnabled},
        {"fileSharingFirewallKnown", shareFwKnown},
        {"fileSharingEnabled", fileSharingEnabled},
        {"smb1Known", smb1Known},
        {"smb1Enabled", smb1Enabled}
    });
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
