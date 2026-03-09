#include "appconfig.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonValue>
#include <QStandardPaths>

namespace {
QString TrimmedOrEmpty(const QString &value)
{
    return value.trimmed();
}

QJsonObject EnsureObject(const QJsonValue &value)
{
    return value.isObject() ? value.toObject() : QJsonObject{};
}

QJsonObject EnsureCategory(QJsonObject *root, const QString &name)
{
    QJsonObject category = EnsureObject(root->value(name));
    root->insert(name, category);
    return category;
}
}  // namespace

AppConfig::AppConfig(QObject *parent)
    : QObject(parent)
{
    load();
}

QString AppConfig::configPath() const
{
    const QString dirPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (dirPath.isEmpty()) {
        return QString();
    }
    return dirPath + "/config.json";
}

void AppConfig::load()
{
    m_root = QJsonObject{};

    const QString path = configPath();
    if (path.isEmpty()) {
        return;
    }

    QFile file(path);
    if (!file.exists()) {
        save();
        return;
    }

    if (!file.open(QIODevice::ReadOnly)) {
        return;
    }

    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    if (!doc.isObject()) {
        return;
    }
    m_root = doc.object();
}

void AppConfig::save() const
{
    const QString path = configPath();
    if (path.isEmpty()) {
        return;
    }

    const QFileInfo info(path);
    QDir().mkpath(info.dir().absolutePath());

    const QString tmpPath = path + ".tmp";
    QFile file(tmpPath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return;
    }

    const QJsonDocument doc(m_root);
    file.write(doc.toJson(QJsonDocument::Indented));
    file.close();

    QFile::remove(path);
    QFile::rename(tmpPath, path);
}

QJsonObject AppConfig::rootObject() const
{
    return m_root;
}

void AppConfig::setRootObject(const QJsonObject &root)
{
    m_root = root;
    save();
    emit changed();
}

QString AppConfig::wanIps() const
{
    const QJsonObject publicObj = EnsureObject(m_root.value("public"));
    return publicObj.value("wanIps").toString();
}

void AppConfig::setWanIps(const QString &value)
{
    QJsonObject root = rootObject();
    QJsonObject publicObj = EnsureCategory(&root, "public");
    const QString trimmed = TrimmedOrEmpty(value);
    if (publicObj.value("wanIps").toString() == trimmed) {
        return;
    }
    publicObj.insert("wanIps", trimmed);
    root.insert("public", publicObj);
    setRootObject(root);
}

bool AppConfig::portForwardEnabled() const
{
    const QJsonObject publicObj = EnsureObject(m_root.value("public"));
    return publicObj.value("portForwardEnabled").toBool(false);
}

void AppConfig::setPortForwardEnabled(bool value)
{
    QJsonObject root = rootObject();
    QJsonObject publicObj = EnsureCategory(&root, "public");
    if (publicObj.value("portForwardEnabled").toBool(false) == value) {
        return;
    }
    publicObj.insert("portForwardEnabled", value);
    root.insert("public", publicObj);
    setRootObject(root);
}

bool AppConfig::dmzEnabled() const
{
    const QJsonObject publicObj = EnsureObject(m_root.value("public"));
    return publicObj.value("dmzEnabled").toBool(false);
}

void AppConfig::setDmzEnabled(bool value)
{
    QJsonObject root = rootObject();
    QJsonObject publicObj = EnsureCategory(&root, "public");
    if (publicObj.value("dmzEnabled").toBool(false) == value) {
        return;
    }
    publicObj.insert("dmzEnabled", value);
    root.insert("public", publicObj);
    setRootObject(root);
}

QString AppConfig::forwardedPortsCsv() const
{
    const QJsonObject publicObj = EnsureObject(m_root.value("public"));
    return publicObj.value("forwardedPortsCsv").toString();
}

void AppConfig::setForwardedPortsCsv(const QString &value)
{
    QJsonObject root = rootObject();
    QJsonObject publicObj = EnsureCategory(&root, "public");
    const QString trimmed = TrimmedOrEmpty(value);
    if (publicObj.value("forwardedPortsCsv").toString() == trimmed) {
        return;
    }
    publicObj.insert("forwardedPortsCsv", trimmed);
    root.insert("public", publicObj);
    setRootObject(root);
}

bool AppConfig::tunnelEnabled() const
{
    const QJsonObject publicObj = EnsureObject(m_root.value("public"));
    return publicObj.value("tunnelEnabled").toBool(false);
}

void AppConfig::setTunnelEnabled(bool value)
{
    QJsonObject root = rootObject();
    QJsonObject publicObj = EnsureCategory(&root, "public");
    if (publicObj.value("tunnelEnabled").toBool(false) == value) {
        return;
    }
    publicObj.insert("tunnelEnabled", value);
    root.insert("public", publicObj);
    setRootObject(root);
}

QString AppConfig::tunnelPortsCsv() const
{
    const QJsonObject publicObj = EnsureObject(m_root.value("public"));
    return publicObj.value("tunnelPortsCsv").toString();
}

void AppConfig::setTunnelPortsCsv(const QString &value)
{
    QJsonObject root = rootObject();
    QJsonObject publicObj = EnsureCategory(&root, "public");
    const QString trimmed = TrimmedOrEmpty(value);
    if (publicObj.value("tunnelPortsCsv").toString() == trimmed) {
        return;
    }
    publicObj.insert("tunnelPortsCsv", trimmed);
    root.insert("public", publicObj);
    setRootObject(root);
}

bool AppConfig::isIpMarkedPublic(const QString &ip, bool guessedPublic) const
{
    const QString key = TrimmedOrEmpty(ip);
    if (key.isEmpty()) {
        return guessedPublic;
    }

    const QJsonObject publicObj = EnsureObject(m_root.value("public"));
    const QJsonObject flags = EnsureObject(publicObj.value("ipPublicFlags"));
    if (!flags.contains(key)) {
        return guessedPublic;
    }
    return flags.value(key).toBool(guessedPublic);
}

void AppConfig::setIpMarkedPublic(const QString &ip, bool value)
{
    const QString key = TrimmedOrEmpty(ip);
    if (key.isEmpty()) {
        return;
    }

    QJsonObject root = rootObject();
    QJsonObject publicObj = EnsureCategory(&root, "public");
    QJsonObject flags = EnsureObject(publicObj.value("ipPublicFlags"));
    if (flags.value(key).toBool(false) == value && flags.contains(key)) {
        return;
    }
    flags.insert(key, value);
    publicObj.insert("ipPublicFlags", flags);
    root.insert("public", publicObj);
    setRootObject(root);
}
